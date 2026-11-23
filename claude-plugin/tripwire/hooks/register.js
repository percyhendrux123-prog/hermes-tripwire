// Tripwire for Claude Code, mod half (v0.2.0).
//
// Logs refusals that settings hooks cannot see: a deny rule or a PreToolUse
// hook blocking a call, a permission dialog you decline, and a call that needs
// approval where nobody can be asked (claude -p, dontAsk mode). Auto mode
// refusals stay with the PermissionDenied settings hook in hooks.json.
//
// It only observes. Every hook below passes its event on with next(e) and
// returns exactly what next(e) returned; nothing is blocked, approved or
// rewritten. Any failure in this file is swallowed, so a logging problem can
// never change a session.
//
// Privacy: what leaves this file is one small record (kind, how, tool name,
// agent type). Commands, arguments, paths, reasons and result text are read in
// memory to classify the refusal and then dropped. The script that writes the
// log (tripwire_hook.py) accepts only the fixed labels used here.

const MAX_TRACKED = 512
const DECLINED = "The user doesn't want to proceed with this tool use"

// Calls Claude Code said it would ask about, waiting for the answer.
// tool_use_id -> { tool, agentId, reason }. Held in memory only.
const asked = new Map()
// Calls already logged, so one refusal is never written twice.
const logged = new Set()
// Subagent id -> subagent type, learned when a subagent starts.
const agentTypes = new Map()

function remember(map, key, value) {
  if (map.size >= MAX_TRACKED) map.delete(map.keys().next().value)
  map.set(key, value)
}

function once(id) {
  if (logged.has(id)) return false
  if (logged.size >= MAX_TRACKED) logged.delete(logged.values().next().value)
  logged.add(id)
  return true
}

function profileOf(agentId) {
  if (!agentId) return null
  return agentTypes.get(agentId) || 'subagent'
}

// The text of a tool result, whether Claude Code stored it as a string or as
// text blocks. Used only to classify the refusal; never stored or sent.
function textOf(content) {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content.map(b => (b && typeof b.text === 'string' ? b.text : '')).join('')
}

function blockHow(decided) {
  if (typeof decided.rule === 'string' && decided.rule) return 'deny_rule'
  if (decided.hook === 'PreToolUse') return 'pretooluse_hook'
  return 'other_policy'
}

function askedHow(text, reason) {
  if (text.startsWith(DECLINED)) return 'user_declined'
  if (text.startsWith('Permission to use ') && text.includes("don't ask mode")) return 'dont_ask_mode'
  // Nobody to ask: Claude Code hands the model the approval question itself.
  if (reason && text.startsWith(reason)) return 'no_approver'
  return null
}

// Hands the record to the Python script, which validates it and appends one
// five-field line. Fail open: nothing here may throw.
async function record($, kind, how, tool, agentId) {
  try {
    const script = $.plugin.root + '/hooks/tripwire_hook.py'
    const payload = { tripwire_mod: 1, kind, how, tool_name: tool, agent_type: profileOf(agentId) }
    await $.process.run(['python3', script], { stdin: JSON.stringify(payload), timeoutMs: 5000 })
  } catch {
    // A missed record is better than a changed session.
  }
}

export function register(on) {
  // Learn which subagent type an agent id belongs to, for the profile field.
  on('agent.spawn', async ($, e, next) => {
    const out = await next(e)
    try {
      if (out && out.agentId && typeof e.subagentType === 'string') {
        remember(agentTypes, out.agentId, e.subagentType)
      }
    } catch {
      // ignore
    }
    return out
  })

  // The permission verdict for each of Claude's own calls. A deny is logged
  // here; an ask is remembered until its outcome arrives below.
  on('tool.check', async ($, e, next) => {
    const decided = await next(e)
    try {
      const id = e.tool_use_id
      if (next.origin && next.origin.plugin === 'engine' && typeof id === 'string' && id && decided) {
        if (decided.decision === 'deny') {
          if (once(id)) await record($, 'tool_blocked', blockHow(decided), e.tool, e.agentId)
        } else if (decided.decision === 'ask') {
          const reason = typeof decided.reason === 'string' ? decided.reason : ''
          remember(asked, id, { tool: e.tool, agentId: e.agentId, reason })
        }
      }
    } catch {
      // ignore
    }
    return decided
  })

  // The result row of each tool call. For a call that was asked about and came
  // back as an error, decide whether it was refused. Errors from a tool that
  // ran and failed, and auto mode's classifier refusals (the settings hook's),
  // do not match and are not logged here.
  on('session.append', { door: 'tool-result' }, async ($, e, next) => {
    const out = await next(e)
    try {
      const blocks = e.message && Array.isArray(e.message.content) ? e.message.content : []
      for (const block of blocks) {
        if (!block || block.type !== 'tool_result' || typeof block.tool_use_id !== 'string') continue
        const wait = asked.get(block.tool_use_id)
        if (!wait) continue
        asked.delete(block.tool_use_id)
        if (!block.is_error) continue
        const how = askedHow(textOf(block.content), wait.reason)
        if (how && once(block.tool_use_id)) {
          await record($, 'permission_declined', how, wait.tool, wait.agentId)
        }
      }
    } catch {
      // ignore
    }
    return out
  })
}
