// node:test suite for the Tripwire mod (hooks/register.js).
//
// register.js is the real file, loaded unchanged. A small fake of Claude Code
// stands in for the engine: it registers the hooks, fires events through them,
// and answers the mod's one API call ($.process.run) by running the real
// tripwire_hook.py, so each test checks the line that would reach the log.
//
// Run: node --test claude-plugin/tests/test_register.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const pluginRoot = path.join(path.dirname(here), 'tripwire')
const source = fs.readFileSync(path.join(pluginRoot, 'hooks', 'register.js'), 'utf8')
const scratchBase = path.join(os.homedir(), '.hermes', 'cache', 'scratch')
const SECRET = 'CANARY-9f8e7d6c'
const FIVE = ['how', 'kind', 'profile', 'tool', 'ts']
const DECLINED = "The user doesn't want to proceed with this tool use. The tool use was rejected."
const ENGINE = { plugin: 'engine', tier: 'core' }

let counter = 0

// A fresh copy of the module per test, so its in-memory tables start empty.
async function load() {
  const base = fs.existsSync(scratchBase) ? scratchBase : os.tmpdir()
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(base, 'tw-mod-')))
  const file = path.join(dir, `register-${counter++}.mjs`)
  fs.writeFileSync(file, source)
  const mod = await import(pathToFileURL(file).href)
  const hooks = []
  mod.register((name, matcher, fn) => {
    if (typeof matcher === 'function') { fn = matcher; matcher = undefined }
    hooks.push({ name, matcher, fn })
    return { catch() {} }
  })
  const log = path.join(dir, 'data', 'events.jsonl')
  const calls = []
  const env = { ...process.env, TRIPWIRE_FILE: log, HOME: dir }
  const api = (over = {}) => ({
    plugin: { name: 'axiom-tripwire', root: pluginRoot },
    process: {
      async run(argv, init) {
        calls.push({ argv, init })
        if (over.runFails) throw new Error('cannot start')
        const done = spawnSync(argv[0], argv.slice(1), { input: init.stdin, env, encoding: 'utf8' })
        return { exitCode: done.status, stdout: done.stdout, stderr: done.stderr }
      },
    },
  })
  const rows = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [])
  const raw = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '')
  const find = (name, door) =>
    hooks.find(h => h.name === name && (door === undefined || (h.matcher && h.matcher.door === door)))
  // Fire an event through the registered hook; next resolves to `answer`.
  const fire = async (name, event, answer, { origin = ENGINE, door, apiOver } = {}) => {
    const hook = find(name, door)
    const next = async () => answer
    next.origin = origin
    const result = await hook.fn(api(apiOver), event, next)
    return { result, answer }
  }
  return { hooks, rows, raw, fire, find, calls, dir }
}

const check = (over = {}) => ({ tool: 'Bash', tool_use_id: 'toolu_1', input: { command: 'echo ' + SECRET }, ...over })
const row = (id, text, over = {}) => ({
  door: 'tool-result',
  origin: { kind: 'tool', tool: 'Bash' },
  message: { type: 'user', content: [{ type: 'tool_result', tool_use_id: id, is_error: true, content: text, ...over }] },
})

test('registers exactly the three observer hooks', async () => {
  const m = await load()
  assert.deepEqual(m.hooks.map(h => h.name), ['agent.spawn', 'tool.check', 'session.append'])
  assert.deepEqual(m.find('session.append').matcher, { door: 'tool-result' })
})

test('deny rule is logged once, with five fields and the right labels', async () => {
  const m = await load()
  const decided = { decision: 'deny', reason: 'denied ' + SECRET, rule: 'Bash(rm:*)' }
  const { result } = await m.fire('tool.check', check(), decided)
  assert.equal(result, decided)
  const rows = m.rows()
  assert.equal(rows.length, 1)
  assert.deepEqual(Object.keys(rows[0]).sort(), FIVE)
  assert.deepEqual({ ...rows[0], ts: 0 }, { ts: 0, profile: 'main', kind: 'tool_blocked', tool: 'Bash', how: 'deny_rule' })
  assert.equal(typeof rows[0].ts, 'number')
})

test('PreToolUse hook block and other policy denials get their own labels', async () => {
  const m = await load()
  await m.fire('tool.check', check({ tool_use_id: 'a' }), { decision: 'deny', hook: 'PreToolUse', reason: 'x' })
  await m.fire('tool.check', check({ tool_use_id: 'b' }), { decision: 'deny', reason: 'plan mode' })
  assert.deepEqual(m.rows().map(r => r.how), ['pretooluse_hook', 'other_policy'])
})

test('a rule wins over a hook when both are named', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'deny', rule: 'Bash(x)', hook: 'PreToolUse' })
  assert.equal(m.rows()[0].how, 'deny_rule')
})

test('allowed calls log nothing', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'allow' })
  assert.equal(m.rows().length, 0)
  assert.equal(m.calls.length, 0)
})

test('declined dialog is logged when the result arrives', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'needs approval ' + SECRET })
  assert.equal(m.rows().length, 0, 'an ask alone is not a refusal')
  const text = "The user doesn't want to proceed with this tool use. The tool use was rejected."
  const { result, answer } = await m.fire('session.append', row('toolu_1', text), { stored: true }, { door: 'tool-result' })
  assert.equal(result, answer)
  assert.deepEqual({ ...m.rows()[0], ts: 0 }, { ts: 0, profile: 'main', kind: 'permission_declined', tool: 'Bash', how: 'user_declined' })
})

test('declined result held as text blocks is read too', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'r' })
  await m.fire('session.append', row('toolu_1', [{ type: 'text', text: "The user doesn't want to proceed with this tool use." }]), {}, { door: 'tool-result' })
  assert.equal(m.rows()[0].how, 'user_declined')
})

test('nobody to ask: the result repeats the approval question', async () => {
  const m = await load()
  const reason = "Output redirection to '/x/y' needs approval. " + SECRET
  await m.fire('tool.check', check(), { decision: 'ask', reason })
  await m.fire('session.append', row('toolu_1', reason), {}, { door: 'tool-result' })
  assert.equal(m.rows()[0].how, 'no_approver')
  assert.equal(m.rows()[0].kind, 'permission_declined')
})

test("dontAsk mode refusal is labelled", async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'needs approval' })
  await m.fire('session.append', row('toolu_1', "Permission to use Bash has been denied because Claude Code is running in don't ask mode."), {}, { door: 'tool-result' })
  assert.equal(m.rows()[0].how, 'dont_ask_mode')
})

test('an asked call that then ran and failed is not a refusal', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'needs approval' })
  await m.fire('session.append', row('toolu_1', 'command not found: nope'), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 0)
})

test('an approved call that succeeded is not a refusal', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'needs approval' })
  await m.fire('session.append', row('toolu_1', DECLINED, { is_error: false }), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 0)
})

test("auto mode classifier refusals are left to the settings hook", async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'ask', reason: 'needs approval' })
  await m.fire('session.append', row('toolu_1', 'Permission for this action has been denied. Reason: [Irreversible Local Destruction]'), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 0)
})

test('a result row with no earlier ask is ignored', async () => {
  const m = await load()
  await m.fire('session.append', row('toolu_9', "The user doesn't want to proceed with this tool use."), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 0)
})

test('one refusal is never written twice', async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'deny', rule: 'Bash(x)' })
  await m.fire('tool.check', check(), { decision: 'deny', rule: 'Bash(x)' })
  await m.fire('session.append', row('toolu_1', 'Permission to use Bash has been denied.'), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 1)
})

test("other mods' queries and calls without an id are not logged", async () => {
  const m = await load()
  await m.fire('tool.check', check(), { decision: 'deny', rule: 'x' }, { origin: { plugin: 'other', tier: 'user' } })
  await m.fire('tool.check', check({ tool_use_id: undefined }), { decision: 'deny', rule: 'x' })
  await m.fire('tool.check', check({ tool_use_id: '' }), { decision: 'deny', rule: 'x' })
  assert.equal(m.rows().length, 0)
})

test('subagent type becomes the profile; an unknown agent id becomes "subagent"', async () => {
  const m = await load()
  const out = await m.fire('agent.spawn', { subagentType: 'security-reviewer', prompt: SECRET }, { model: 'm', agentId: 'agent-1' })
  assert.deepEqual(out.result, out.answer)
  await m.fire('tool.check', check({ tool_use_id: 'a', agentId: 'agent-1' }), { decision: 'deny', rule: 'x' })
  await m.fire('tool.check', check({ tool_use_id: 'b', agentId: 'agent-2' }), { decision: 'deny', rule: 'x' })
  await m.fire('tool.check', check({ tool_use_id: 'c' }), { decision: 'deny', rule: 'x' })
  assert.deepEqual(m.rows().map(r => r.profile), ['security-reviewer', 'subagent', 'main'])
})

test('no command, reason, path or result text reaches the log or the script', async () => {
  const m = await load()
  const reason = "Output redirection to '/home/example/client-project/out.txt' needs approval " + SECRET
  await m.fire('tool.check', check({ tool_use_id: 'a', input: { command: 'curl ' + SECRET, file_path: '/home/example/client-project' } }), { decision: 'deny', reason, rule: 'Bash(curl:*)' })
  await m.fire('tool.check', check({ tool_use_id: 'b' }), { decision: 'ask', reason })
  await m.fire('session.append', row('b', reason), {}, { door: 'tool-result' })
  const sent = JSON.stringify(m.calls)
  for (const forbidden of [SECRET, 'client-project', 'curl', 'toolu_', 'approval']) {
    assert.ok(!m.raw().includes(forbidden), `log leaks ${forbidden}`)
    assert.ok(!sent.includes(forbidden), `script input leaks ${forbidden}`)
  }
  assert.equal(m.rows().length, 2)
})

test('a tool name that is not identifier-shaped is written as unknown', async () => {
  const m = await load()
  await m.fire('tool.check', check({ tool: 'run ' + SECRET }), { decision: 'deny', rule: 'x' })
  assert.equal(m.rows()[0].tool, 'unknown')
  assert.ok(!m.raw().includes(SECRET))
})

test('fails open: a log failure never changes what the hook returns', async () => {
  const m = await load()
  const decided = { decision: 'deny', rule: 'Bash(x)' }
  const a = await m.fire('tool.check', check(), decided, { apiOver: { runFails: true } })
  assert.equal(a.result, decided)
  await m.fire('tool.check', check({ tool_use_id: 'b' }), { decision: 'ask', reason: 'r' })
  const stored = { stored: true }
  const b = await m.fire('session.append', row('b', DECLINED), stored, { door: 'tool-result', apiOver: { runFails: true } })
  assert.equal(b.result, stored)
})

test('fails open: odd events and odd answers never throw', async () => {
  const m = await load()
  for (const answer of [undefined, null, {}, { decision: 7 }, 'x']) {
    const { result } = await m.fire('tool.check', check(), answer)
    assert.equal(result, answer)
  }
  for (const event of [{}, { message: null }, { message: { content: 'x' } }, { message: { content: [null, 1, {}] } }]) {
    await m.fire('session.append', event, { ok: 1 }, { door: 'tool-result' })
  }
  await m.fire('agent.spawn', {}, undefined)
  assert.equal(m.rows().length, 0)
})

test('the tables are bounded', async () => {
  const m = await load()
  for (let i = 0; i < 1500; i += 1) {
    await m.fire('tool.check', check({ tool_use_id: 'id' + i }), { decision: 'ask', reason: 'r' })
  }
  await m.fire('tool.check', check({ tool_use_id: 'late' }), { decision: 'ask', reason: 'r' })
  await m.fire('session.append', row('late', DECLINED), {}, { door: 'tool-result' })
  assert.equal(m.rows().length, 1)
})

test('every hook passes the event on with next and never answers in its place', () => {
  assert.ok(!/\bdeny\s*:/.test(source.replace(/\/\/.*$/gm, '').replace(/decision === 'deny'/g, '')), 'register.js must not return { deny }')
  assert.ok(!/decision:\s*'(allow|deny|ask)'/.test(source), 'register.js must not return a decision')
})
