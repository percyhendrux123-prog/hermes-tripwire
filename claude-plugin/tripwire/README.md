# Tripwire for Claude Code

When one of my agents gets told no, I want to know.

Tripwire is a small Claude Code plugin. Each time Claude Code refuses a tool call, it writes one line to a private log file. It does nothing else. It never blocks, approves or changes a call, and it never prints anything into your session.

It is the Claude Code counterpart of [Tripwire for Hermes Agent](https://github.com/percyhendrux123-prog/hermes-tripwire), and it keeps the same privacy rule: record that something was refused, not what it was.

It has two parts. A settings hook catches auto mode refusals. A mod, which runs inside Claude Code, catches the refusals that settings hooks are never told about: deny rules, hook blocks, declined permission dialogs, and calls that needed approval with nobody to ask.

## What it records, and what it doesn't

One line per refusal, with exactly five fields:

| Field | Value |
|---|---|
| `ts` | Unix timestamp |
| `profile` | The subagent type when the refusal happened inside a subagent, otherwise `main`. A subagent whose type was not seen starting is `subagent`. |
| `kind` | `permission_denied`, `tool_blocked` or `permission_declined` |
| `tool` | The tool name, for example `Bash` or `mcp__server__tool` |
| `how` | A fixed label, from the table below |

The labels, by kind:

| `kind` | Meaning | `how` | Source |
|---|---|---|---|
| `permission_denied` | Auto mode refused the call | `policy_verdict`, `classifier_verdict`, `no_verdict`, `classifier_unavailable`, `unspecified` | Settings hook |
| `tool_blocked` | The verdict was "deny", so nobody was asked | `deny_rule` (a permission rule matched), `pretooluse_hook` (a `PreToolUse` hook blocked it), `other_policy` (anything else that denied: a mode, an organization block, another mod) | Mod |
| `permission_declined` | Claude Code needed an answer, and the answer was no | `user_declined` (you declined the dialog), `no_approver` (nobody could be asked, as in `claude -p`), `dont_ask_mode` (`dontAsk` mode turned the question into a refusal) | Mod |

Example line:

```
{"ts": 1790000000.5, "profile": "main", "kind": "tool_blocked", "tool": "Bash", "how": "deny_rule"}
```

- No commands, tool arguments, file paths, denial text, session ids, working directories or message text are stored. The settings hook and the mod receive them from Claude Code. The mod reads the permission reason and the result text in memory, only to choose a label, and drops them. Only the tool name, the agent type and the label are passed on.
- The script that writes the log accepts only the fixed labels above. Anything else is dropped, or written as `unspecified`, so even a bug in the mod cannot put free text in the log.
- Profile and tool values must be identifier-shaped (1 to 80 ASCII letters, digits or `_.:/-`, starting with a letter, digit or underscore). Anything else is written as `unknown`. Do not put sensitive data in agent or tool names.
- If recording fails for any reason (bad input, unwritable folder, a symlink where the log should be, `python3` missing), it fails quietly and the session carries on. A storage failure can therefore mean a missed record.
- The mod only observes. Each of its hooks passes the event on and returns exactly what it received. A fault in the mod is skipped by Claude Code, so a problem here cannot become a block.

## Before you install

- **Files it writes:** `~/.claude/tripwire/events.jsonl` by default. The directory is created as 0700 and the file as 0600, and existing permissions are tightened before each append. A symlink in place of the log is refused. Set the environment variable `TRIPWIRE_FILE` to use a different file path (`~` is expanded).
- **Files it reads:** none. The settings hook reads the event on standard input. The mod reads events inside Claude Code.
- **Network at runtime:** none.
- **Runtime shell commands:** the mod starts one process per recorded refusal: `python3` running the plugin's own `hooks/tripwire_hook.py`, with the record on standard input. Nothing else is started. No background processes, stored credentials or telemetry.
- **What the mod can see:** a mod runs inside Claude Code with your permissions, as the [mods overview](https://code.claude.com/docs/en/plugins/mods/overview#what-a-mod-can-reach) describes. This one hooks three events: `tool.check` (each permission verdict), `session.append` for tool results (each result row), and `agent.spawn` (to learn subagent types). It calls one API method, `$.process.run`. You can confirm this yourself: `claude plugin validate claude-plugin/tripwire` lists the `hooks:` and `calls:` lines.
- **Requires:** `python3` on your PATH, and a Claude Code version with mods (v2.1.287 or later) and the `PermissionDenied` hook event. The mod half was tested on Claude Code 2.1.325 only. Rows are appended with a file lock on macOS and Linux; on Windows the append is unlocked.
- **Not a directory plugin:** it contains a mod and a script, so it installs from this repository, not from the Anthropic plugin directory.

## Install

```
claude plugin marketplace add percyhendrux123-prog/hermes-tripwire
claude plugin install axiom-tripwire@deploy-axiom-tripwire
```

If a session is already open, run `/reload-plugins` in it. In an interactive session, `/plugin` shows `1 mod active · axiom-tripwire` once the mod has loaded.

To try it for one session without installing, point Claude Code at the plugin folder:

```
claude --plugin-dir ./claude-plugin/tripwire
```

## What it can and cannot see

- **Logged by the settings hook:** auto mode denying a tool call, including denials where the classifier gave no verdict or was unavailable. These arrive as the `PermissionDenied` hook event.
- **Logged by the mod:** a `deny` rule matching; a `PreToolUse` hook blocking the call; you declining a permission dialog (the "No" choice); a call that needs approval where nobody can be asked, such as `claude -p` in the default mode; and `dontAsk` mode refusing a call. It also covers subagents' calls.
- **Checked live** (Claude Code 2.1.325, throwaway config, harmless stand-in commands): a deny rule, a blocking `PreToolUse` hook, `dontAsk` mode, a headless call needing approval (main session and a subagent), and a declined dialog in an interactive session each wrote exactly one line. A permitted call wrote none, and an approved dialog wrote none.

## Known gaps

These refusals are not logged. This is from the mods and hooks references at the time of writing and from the checks above; check them if a newer Claude Code adds events.

- **Auto mode refusals are only as visible as the settings hook.** The mod does not try to log them, so one refusal is not written twice. The classifier's wording was not exercised in a live run of the mod.
- **A refusal that happens before any mod hook runs.** A `PreToolUse` hook in your organization's managed settings runs before the mods. The docs say that when it blocks a call, no mod's `tool.call` hook runs; whether `tool.check` is reached was not tested, so treat this as unlogged. The same goes for another mod that answers a call itself with a refusal.
- **A `PermissionRequest` hook that denies a dialog.** The mod recognises three outcomes by the wording of the result Claude Code gives the model, and a refusal worded differently is not recognised. Only the dialog decline was seen in a live run.
- **Wording can change.** `user_declined` and `dont_ask_mode` match Claude Code's current refusal messages, and `no_approver` matches a result that repeats the approval question. If a later Claude Code rewords them, those lines stop being written, quietly. The tests and the live check would need repeating.
- **`other_policy` is a catch-all.** A mode, an organization block, a `tool.check` verdict from another mod, and anything else that denied without naming a rule or a `PreToolUse` hook look the same.
- **The call was rejected before it ran**: an unknown tool name, or input that failed validation. Claude Code asks for no permission verdict for these.
- **Tool failures.** A tool that ran and then failed (a command that exited non-zero, for instance) is not a refusal. The mod ignores errors that do not match a refusal, and the `PostToolUseFailure` event is deliberately not used.
- **Where the mod does not run.** `--safe-mode` and `"disableAllHooks": true` turn mods off, and an organization can stop user-installed mods from loading. The Desktop app's WSL sessions load no plugins, and its SSH sessions do not run a mod installed only on your computer. With `disableAllHooks` set, the settings hook stops too.
- **Subagent type.** The profile is the subagent type seen when the subagent started. A subagent that started before the mod loaded is `subagent`.

There is no opt-in detail mode in this version. The Hermes plugin has one that adds a redacted reason and an arguments hash; the Claude Code version does not.

## Try it with no install

```
python3 -m unittest discover -s claude-plugin/tests
node --test claude-plugin/tests/test_register.mjs
```

The Python tests feed sample hook events and mod records to the script and check the written line, that no argument text leaks, and that bad input never fails the hook. The Node tests load the real `register.js` with a small fake of Claude Code and check each refusal kind end to end, that every hook returns exactly what it was given, and that a failure in the log writer changes nothing. (The Python run also runs the Node file when `node` is installed.) They use a temporary directory and touch nothing in `~/.claude`.

`claude plugin test` runs `*.test.ts` files from inside a plugin folder, so `claude-plugin/tests/tripwire.test.ts` is run on a copy; the steps are in that file. It checks only that the mod loads and passes a verdict through unchanged, because the test kit cannot give a permission check a call id.

## Undo

Run `claude plugin uninstall axiom-tripwire` and, if you added the marketplace, `claude plugin marketplace remove deploy-axiom-tripwire`. Delete `~/.claude/tripwire/` (or your `TRIPWIRE_FILE`) if you no longer want the log. Existing rows are never rewritten or deleted by the plugin.

## How it was made

I designed it, set the rules for what it may record, and tested it on my own system. AI agents wrote the code under my spec and review. I read Python; I don't claim to write it by hand.

Percy Keith, Deploy Axiom. MIT license.
