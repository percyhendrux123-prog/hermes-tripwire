# Tripwire for Claude Code

When one of my agents gets told no, I want to know.

Tripwire is a small Claude Code plugin. Each time Claude Code's auto mode refuses a tool call, it writes one line to a private log file. It does nothing else. It never blocks, approves or changes a call, and it never prints anything into your session.

It is the Claude Code counterpart of [Tripwire for Hermes Agent](https://github.com/percyhendrux123-prog/hermes-tripwire), and it keeps the same privacy rule: record that something was refused, not what it was.

## What it records, and what it doesn't

One line per refusal, with exactly five fields:

| Field | Value |
|---|---|
| `ts` | Unix timestamp |
| `profile` | The subagent type when the refusal happened inside a subagent, otherwise `main` |
| `kind` | `permission_denied` |
| `tool` | The tool name, for example `Bash` or `mcp__server__tool` |
| `how` | A fixed label for the kind of denial: `policy_verdict`, `classifier_verdict`, `no_verdict`, `classifier_unavailable` or `unspecified` |

Example line:

```
{"ts": 1790000000.5, "profile": "main", "kind": "permission_denied", "tool": "Bash", "how": "policy_verdict"}
```

- No commands, tool arguments, file paths, denial text, session ids, working directories or message text are stored. The hook receives them from Claude Code, but only the tool name and the type of denial are used.
- Profile and tool values must be identifier-shaped (1 to 80 ASCII letters, digits or `_.:/-`, starting with a letter, digit or underscore). Anything else is written as `unknown`. Do not put sensitive data in agent or tool names.
- `how` is chosen from the five fixed labels above by matching the wording of Claude Code's denial reason. The reason text itself is discarded.
- If recording fails for any reason (bad input, unwritable folder, a symlink where the log should be), the hook exits quietly with status 0 and the session carries on. A storage failure can therefore mean a missed record.

## Before you install

- **Files it writes:** `~/.claude/tripwire/events.jsonl` by default. The directory is created as 0700 and the file as 0600, and existing permissions are tightened before each append. A symlink in place of the log is refused. Set the environment variable `TRIPWIRE_FILE` to use a different file path (`~` is expanded).
- **Files it reads:** none. It reads only the hook event that Claude Code sends on standard input.
- **Network at runtime:** none.
- **Runtime shell commands, background processes, stored credentials, telemetry:** none. The hook is one Python script that uses only the standard library.
- **Requires:** `python3` on your PATH, and a Claude Code version that has the `PermissionDenied` hook event. Rows are appended with a file lock on macOS and Linux; on Windows the append is unlocked.

## Install

```
claude plugin marketplace add percyhendrux123-prog/hermes-tripwire
claude plugin install tripwire@deploy-axiom-tripwire
```

To try it for one session without installing, point Claude Code at the plugin folder:

```
claude --plugin-dir ./claude-plugin/tripwire
```

## What it can and cannot see

Claude Code only tells a plugin about a refusal in one case, so Tripwire only logs that case.

- **Logged:** auto mode denying a tool call. This includes denials where the classifier gave no verdict, or was unavailable. These arrive as the `PermissionDenied` hook event.

## Known gaps

These refusals are not logged, because Claude Code's hook events do not report them. This is from the hooks reference at the time of writing; check it if a newer Claude Code adds events.

- **You decline a permission dialog yourself.** `PermissionDenied` does not fire.
- **A `deny` rule in your permission settings matches.** `PermissionDenied` does not fire.
- **A `PreToolUse` hook, from this or another plugin, blocks the call.** `PermissionDenied` does not fire, and one hook cannot see another hook's decision.
- **A tool is denied because there is nobody to ask**, for example a headless `claude -p` run in a mode that cannot prompt. The docs list auto mode as the only source of `PermissionDenied`, so this is not logged.
- **The call was rejected before it ran**: an unknown tool name, or input that failed validation. Claude Code fires no hook for these.
- **Tool failures.** The `PostToolUseFailure` event is deliberately not used. The hooks reference says it does not fire for permission denials; it fires when a tool ran and then failed (a command that exited non-zero, for instance), which is not a refusal.

There is no opt-in detail mode in this version. The Hermes plugin has one that adds a redacted reason and an arguments hash; the Claude Code version does not.

## Try it with no install

```
python3 -m unittest discover -s claude-plugin/tests
```

The tests feed sample hook events to the script and check the written line, that no argument text leaks, and that bad input never fails the hook. They use a temporary directory and touch nothing in `~/.claude`.

## Undo

Run `claude plugin uninstall tripwire` and, if you added the marketplace, `claude plugin marketplace remove deploy-axiom-tripwire`. Delete `~/.claude/tripwire/` (or your `TRIPWIRE_FILE`) if you no longer want the log. Existing rows are never rewritten or deleted by the plugin.

## How it was made

I designed it, set the rules for what it may record, and tested it on my own system. AI agents wrote the code under my spec and review. I read Python; I don't claim to write it by hand.

Percy Keith, Deploy Axiom. MIT license.
