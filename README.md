# Tripwire for Hermes Agent

When one of my agents gets told no, I want to know.

Tripwire is a small plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Every time an agent is refused an action, it writes one line to a log. A refusal can be a tool blocked by a guardrail or another plugin, or a risky command denied, cancelled or timed out at approval. A scheduled job then reads the new lines and sends you one short alert. If nothing was refused, you hear nothing.

## Why I built it

I run two businesses on a team of Hermes agents. Most of the time a refusal means the guardrails worked. But a cluster of them from one session can mean something tried to steer an agent. In my practice drill, a fake intake form carried a hidden instruction to text out a client list and delete the logs. All three actions were stopped. Then the agent wrote a clean, friendly summary that mentioned none of it.

That is the point of Tripwire. It records what happened instead of asking the agent what happened.

## What it records, and what it doesn't

One line per refusal, with exactly five fields: timestamp (`ts`), agent profile (`profile`), event kind (`kind`), tool identifier (`tool`), and rejection category or approval choice (`how`).

- No refusal-message snippets, approval-rule text, session ids, surface names, tool arguments, commands, results or message text are stored. Profile, tool and category values must be identifier-shaped (1–80 ASCII letters/digits or `_.:/-`, starting with a letter/digit/underscore); other values become `unknown`. Do not put sensitive data in identifier names.
- Logs from versions before 0.1.3 may contain refusal-message or rule fragments. Upgrading does not erase old records; review or remove those yourself before sharing a log.
- It only watches, except for the explicit `TEST_BLOCK` drill switch described below. If recording hits an error, the plugin gets out of the way (it fails open). A storage failure can therefore mean a missed record.
- **Not alerted:** housekeeping blocks tagged `suspected_pruned_tool_arguments`, and `tool_scope_block` rejections matching the host's complete `tool_call to '…' failed argument validation at arguments… (…)` or `tool_call to '…' is missing required argument(s): ….` typo templates. Other categories, policy reasons merely containing those phrases, or unrecognized message shapes still alert. New typo rejections are not written; the notifier applies the same narrow filter to legacy records.
- **Known gap:** if a model calls a tool that isn't in its toolset at all, Hermes rejects the call before any plugin hook runs, so Tripwire doesn't see it.

## Before you install

- **Files it writes:** one line per refusal to `~/.hermes/tripwire/events.jsonl` by default, shared across profiles. Data directories are created as 0700 and the event file as 0600; existing data-directory/event-file modes are tightened before appending. Event-file symlinks are refused. The optional notifier reads that file and its `notify-offset` cursor, and writes a 0600 temporary cursor then atomically replaces `notify-offset` in the same directory. It does not erase or rotate events.
- **Files it reads:** the `TEST_BLOCK` switch beside the effective event file. While that file exists, the plugin blocks the one tool it names for the one profile it names. That is the only time Tripwire blocks anything, and it exists to prove the alarm works.
- **Network at runtime:** none. Alerts go out only through the Hermes cron delivery you choose. The optional manual notifier download below contacts GitHub at setup time.
- **Runtime shell commands, background processes, stored credentials, telemetry:** none.
- Requires Hermes >=0.22.5. Uses Python's `fcntl`, so macOS and Linux only. Synthetic tests run on Linux/Python 3.12; native installation and cron delivery must be checked on your Hermes host.

## Install

Use the reviewed catalog pin, not an unpinned repository URL:

```sh
hermes plugins install tripwire
hermes plugins enable tripwire
```

For another profile, install and enable there too:

```sh
hermes -p <profile> plugins install tripwire
hermes -p <profile> plugins enable tripwire
```

Check the installed version and record the exact 40-hex commit shown at installation. This README describes 0.1.3; if the catalog still points at an older version, these fixes are not installed yet. Do not replace a reviewed pin with a branch-tip install to work around that. The catalog installs the `tripwire/` subtree, including its MIT `LICENSE`.

### Optional notifier (separate download)

The catalog does **not** install `scripts/tripwire_notify.py`. Obtain it from the **same full commit SHA as your installed plugin**, not `main`, a version label or a different catalog revision. Replace the placeholder below with the recorded pin, then download and inspect the readable Python before scheduling it:

```sh
TRIPWIRE_SHA='<40-hex SHA of your installed catalog pin>'
mkdir -p "$HOME/.hermes/scripts"
curl --fail --location --proto '=https' \
  "https://raw.githubusercontent.com/percyhendrux123-prog/hermes-tripwire/${TRIPWIRE_SHA}/scripts/tripwire_notify.py" \
  --output "$HOME/.hermes/scripts/tripwire_notify.py"
```

The repository's README, source and root LICENSE are also available at that exact SHA. When updating the plugin, update this separate script to the new installed pin too. From a local checkout already at that pin, copying `scripts/tripwire_notify.py` is equivalent.

Schedule it with no agent, so no model runs and no tokens are spent:

```sh
hermes cron create "every 5m" --name "Tripwire alerts" --script tripwire_notify.py --no-agent --deliver telegram
```

Any delivery target Hermes supports works. Empty stdout means a silent run. The notifier validates each complete JSON line, skips malformed records and reports their count on stderr without echoing content. It flushes the valid alert to stdout before atomically advancing the byte cursor; failures before cursor replacement can repeat an alert rather than silently lose it. Hermes cron owns delivery after stdout, so this is not a receipt that a message reached you. Alerts show the last eight refusals plus a count/agent summary of any earlier ones in that batch; full records remain in the log.

Restart the gateway after enabling the plugin so it loads. For local development only, copying the entire `tripwire/` directory (including LICENSE) to `~/.hermes/plugins/tripwire` and enabling it is the manual alternative; this bypasses catalog pin review.

## Paths and overrides

The plugin writer, drill switch and standalone notifier use the **same contract**:

| Setting | Effective path |
|---|---|
| No overrides | `~/.hermes/tripwire/events.jsonl` |
| `TRIPWIRE_DIR` | `<TRIPWIRE_DIR>/events.jsonl` |
| `TRIPWIRE_EVENTS` | That exact event-file path; takes precedence over `TRIPWIRE_DIR` |
| Drill switch | `TEST_BLOCK` beside the effective event file |
| Notifier cursor | `notify-offset` beside the effective event file |

Use a dedicated data directory and absolute override paths (`~` is expanded in Python). The writer tightens its data-directory permissions; do not point it at a shared working directory. Set the same environment in every watched profile/gateway and the notifier's cron process, then restart the gateway after changes. These paths are deliberately shared, not derived from `HERMES_HOME` or the active profile. An override is not isolation unless all of those processes use it. Empty overrides fall back to defaults.

## Prove it works

The commands below use the default path. If you set an override, use `TEST_BLOCK` beside your effective event file instead.

```sh
(umask 077; mkdir -p -m 700 "$HOME/.hermes/tripwire"; printf '%s\n' 'default terminal' > "$HOME/.hermes/tripwire/TEST_BLOCK")
```
That blocks the terminal tool for the `default` profile only. Ask an agent to run any command, check that the event line and the alert both show up, then turn the switch off:
```sh
rm "$HOME/.hermes/tripwire/TEST_BLOCK"
```

## Try it with no install

```
python3 -m unittest discover -s tests
TRIPWIRE_DIR=$(mktemp -d) sh -c 'cp examples/events.sample.jsonl $TRIPWIRE_DIR/events.jsonl && python3 scripts/tripwire_notify.py'
```
`examples/events.sample.jsonl` is fake drill data.

## Undo

Run `hermes plugins disable tripwire` (add `-p <profile>` for each other profile), remove the cron job with `hermes cron remove <id>`, and restart the gateway.

## How it was made

I designed it, set the rules for what it may record, and tested it on my own system. AI agents wrote the code under my spec and review. I read Python; I don't claim to write it by hand.

Percy Keith, Deploy Axiom. MIT license.
