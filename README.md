# Tripwire for Hermes Agent

When one of my agents gets told no, I want to know.

Tripwire is a small plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Every time an agent is refused an action, it writes one line to a log. A refusal can be a tool blocked by a guardrail or another plugin, or a risky command denied, cancelled or timed out at approval. A scheduled job then reads the new lines and sends you one short alert. If nothing was refused, you hear nothing.

## Why I built it

I run two businesses on a team of Hermes agents. Most of the time a refusal means the guardrails worked. But a cluster of them from one session can mean something tried to steer an agent. In my practice drill, a fake intake form carried a hidden instruction to text out a client list and delete the logs. All three actions were stopped. Then the agent wrote a clean, friendly summary that mentioned none of it.

That is the point of Tripwire. It records what happened instead of asking the agent what happened.

## What it records, and what it doesn't

One line per refusal, with these fields: time, agent profile, tool, how it was stopped, a short reason, and the session id.

- It never stores tool arguments, results or message text.
- The reason is the refusal message, cut to 120 characters. Some refusal messages name the rule that fired, so read your own log once before you share it.
- It only watches. It never blocks anything, and if it hits an error it gets out of the way (it fails open).
- **Known gap:** if a model calls a tool that isn't in its toolset at all, Hermes rejects the call before any plugin hook runs, so Tripwire doesn't see it.

## Install

1. Copy the `tripwire/` folder to `~/.hermes/plugins/tripwire`, then enable it in every profile you want watched:
   ```
   hermes plugins enable tripwire
   hermes -p <profile> plugins enable tripwire
   ```
2. Copy `scripts/tripwire_notify.py` to `~/.hermes/scripts/`, then schedule it with no agent, so no model runs and no tokens are spent:
   ```
   hermes cron create "every 5m" --name "Tripwire alerts" --script tripwire_notify.py --no-agent --deliver telegram
   ```
   Any delivery target Hermes supports works. Empty output means a silent run.
3. Restart the gateway so the plugin loads.

Events go to `~/.hermes/tripwire/events.jsonl`. Set `TRIPWIRE_DIR` to point the notifier at a different folder, which is how I run drills without touching the real log.

## Prove it works

```
echo "default terminal" > ~/.hermes/tripwire/TEST_BLOCK
```
That blocks the terminal tool for the `default` profile only. Ask an agent to run any command, check that the event line and the alert both show up, then turn the switch off:
```
rm ~/.hermes/tripwire/TEST_BLOCK
```

## Try it with no install

```
python3 -m unittest discover tests
TRIPWIRE_DIR=$(mktemp -d) sh -c 'cp examples/events.sample.jsonl $TRIPWIRE_DIR/events.jsonl && python3 scripts/tripwire_notify.py'
```
`examples/events.sample.jsonl` is fake drill data.

## Undo

Run `hermes plugins disable tripwire` (add `-p <profile>` for each other profile), remove the cron job with `hermes cron remove <id>`, and restart the gateway.

## How it was made

I designed it, set the rules for what it may record, and tested it on my own system. AI agents wrote the code under my spec and review. I read Python; I don't claim to write it by hand.

Percy Keith, Deploy Axiom. MIT license.
