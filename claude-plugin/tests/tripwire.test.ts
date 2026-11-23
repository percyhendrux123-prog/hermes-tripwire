// Kit test for the Tripwire mod, for `claude plugin test`. That command runs
// *.test.ts files found inside the plugin folder, so run it on a copy:
//   T=$(mktemp -d); cp -R claude-plugin/tripwire "$T/t"; cp claude-plugin/tests/tripwire.test.ts "$T/t/hooks/"
//   claude plugin test "$T/t"
// The kit cannot give a tool.check event a call id, so this checks the part it
// can: the mod loads, passes a verdict through unchanged, and sends nothing to
// the log writer for a query that is not one of Claude's own calls. The full
// record path is covered by test_register.mjs (node --test).
import { expect, test } from 'claude-code/testing'

test('the mod passes a verdict through unchanged and logs a bare query as nothing', async ($: any, on: any) => {
  const sent: unknown[] = []
  on('process.run', ($: any, e: any) => {
    sent.push(e.argv)
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  on('tool.check', () => ({ decision: 'deny', reason: 'blocked', rule: 'Bash(rm:*)' }))
  const verdict = await $.tool.check({ tool: 'Bash', input: { command: 'echo hi' } })
  expect(verdict.decision).toBe('deny')
  expect(verdict.rule).toBe('Bash(rm:*)')
  expect(sent.length).toBe(0)
})
