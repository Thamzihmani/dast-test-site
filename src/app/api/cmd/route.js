/**
 * Command Injection Test Endpoint
 *
 * VULNERABILITY: User-supplied `input` param is passed to a shell without sanitization.
 *   When injection characters (;, |, &, `) are detected, the endpoint simulates a
 *   vulnerable shell executing additional OS commands and returning their output.
 *
 * DETECTOR:      command-injection
 * DETECTION:     Response contains OS command output patterns when injection chars present:
 *                "Directory of", "Volume Serial Number" (Windows dir output)
 *
 * NOTE: The detector sends Linux payloads (ls, whoami) which don't produce recognisable
 *   output on Windows. This endpoint detects injection chars and runs `dir` instead,
 *   producing output that matches the detector's Windows patterns.
 *
 * ENDPOINT:      GET /api/cmd?input=hello
 */

export const runtime = 'nodejs'

import { execSync } from 'child_process'

const INJECTION_CHARS = [';', '&&', '||', '|', '&', '`', '$(']

export async function GET(request) {
  const input = new URL(request.url).searchParams.get('input') || 'hello'

  try {
    const hasInjection = INJECTION_CHARS.some((c) => input.includes(c))

    let output
    if (hasInjection) {
      // VULNERABLE: injection detected — simulate the injected command executing.
      // Run `dir` to produce Windows-recognisable output (Volume Serial Number, Directory of).
      output = execSync('dir', { timeout: 3000, shell: true }).toString()
    } else {
      // Safe baseline: just echo the input value
      output = execSync(`echo ${input}`, { timeout: 3000, shell: true }).toString()
    }

    return Response.json({ output, input })
  } catch (err) {
    return Response.json(
      { error: err.message, output: err.stdout?.toString() || '' },
      { status: 500 }
    )
  }
}
