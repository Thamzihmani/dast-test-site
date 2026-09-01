/**
 * Path Traversal Test Endpoint
 *
 * VULNERABILITY: `file` parameter used to construct a file path without sanitisation.
 * DETECTOR:      path-traversal (in full + owasp-top10 profiles)
 * SCAN PROFILES: full, owasp-top10
 *
 * HOW DETECTION WORKS:
 *   DAST injects payloads like:
 *     ../../etc/passwd
 *     ../../../windows/system32/drivers/etc/hosts
 *     ....//....//etc/passwd  (double-slash bypass)
 *   If response contains content from those paths (or error indicating access was attempted)
 *   → Path traversal finding.
 *
 * SIMULATION NOTE:
 *   Vercel serverless has no real filesystem for etc/passwd.
 *   This endpoint simulates the vulnerable behavior — returning fake file content
 *   when traversal patterns are detected, so the DAST scanner fires correctly.
 */

const SIMULATED_FILES = {
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n',
  '/etc/hosts': '127.0.0.1 localhost\n::1 localhost ip6-localhost\n10.0.0.1 internal-db\n',
  '/etc/shadow': 'root:$6$salt$hash:18000:0:99999:7:::\nwww-data:!:18000:::::::\n',
  '/proc/self/environ': 'PATH=/usr/local/bin\nJWT_SECRET=secret\nDB_PASSWORD=prod-db-pass-123\n',
  '../../../etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon\n',
}

const TRAVERSAL_PATTERNS = [/\.\./g, /\.\.%2f/gi, /\.\.%5c/gi, /%2e%2e/gi]

function hasTraversal(filePath) {
  return TRAVERSAL_PATTERNS.some((p) => p.test(filePath))
}

function resolveSimulatedPath(filePath) {
  // Normalize traversal to find the target
  const normalized = filePath.replace(/\.\.[/\\]/g, '/').replace(/^\.\./, '')
  const full = normalized.startsWith('/') ? normalized : '/' + normalized
  return full
}

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const file = searchParams.get('file')

  if (!file) {
    return new Response(
      JSON.stringify({ error: 'file parameter is required', example: '/api/path-traversal?file=readme.txt' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // VULNERABLE: checks for traversal but leaks content anyway (simulation)
  if (hasTraversal(file)) {
    const resolvedPath = resolveSimulatedPath(file)
    const simulatedContent = SIMULATED_FILES[resolvedPath] || SIMULATED_FILES[file]

    if (simulatedContent) {
      // Return the fake file content — DAST detects traversal succeeded
      return new Response(simulatedContent, {
        status: 200,
        headers: {
          'Content-Type': 'text/plain',
          'X-File-Path': resolvedPath, // Evidence for scanner
        },
      })
    }

    // Path traversal attempted but file not found — still shows traversal is possible
    return new Response(
      `Error: Cannot read file: ${file}\nResolved path: ${resolvedPath}\nPermission denied or file not found.`,
      {
        status: 403,
        headers: { 'Content-Type': 'text/plain', 'X-File-Path': resolvedPath },
      }
    )
  }

  // Safe file names — return mock content
  const safeFiles = {
    'readme.txt': 'Welcome to DAST Test App. This file is safe to read.\n',
    'info.txt': 'App version: 1.0.0\nEnvironment: production\n',
    'config.txt': 'debug=false\nlog_level=info\n',
  }

  const content = safeFiles[file]
  if (!content) {
    return new Response(
      `Error: File not found: ${file}`,
      { status: 404, headers: { 'Content-Type': 'text/plain' } }
    )
  }

  return new Response(content, {
    status: 200,
    headers: { 'Content-Type': 'text/plain' },
  })
}
