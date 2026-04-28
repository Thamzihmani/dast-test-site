/**
 * Open Redirect Test Endpoint
 *
 * VULNERABILITY: Redirects to any URL supplied in the `url` parameter without validation.
 * DETECTOR:      open-redirect
 * SCAN PROFILES: full, owasp-top10
 *
 * HOW DETECTION WORKS:
 *   DAST injects a canary URL like https://evil-dast-test.com into the `url` param.
 *   If the 302 Location header matches the injected URL → open redirect finding.
 *
 * REAL RISK: Attackers use this for phishing:
 *   https://trusted.com/api/redirect?url=https://attacker.com/phishing
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const redirectUrl = searchParams.get('url')

  if (!redirectUrl) {
    return new Response(
      JSON.stringify({ error: 'url parameter is required', example: '/api/redirect?url=https://example.com' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // VULNERABLE: no validation — redirects to any URL including https://evil.com
  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectUrl,
      'X-Redirect-Reason': 'user-supplied', // Evidence for the scanner
    },
  })
}
