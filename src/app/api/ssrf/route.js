/**
 * SSRF (Server-Side Request Forgery) Test Endpoint
 *
 * VULNERABILITY: Server fetches any URL supplied by the client without restriction.
 * DETECTOR:      ssrf
 * SCAN PROFILES: full, owasp-top10, quick, api-only
 *
 * HOW DETECTION WORKS:
 *   DAST injects URLs like:
 *     http://169.254.169.254/latest/meta-data/  (AWS metadata endpoint)
 *     http://localhost:22                        (internal service scan)
 *     http://0.0.0.0                            (internal network)
 *   If server makes an outbound request to these → SSRF finding.
 *
 * ON VERCEL:
 *   Cloud metadata endpoints (169.254.x.x) are firewalled but the attempt is observable.
 *   Public URLs like http://example.com will work fine.
 *
 * REAL RISK: Attackers use SSRF to:
 *   - Read AWS/GCP/Azure metadata credentials
 *   - Probe internal network services
 *   - Bypass IP allowlists
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const targetUrl = searchParams.get('url')

  if (!targetUrl) {
    return new Response(
      JSON.stringify({
        error: 'url parameter is required',
        example: '/api/ssrf?url=https://example.com',
        dangerousExamples: [
          '/api/ssrf?url=http://169.254.169.254/latest/meta-data/',
          '/api/ssrf?url=http://localhost:8080/admin',
          '/api/ssrf?url=http://internal-service/api',
        ],
      }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  const timeout = parseInt(process.env.SSRF_TIMEOUT_MS || '3000', 10)

  try {
    // VULNERABLE: fetches any URL without validation
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)

    const response = await fetch(targetUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': 'DAST-Test-App/1.0' },
    })
    clearTimeout(timer)

    const contentType = response.headers.get('content-type') || ''
    const body = await response.text()

    return new Response(
      JSON.stringify({
        fetchedUrl: targetUrl,
        status: response.status,
        contentType,
        // Return first 500 chars of body to show content was fetched
        preview: body.slice(0, 500),
        fullBodyLength: body.length,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    // Still a finding — server attempted the request
    return new Response(
      JSON.stringify({
        fetchedUrl: targetUrl,
        error: err.message,
        note: 'Server attempted to fetch the URL — this is still an SSRF vulnerability.',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }
}
