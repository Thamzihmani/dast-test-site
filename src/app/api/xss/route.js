/**
 * Reflected XSS Test Endpoint
 *
 * VULNERABILITY: `q` parameter reflected directly into HTML response without escaping.
 * DETECTOR:      xss
 * SCAN PROFILES: full, owasp-top10, quick
 *
 * WAF INTERACTION (fragmentationEnabled test):
 *   ENABLE_FAKE_WAF=false: payload <script>alert(1)</script> reaches this endpoint → XSS confirmed
 *   ENABLE_FAKE_WAF=true:
 *     fragmentationEnabled=false → WAF blocks <script> → endpoint never reached → 0 findings
 *     fragmentationEnabled=true  → WAF sees split chunks → endpoint reached → XSS confirmed
 *
 * HOW DETECTION WORKS:
 *   DAST injects payloads like <script>alert(1)</script> into the `q` param.
 *   If the payload is reflected verbatim in text/html response → XSS finding.
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url)
  // Intentionally NOT sanitised — do not use encodeURIComponent or escapeHtml here
  const q = searchParams.get('q') || ''

  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Search Results</title>
  <style>body { font-family: monospace; background: #0f0f0f; color: #e0e0e0; padding: 24px; }</style>
</head>
<body>
  <h1>Search Results</h1>
  <!-- VULNERABLE: user input reflected without sanitisation -->
  <p>You searched for: <strong>${q}</strong></p>
  <p>No results found for &quot;${q}&quot;</p>
  <form method="GET" action="/api/xss">
    <input name="q" value="${q}" />
    <button type="submit">Search again</button>
  </form>
  <a href="/">← Back to home</a>
</body>
</html>`

  return new Response(html, {
    status: 200,
    headers: {
      // text/html is required for XSS — browsers execute scripts in HTML responses
      'Content-Type': 'text/html; charset=utf-8',
      // Intentionally NO X-XSS-Protection, NO Content-Security-Policy
    },
  })
}
