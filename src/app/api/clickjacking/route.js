/**
 * Clickjacking Test Endpoint
 *
 * VULNERABILITY: HTML page served without X-Frame-Options or CSP frame-ancestors.
 * DETECTOR:      clickjacking
 * SCAN PROFILES: full, owasp-top10
 *
 * HOW DETECTION WORKS:
 *   DAST checks: is the response text/html AND is X-Frame-Options missing AND
 *                is Content-Security-Policy frame-ancestors missing?
 *   → Clickjacking finding.
 *
 * REAL RISK:
 *   Attacker embeds this page in an iframe on their site.
 *   User thinks they're clicking on attacker's site but actually clicking on hidden iframe.
 */
export async function GET() {
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Payment Confirmation</title>
  <style>
    body { font-family: monospace; background: #0f0f0f; color: #e0e0e0; padding: 48px; text-align: center; }
    .btn { background: #ff4444; color: white; border: none; padding: 16px 48px; font-size: 18px; cursor: pointer; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Confirm Payment</h1>
  <p>Click below to confirm your $500 transfer to account #12345</p>
  <form method="POST" action="/api/csrf">
    <input type="hidden" name="action" value="transfer" />
    <input type="hidden" name="amount" value="500" />
    <input type="hidden" name="to" value="12345" />
    <button class="btn" type="submit">Confirm Transfer</button>
  </form>
  <!-- This page has NO X-Frame-Options — can be embedded in an attacker's iframe -->
</body>
</html>`

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      // ✗ No X-Frame-Options: DENY
      // ✗ No Content-Security-Policy: frame-ancestors 'none'
    },
  })
}
