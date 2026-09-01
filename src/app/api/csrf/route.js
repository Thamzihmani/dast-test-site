/**
 * CSRF Test Endpoint
 *
 * VULNERABILITY: State-changing POST endpoint that accepts requests
 *                without any CSRF token validation.
 * DETECTOR:      csrf
 * SCAN PROFILES: full, owasp-top10
 *
 * HOW DETECTION WORKS:
 *   DAST looks for:
 *     1. Forms in HTML pages that POST to this endpoint without a CSRF hidden input
 *     2. POST endpoints that don't check Origin/Referer or a CSRF token header
 *   If both conditions met → CSRF finding.
 *
 * SEE ALSO: /login page has a form that POSTs to /api/auth/login without a CSRF token.
 */
export async function GET() {
  // Show a form page — spider discovers the POST endpoint via this form
  const html = `<!DOCTYPE html>
<html>
<head><title>Update Settings</title>
<style>body { font-family: monospace; background: #0f0f0f; color: #e0e0e0; padding: 24px; }</style>
</head>
<body>
  <h1>Update Settings</h1>
  <!-- VULNERABLE: No CSRF token in this form -->
  <form method="POST" action="/api/csrf">
    <label>New Email: <input name="email" type="email" value="user@example.com" /></label><br/><br/>
    <label>New Username: <input name="username" type="text" value="alice" /></label><br/><br/>
    <!-- A secure form would have: <input type="hidden" name="_csrf" value="...token..." /> -->
    <button type="submit">Save Changes</button>
  </form>
  <a href="/">← Back</a>
</body>
</html>`
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  })
}

export async function POST(request) {
  let body = {}
  try {
    const contentType = request.headers.get('content-type') || ''
    if (contentType.includes('application/json')) {
      body = await request.json()
    } else {
      const formData = await request.formData()
      for (const [key, value] of formData.entries()) body[key] = value
    }
  } catch {
    // ignore parse errors
  }

  // VULNERABLE: no CSRF token check, no Origin/Referer validation
  return new Response(
    JSON.stringify({
      success: true,
      message: 'Settings updated successfully',
      updatedFields: body,
      warning: 'VULNERABILITY: No CSRF token validated — any site can trigger this action',
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  )
}
