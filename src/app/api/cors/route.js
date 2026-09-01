/**
 * CORS Misconfiguration Test Endpoint
 *
 * VULNERABILITY: Reflects the Origin header back in Access-Control-Allow-Origin
 *                AND sets Access-Control-Allow-Credentials: true.
 * DETECTOR:      cors
 * SCAN PROFILES: full, owasp-top10, api-only
 *
 * WHY THIS IS DANGEROUS:
 *   A legitimate server should only allow specific trusted origins.
 *   Reflecting any Origin + allowing credentials means:
 *   → Attacker's page can make authenticated cross-origin requests to this API.
 *   → Session cookies / auth tokens are sent cross-origin.
 *
 * HOW DETECTION WORKS:
 *   DAST sends a request with Origin: https://evil-test.vigilnz.com
 *   If response has:
 *     Access-Control-Allow-Origin: https://evil-test.vigilnz.com  ← reflected!
 *     Access-Control-Allow-Credentials: true
 *   → CORS misconfiguration finding.
 */
export async function GET(request) {
  const origin = request.headers.get('origin') || '*'

  return new Response(
    JSON.stringify({
      message: 'CORS-vulnerable endpoint',
      data: { userId: 1, apiKey: 'secret-api-key-1234', balance: 9999 },
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // VULNERABLE: reflects attacker origin
        'Access-Control-Allow-Origin': origin,
        // VULNERABLE: allows cookies/auth with any origin
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    }
  )
}

export async function OPTIONS(request) {
  const origin = request.headers.get('origin') || '*'
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  })
}
