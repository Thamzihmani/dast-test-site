/**
 * Missing Security Headers Test Endpoint
 *
 * VULNERABILITY: Response intentionally omits all recommended security headers.
 * DETECTOR:      security-headers
 * SCAN PROFILES: full, owasp-top10, quick, api-only
 *
 * MISSING HEADERS (each one triggers a separate sub-finding):
 *   - Content-Security-Policy     → XSS attack surface
 *   - X-Frame-Options             → Clickjacking
 *   - X-Content-Type-Options      → MIME sniffing
 *   - Strict-Transport-Security   → Downgrade attacks
 *   - Referrer-Policy             → Data leakage in Referer header
 *   - Permissions-Policy          → Browser feature abuse
 *
 * HOW TO TEST:
 *   Run scan with scanProfile=quick — security-headers is in the quick profile, should fire.
 *   Run scan with scanProfile=api-only — also fires (in api-only profile).
 */
export async function GET() {
  return new Response(
    JSON.stringify({
      message: 'This response intentionally omits all security headers.',
      data: { id: 1, name: 'test-resource', value: 'sensitive-data' },
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // ✗ No Content-Security-Policy
        // ✗ No X-Frame-Options
        // ✗ No X-Content-Type-Options
        // ✗ No Strict-Transport-Security
        // ✗ No Referrer-Policy
        // ✗ No Permissions-Policy
      },
    }
  )
}
