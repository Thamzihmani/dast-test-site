/**
 * No Rate Limiting Test Endpoint
 *
 * VULNERABILITY: Sensitive endpoint with no rate limiting — accepts unlimited requests.
 * DETECTOR:      rate-limiting
 * SCAN PROFILES: full, owasp-top10
 *
 * HOW DETECTION WORKS:
 *   DAST sends a burst of requests (e.g., 50 rapid requests).
 *   If all return 200 (no 429 Too Many Requests) → rate-limiting finding.
 *
 * SEE ALSO: /api/auth/login also has no rate limiting (brute-force risk).
 */

// In-memory hit counter (resets on cold start — fine for testing)
let hitCount = 0

export async function GET(request) {
  hitCount++
  const { searchParams } = new URL(request.url)
  const username = searchParams.get('username') || 'user'
  const password = searchParams.get('password') || ''

  // VULNERABLE: no rate limiting, no lockout, no CAPTCHA
  // A real endpoint would check: if (hitCount > 10 per IP per minute) return 429
  return new Response(
    JSON.stringify({
      success: false,
      message: 'Invalid credentials',
      // Leaks the hit count — shows no rate limiting is applied
      totalAttempts: hitCount,
      warning: 'VULNERABILITY: No rate limiting — this endpoint accepts unlimited login attempts (brute-force)',
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // ✗ No Retry-After header
        // ✗ No X-RateLimit-Remaining header
      },
    }
  )
}
