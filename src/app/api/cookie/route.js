/**
 * Insecure Cookie Test Endpoint
 *
 * VULNERABILITY: Session cookie set with httpOnly: false and secure: false.
 *   httpOnly: false — cookie readable by JavaScript (enables XSS session theft).
 *   secure: false  — cookie transmitted over plain HTTP (enables interception).
 *
 * DETECTOR:      insecure-cookie-no-httponly, insecure-cookie-no-secure
 * DETECTION:     Pattern match on res.cookie() call with explicit insecure flags.
 *
 * NOTE: This uses Express res.cookie() style for SAST pattern coverage.
 *   The Next.js runtime path below sets cookies via Response headers (secure).
 *   The Express-style helper function below is intentionally vulnerable for SAST.
 *
 * ENDPOINT:      GET /api/cookie?user=test
 */

export const runtime = 'nodejs'

// VULNERABLE helper — Express-style cookie setter with insecure flags
// SAST should flag both httpOnly: false and secure: false here.
function setSessionCookie(res, token) {
  res.cookie('session', token, { httpOnly: false, secure: false, sameSite: 'lax' })
}

export async function GET(request) {
  const user = new URL(request.url).searchParams.get('user') || 'anonymous'
  const token = Buffer.from(user).toString('base64')

  // Next.js App Router path — set cookie via Response header (safe baseline)
  const response = Response.json({ status: 'ok', user })
  response.headers.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`)
  return response
}
