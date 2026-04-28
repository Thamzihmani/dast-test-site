/**
 * JWT Vulnerability Test Endpoint
 *
 * VULNERABILITY 1: Accepts JWTs signed with a weak secret ("secret").
 * VULNERABILITY 2: Accepts JWTs with algorithm "none" (no signature verification).
 * DETECTOR:        jwt
 * SCAN PROFILES:   full, owasp-top10, api-only
 *
 * HOW DETECTION WORKS:
 *   DAST crafts tokens with:
 *     1. alg: "none"  — no signature, should be rejected but isn't
 *     2. alg: "HS256" signed with common weak secrets ("secret", "password", "1234")
 *   If the endpoint accepts these → JWT vulnerability finding.
 *
 * NOTE: This endpoint is in robots.txt Disallow list.
 *       Set ignoreRobotsTxt=true to test it via spider discovery.
 *
 * TEST TOKENS:
 *   Weak secret (HS256, secret="secret"):
 *     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.Iv-jMTH8nXXFuDVuMz_5VQMJWj6JJFELrqjJEfp0lnI
 *
 *   Algorithm none:
 *     eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const WEAK_SECRET = process.env.JWT_SECRET || 'secret'

function decodeJwtUnsafe(token) {
  const [headerB64, payloadB64] = token.split('.')
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString())
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
  return { header, payload }
}

export async function GET(request) {
  const authHeader = request.headers.get('authorization') || ''
  const token = authHeader.replace(/^Bearer\s+/i, '') ||
    new URL(request.url).searchParams.get('token')

  if (!token) {
    return new Response(
      JSON.stringify({
        error: 'Provide a JWT via Authorization: Bearer <token> header or ?token= query param',
        examples: {
          weakSecret: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0.Iv-jMTH8nXXFuDVuMz_5VQMJWj6JJFELrqjJEfp0lnI',
          algNone:    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.',
        },
      }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  try {
    // Decode header first to check algorithm
    const { header, payload: rawPayload } = decodeJwtUnsafe(token)

    // VULNERABLE: accepts algorithm "none" — no signature check
    if (header.alg === 'none' || header.alg === 'NONE') {
      return new Response(
        JSON.stringify({
          valid: true,
          method: 'alg:none — accepted without signature verification',
          payload: rawPayload,
          warning: 'VULNERABILITY: alg:none accepted — attacker can forge any payload',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    // VULNERABLE: verifies with weak secret "secret"
    const verified = jwt.verify(token, WEAK_SECRET)
    return new Response(
      JSON.stringify({
        valid: true,
        method: `HS256 verified with weak secret: "${WEAK_SECRET}"`,
        payload: verified,
        warning: 'VULNERABILITY: Weak JWT secret — easily brute-forced',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    return new Response(
      JSON.stringify({ valid: false, error: err.message }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    )
  }
}
