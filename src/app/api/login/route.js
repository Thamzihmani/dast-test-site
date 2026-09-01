/**
 * route.js
 * Purpose: Simple login endpoint for api-security FormLogin auth testing (TC-014).
 *          Returns flat { token } response that AuthManager.formLogin() can extract
 *          without a tokenPath. Also used to obtain TOKEN_A/TOKEN_B in TC section 2.3.
 * Author: Thamizhmani
 * Date: 2026-08-07
 *
 * VULNERABILITY: No rate limiting, weak JWT secret — intentional for DAST testing.
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const USERS = {
  alice: { id: 1, username: 'alice', password: 'alice123', role: 'user' },
  bob:   { id: 2, username: 'bob',   password: 'bob123',   role: 'user' },
  admin: { id: 3, username: 'admin', password: 'admin123', role: 'admin' },
}

const JWT_SECRET = process.env.JWT_SECRET || 'secret'

export async function POST(request) {
  let username = ''
  let password = ''

  try {
    const contentType = request.headers.get('content-type') || ''
    if (contentType.includes('application/json')) {
      const body = await request.json()
      username = body.username || ''
      password = body.password || ''
    } else {
      const formData = await request.formData()
      username = formData.get('username') || ''
      password = formData.get('password') || ''
    }
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid request body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const user = USERS[username.toLowerCase()]

  if (!user || user.password !== password) {
    return new Response(
      JSON.stringify({ success: false, error: 'Invalid username or password' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  // Weak secret intentional — JWT vulnerability for scanner testing
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' },
  )

  // Flat top-level { token } — AuthManager.formLogin() extracts this without tokenPath
  return new Response(
    JSON.stringify({ success: true, token, user: { id: user.id, username: user.username, role: user.role } }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
