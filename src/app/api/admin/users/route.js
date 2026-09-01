/**
 * route.js
 * Purpose: Admin user list endpoint — deliberately missing role authorisation (TC-045).
 *          VULNERABILITY: API5 Function Level Authorization Failure — the endpoint checks
 *          that the caller is authenticated but does NOT verify they hold the admin role.
 *          Any valid JWT (regular user) gets the full user list.
 * Author: Thamizhmani
 * Date: 2026-08-07
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const USERS = [
  { id: 1, username: 'alice', email: 'alice@example.com', role: 'user',  lastLogin: '2026-08-06T10:00:00Z' },
  { id: 2, username: 'bob',   email: 'bob@example.com',   role: 'user',  lastLogin: '2026-08-05T09:00:00Z' },
  { id: 4, username: 'admin', email: 'admin@example.com', role: 'admin', lastLogin: '2026-08-07T08:00:00Z' },
]

const JWT_SECRET = process.env.JWT_SECRET || 'secret'

export async function GET(request) {
  const authHeader = request.headers.get('authorization') || ''
  const match = authHeader.match(/^[Bb]earer\s+(.+)$/)

  if (!match) {
    return new Response(
      JSON.stringify({ error: 'Authentication required' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  try {
    jwt.verify(match[1], JWT_SECRET)
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid or expired token' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  // VULNERABILITY: missing `if (decoded.role !== 'admin') return 403` check
  return new Response(
    JSON.stringify({ success: true, users: USERS, total: USERS.length }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
