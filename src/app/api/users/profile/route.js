/**
 * route.js
 * Purpose: User profile update — deliberately vulnerable to mass assignment (TC-047).
 *          VULNERABILITY: API6 Mass Assignment — PUT body is spread directly into the
 *          response without filtering. Privilege fields (role, isAdmin, permissions) sent
 *          by the caller are reflected back, confirming they were accepted as-is.
 * Author: Thamizhmani
 * Date: 2026-08-07
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'secret'

export async function PUT(request) {
  const authHeader = request.headers.get('authorization') || ''
  const match = authHeader.match(/^[Bb]earer\s+(.+)$/)

  if (!match) {
    return new Response(
      JSON.stringify({ error: 'Authentication required' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  let decoded
  try {
    decoded = jwt.verify(match[1], JWT_SECRET)
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid or expired token' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  let body = {}
  try {
    body = await request.json()
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  // VULNERABILITY: spreads all submitted fields into the response without filtering.
  // Should blocklist: role, isAdmin, is_admin, admin, permissions, balance, credit, verified.
  const updated = {
    id: decoded.userId,
    username: decoded.username,
    ...body,
    updatedAt: new Date().toISOString(),
  }

  return new Response(
    JSON.stringify({ success: true, user: updated }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

// GET for endpoint discovery by the scanner crawler
export async function GET() {
  return new Response(
    JSON.stringify({ description: 'PUT /api/users/profile — update your profile. Accepted fields: name, bio, avatar.' }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
