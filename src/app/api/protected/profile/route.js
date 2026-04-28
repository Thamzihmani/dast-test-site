/**
 * Protected Profile Endpoint — tests all 5 DAST authentication types
 *
 * Accepts any one of the following auth schemes:
 *
 *   type: "bearer"  → Authorization: Bearer <jwt>
 *                     credentials: { token: "<jwt>" }
 *
 *   type: "basic"   → Authorization: Basic <base64(admin:password123)>
 *                     credentials: { username: "admin", password: "password123" }
 *
 *   type: "cookie"  → Cookie: api-key=vigilnz-secret
 *                     credentials: { cookies: "api-key=vigilnz-secret" }
 *
 *   type: "header"  → X-API-Key: vigilnz-secret
 *                     credentials: { headers: { "X-API-Key": "vigilnz-secret" } }
 *
 *   type: "form"    → handled via session cookie from login (tokenPath: "data.session.token")
 *                     credentials: { username, password, tokenPath: "data.session.token" }
 *
 * VULNERABILITY: IDOR — returns any user's private data by id param (no ownership check)
 * This finding only appears in authenticated scans.
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'secret'

// Valid static credentials for cookie and header auth types
const VALID_API_KEY   = 'vigilnz-secret'
const VALID_API_COOKIE = 'vigilnz-secret'

// Valid basic auth credentials
const BASIC_USERS = {
  admin: 'password123',
  user:  'password123',
}

const USERS = [
  { id: 1, username: 'alice', email: 'alice@example.com', ssn: '123-45-6789', creditCard: '4111-1111-1111-1111' },
  { id: 2, username: 'bob',   email: 'bob@example.com',   ssn: '987-65-4321', creditCard: '4222-2222-2222-2222' },
  { id: 3, username: 'carol', email: 'carol@example.com', ssn: '555-55-5555', creditCard: '4333-3333-3333-3333' },
  { id: 4, username: 'admin', email: 'admin@example.com', ssn: '000-00-0000', creditCard: '4000-0000-0000-0000' },
]

function isAuthenticated(request) {
  const authHeader = request.headers.get('authorization') || ''

  // Bearer JWT
  const bearerMatch = authHeader.match(/^[Bb]earer\s+(.+)$/)
  if (bearerMatch) {
    try {
      jwt.verify(bearerMatch[1], JWT_SECRET)
      return true
    } catch {
      return false
    }
  }

  // Basic auth
  const basicMatch = authHeader.match(/^[Bb]asic\s+(.+)$/)
  if (basicMatch) {
    try {
      const decoded = Buffer.from(basicMatch[1], 'base64').toString('utf8')
      const [username, password] = decoded.split(':')
      return BASIC_USERS[username] === password
    } catch {
      return false
    }
  }

  // Cookie auth — api-key=vigilnz-secret
  const cookieHeader = request.headers.get('cookie') || ''
  const cookieMatch = cookieHeader.match(/api-key=([^;]+)/)
  if (cookieMatch && cookieMatch[1] === VALID_API_COOKIE) {
    return true
  }

  // Custom header auth — X-API-Key: vigilnz-secret
  const apiKey = request.headers.get('x-api-key') || ''
  if (apiKey === VALID_API_KEY) {
    return true
  }

  return false
}

export async function GET(request) {
  if (!isAuthenticated(request)) {
    return new Response(
      JSON.stringify({
        error: 'Unauthorized',
        acceptedAuthTypes: ['bearer', 'basic', 'cookie (api-key=vigilnz-secret)', 'header (X-API-Key: vigilnz-secret)'],
      }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // VULNERABLE: returns any user's data by id — no ownership check (IDOR)
  const { searchParams } = new URL(request.url)
  const id = parseInt(searchParams.get('id') || '1')
  const user = USERS.find(u => u.id === id)

  if (!user) {
    return new Response(
      JSON.stringify({ error: 'User not found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    )
  }

  return new Response(
    JSON.stringify({ user }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  )
}
