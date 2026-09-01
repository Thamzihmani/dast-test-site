/**
 * IDOR (Insecure Direct Object Reference) Test Endpoint
 *
 * VULNERABILITY: Returns any user's full record (including secret) by ID,
 *                without checking if the requester owns that ID.
 * DETECTOR:      idor
 * SCAN PROFILES: full, owasp-top10, api-only
 *
 * HOW DETECTION WORKS:
 *   DAST requests /api/idor?id=1 as a baseline, then tries id=2, id=3.
 *   All return different users' private data without auth check → IDOR finding.
 *
 * AUTHENTICATION TEST:
 *   Without auth: all IDs accessible → IDOR confirmed
 *   With auth (Bearer token for user 1): id=1 OK, but id=2 still returns Bob's data
 *   → Proves scanner found the vulnerability even in an authenticated context
 *
 * NOTE: This path is listed in robots.txt as Disallow: /api/idor
 *   → With ignoreRobotsTxt=false: spider skips this, active scan won't test it
 *   → With ignoreRobotsTxt=true:  spider finds it, active scan tests it → IDOR found
 */

const USERS = [
  { id: 1, name: 'Alice',   email: 'alice@example.com',  role: 'user',  secret: 'alice-private-token-abc123',  balance: 1500.00 },
  { id: 2, name: 'Bob',     email: 'bob@example.com',    role: 'user',  secret: 'bob-private-token-def456',    balance: 3200.50 },
  { id: 3, name: 'Charlie', email: 'charlie@example.com',role: 'user',  secret: 'charlie-private-token-ghi789',balance: 750.00  },
  { id: 4, name: 'Admin',   email: 'admin@example.com',  role: 'admin', secret: 'admin-private-token-xyz000',  balance: 99999.00},
]

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const id = searchParams.get('id')

  if (!id) {
    return new Response(
      JSON.stringify({ error: 'id parameter is required', example: '/api/idor?id=1' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  const numId = parseInt(id, 10)
  if (isNaN(numId)) {
    return new Response(
      JSON.stringify({ error: 'id must be a number' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  const user = USERS.find((u) => u.id === numId)

  if (!user) {
    return new Response(
      JSON.stringify({ error: 'User not found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // VULNERABLE: no auth check — returns any user's private data including `secret` and `balance`
  return new Response(
    JSON.stringify({ user }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  )
}
