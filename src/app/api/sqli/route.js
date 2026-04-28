/**
 * SQL Injection Test Endpoint
 *
 * VULNERABILITY: Unsanitised `id` parameter used directly in a simulated SQL query.
 * DETECTOR:      sql-injection
 * SCAN PROFILES: full, owasp-top10, quick
 *
 * HOW DETECTION WORKS (differential analysis):
 *   Normal:    GET /api/sqli?id=1        → 200, returns user row
 *   Boolean:   GET /api/sqli?id=1 OR 1=1 → 200, returns ALL users (different response length)
 *   Error:     GET /api/sqli?id=1'       → 500, returns SQL error message
 *   Union:     GET /api/sqli?id=-1 UNION SELECT → different response
 *
 * The DAST detector injects SQL payloads and compares responses to baseline.
 * A different body length or SQL error string = SQLi finding.
 */

// Simulated in-memory user table
const USERS = [
  { id: 1, name: 'Alice',  email: 'alice@example.com',  role: 'user',  secret: 'alice-token-abc' },
  { id: 2, name: 'Bob',    email: 'bob@example.com',    role: 'user',  secret: 'bob-token-def' },
  { id: 3, name: 'Admin',  email: 'admin@example.com',  role: 'admin', secret: 'admin-token-xyz' },
]

// SQL keywords/characters that indicate injection attempt
const SQL_INJECTION_PATTERNS = [
  /'/,
  /--/,
  /;/,
  /\bOR\b/i,
  /\bAND\b/i,
  /\bUNION\b/i,
  /\bSELECT\b/i,
  /\bDROP\b/i,
  /\bINSERT\b/i,
  /\bDELETE\b/i,
  /\bUPDATE\b/i,
  /\bSLEEP\b/i,
  /\bWAITFOR\b/i,
]

function hasSqlInjection(input) {
  return SQL_INJECTION_PATTERNS.some((p) => p.test(input))
}

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const id = searchParams.get('id') || ''

  // Simulate SQL error when injection characters are present
  if (hasSqlInjection(id)) {
    return new Response(
      JSON.stringify({
        error: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + id + "' at line 1",
        query: `SELECT * FROM users WHERE id = '${id}'`,
        sqlState: '42000',
        errno: 1064,
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }

  const numId = parseInt(id, 10)

  if (isNaN(numId)) {
    return new Response(
      JSON.stringify({ error: 'id must be a number', query: `SELECT * FROM users WHERE id = '${id}'` }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  const user = USERS.find((u) => u.id === numId)

  if (!user) {
    return new Response(
      JSON.stringify({ error: 'User not found', query: `SELECT * FROM users WHERE id = ${numId}` }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    )
  }

  return new Response(
    JSON.stringify({
      // Intentionally returns secret field — no column filtering
      user,
      query: `SELECT * FROM users WHERE id = ${numId}`,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  )
}
