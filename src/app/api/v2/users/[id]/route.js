/**
 * route.js
 * Purpose: Current versioned endpoint — /api/v2/users/{id}. Needed alongside
 *          /api/v1/users/{id} so the DEPRECATED_VERSION detector can compare
 *          v1 vs v2 and flag v1 as deprecated (TC-062).
 * Author: Thamizhmani
 * Date: 2026-08-07
 *
 * v2 differences from v1: `secret` field removed, pagination metadata added.
 */

const USERS = [
  { id: 1, name: 'Alice', email: 'alice@example.com', role: 'user' },
  { id: 2, name: 'Bob',   email: 'bob@example.com',   role: 'user' },
  { id: 3, name: 'Admin', email: 'admin@example.com', role: 'admin' },
]

export async function GET(request, { params }) {
  const id = parseInt(params.id, 10)

  if (isNaN(id)) {
    return new Response(
      JSON.stringify({ error: 'Invalid user ID', apiVersion: 'v2' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const user = USERS.find((u) => u.id === id)

  if (!user) {
    return new Response(
      JSON.stringify({ error: 'User not found', apiVersion: 'v2' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } },
    )
  }

  return new Response(
    JSON.stringify({ user, apiVersion: 'v2' }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
