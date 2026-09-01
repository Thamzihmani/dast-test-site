/**
 * route.js
 * Purpose: Deprecated versioned endpoint for api-security deprecated-API detection (TC-062).
 *          This is /api/v1/users/{id} — an older version of /api/users/{id} that has
 *          been superseded but left live. The DEPRECATED_VERSION detector flags endpoints
 *          matching /v1/ or /v2/ path patterns that still return HTTP 200.
 * Author: Thamizhmani
 * Date: 2026-08-07
 *
 * VULNERABILITY: Old API version still accessible — leaks internal user data including
 *                the deprecated `secret` field that was removed from v2.
 */

const USERS = [
  { id: 1, name: 'Alice', email: 'alice@example.com', role: 'user',  secret: 'alice-token-abc' },
  { id: 2, name: 'Bob',   email: 'bob@example.com',   role: 'user',  secret: 'bob-token-def' },
  { id: 3, name: 'Admin', email: 'admin@example.com', role: 'admin', secret: 'admin-token-xyz' },
]

export async function GET(request, { params }) {
  const id = parseInt(params.id, 10)

  if (isNaN(id)) {
    return new Response(
      JSON.stringify({ error: 'Invalid user ID', apiVersion: 'v1', deprecated: true }),
      { status: 400, headers: { 'Content-Type': 'application/json', 'X-API-Deprecated': 'true', 'X-API-Successor': '/api/v2/users/{id}' } },
    )
  }

  const user = USERS.find((u) => u.id === id)

  if (!user) {
    return new Response(
      JSON.stringify({ error: 'User not found', apiVersion: 'v1', deprecated: true }),
      { status: 404, headers: { 'Content-Type': 'application/json', 'X-API-Deprecated': 'true' } },
    )
  }

  // VULNERABILITY: v1 leaks the `secret` field — removed in v2
  return new Response(
    JSON.stringify({ user, apiVersion: 'v1', deprecated: true }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // Deprecated header signals to scanners this endpoint is old
        'X-API-Deprecated': 'true',
        'X-API-Successor': '/api/v2/users/{id}',
        'Deprecation': 'true',
        'Sunset': '2025-12-31',
      },
    },
  )
}
