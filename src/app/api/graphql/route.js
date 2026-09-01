/**
 * GraphQL Vulnerability Test Endpoint
 *
 * VULNERABILITY 1: Introspection enabled — exposes full schema to attackers.
 * VULNERABILITY 2: No query depth or complexity limits.
 * VULNERABILITY 3: Sensitive mutations (deleteUser, updateRole) accessible without auth.
 *
 * DETECTOR:      graphql-vulnerabilities
 * DISCOVERY:     Spider finds the POST form on homepage with input named "query".
 *                GraphQLDetector recognises endpoint because URL contains "/api/graphql".
 * DETECTION:     Introspection query returns data.__schema → finding.
 *
 * ENDPOINT:      POST /api/graphql  body: {"query": "{ hello }"}
 */

export const runtime = 'nodejs'

// Mock schema definition (mirrored in MOCK_SCHEMA response below)
const MOCK_SCHEMA = {
  queryType: { name: 'Query' },
  mutationType: { name: 'Mutation' },
  types: [
    {
      name: 'Query',
      kind: 'OBJECT',
      fields: [
        { name: 'hello' },
        { name: 'user' },
        { name: 'users' },
        { name: 'admin' },
      ],
    },
    {
      name: 'Mutation',
      kind: 'OBJECT',
      fields: [
        { name: 'createUser' },
        { name: 'deleteUser' },
        { name: 'updateRole' },
      ],
    },
    { name: 'User',  kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'name' }, { name: 'email' }, { name: 'role' }] },
    { name: 'Admin', kind: 'OBJECT', fields: [{ name: 'secret' }, { name: 'config' }] },
  ],
}

export async function POST(request) {
  let body = {}
  try {
    body = await request.json()
  } catch {
    return Response.json({ errors: [{ message: 'Invalid JSON body' }] }, { status: 400 })
  }

  const query = String(body.query || '')

  // VULNERABLE: introspection always enabled — exposes schema to anyone
  if (query.includes('__schema') || query.includes('__type')) {
    return Response.json({ data: { __schema: MOCK_SCHEMA } })
  }

  // VULNERABLE: sensitive mutations accessible without authentication
  if (query.includes('deleteUser') || query.includes('updateRole') || query.includes('createUser')) {
    return Response.json({ data: { result: true, affected: 1 } })
  }

  // Default data response
  return Response.json({
    data: {
      hello: 'World',
      user: { id: 1, name: 'Test User', email: 'test@example.com', role: 'user' },
    },
  })
}

export async function GET() {
  return new Response('GraphQL endpoint — POST {"query": "{ hello }"}', { status: 200 })
}
