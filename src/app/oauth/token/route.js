/**
 * route.js
 * Purpose: Mock OAuth2 token endpoint for api-security OAuth2 auth testing (TC-011).
 *          Handles client_credentials grant. AuthManager.oauth2ClientCredentials()
 *          sends form-urlencoded body and expects { access_token } in response.
 * Author: Thamizhmani
 * Date: 2026-08-07
 *
 * Accepts any client_id / client_secret pair — deliberately permissive for testing.
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'secret'

export async function POST(request) {
  let grantType = ''
  let clientId = ''
  let clientSecret = ''
  let scope = ''

  try {
    const contentType = request.headers.get('content-type') || ''
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const text = await request.text()
      const params = new URLSearchParams(text)
      grantType = params.get('grant_type') || ''
      clientId = params.get('client_id') || ''
      clientSecret = params.get('client_secret') || ''
      scope = params.get('scope') || ''
    } else {
      const body = await request.json()
      grantType = body.grant_type || ''
      clientId = body.client_id || ''
      clientSecret = body.client_secret || ''
      scope = body.scope || ''
    }
  } catch {
    return new Response(
      JSON.stringify({ error: 'invalid_request', error_description: 'Unable to parse request body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  if (grantType !== 'client_credentials') {
    return new Response(
      JSON.stringify({ error: 'unsupported_grant_type', error_description: 'Only client_credentials is supported' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  if (!clientId) {
    return new Response(
      JSON.stringify({ error: 'invalid_client', error_description: 'client_id is required' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const accessToken = jwt.sign(
    { sub: clientId, scope: scope || 'read write', grant_type: 'client_credentials' },
    JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' },
  )

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: scope || 'read write',
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
