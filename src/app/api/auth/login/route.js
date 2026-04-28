/**
 * Login Endpoint — tests DAST authentication config
 *
 * DAST AUTHENTICATION CONFIG (type: "form"):
 *   loginUrl:    https://<your-app>/api/auth/login
 *   credentials: { username: "admin", password: "password123" }
 *
 * On success: returns JWT in response body AND sets a session cookie.
 * The DAST scanner captures both and uses them for subsequent requests.
 *
 * VULNERABILITIES:
 *   1. No rate limiting          → brute-force possible
 *   2. No CSRF token             → CSRF on login
 *   3. Weak JWT secret ("secret")→ JWT vulnerability
 *   4. Returns JWT in body       → token leakage risk
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const USERS = {
  admin: { id: 4, username: 'admin', password: 'password123', role: 'admin' },
  user:  { id: 1, username: 'user',  password: 'password123', role: 'user'  },
  alice: { id: 1, username: 'alice', password: 'password123', role: 'user'  },
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
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }

  const user = USERS[username.toLowerCase()]

  if (!user || user.password !== password) {
    // VULNERABLE: no lockout after failed attempts
    return new Response(
      JSON.stringify({ success: false, error: 'Invalid username or password' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    )
  }

  // VULNERABLE: signed with weak secret "secret"
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' }
  )

  // Non-standard nested response schema — requires tokenPath: "data.session.token"
  return new Response(
    JSON.stringify({
      success: true,
      data: {
        session: {
          token,
          expiresIn: 3600,
        },
        user: { id: user.id, username: user.username, role: user.role },
      },
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // No Set-Cookie — token only available in response body via tokenPath
        // Forces scanner to use tokenPath: "data.session.token" to extract Bearer token
      },
    }
  )
}

// GET shows the login form for spider discovery
export async function GET() {
  const html = `<!DOCTYPE html>
<html>
<head><title>Login</title>
<style>body { font-family: monospace; background: #0f0f0f; color: #e0e0e0; padding: 24px; } input, button { display: block; margin: 8px 0; padding: 8px; }</style>
</head>
<body>
  <h1>Login API</h1>
  <p>POST with JSON or form data: { username, password }</p>
  <p>Test credentials: admin/password123 or user/password123</p>
  <!-- Form for spider discovery — no CSRF token -->
  <form method="POST">
    <input name="username" type="text" placeholder="username" />
    <input name="password" type="password" placeholder="password" />
    <button type="submit">Login</button>
  </form>
</body>
</html>`
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  })
}
