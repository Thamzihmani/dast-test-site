/**
 * Custom Login Endpoint — tests DAST tokenPath config
 *
 * Returns token in a non-standard nested schema:
 *   { data: { session: { token: "<jwt>" } } }
 *
 * DAST AUTHENTICATION CONFIG (type: "form" with tokenPath):
 *   loginUrl:    http://<host>/api/auth/login-custom
 *   credentials: {
 *     username: "admin",
 *     password: "password123",
 *     tokenPath: "data.session.token"
 *   }
 */

export const runtime = 'nodejs'

import jwt from 'jsonwebtoken'

const USERS = {
  admin: { id: 4, username: 'admin', password: 'password123', role: 'admin' },
  user:  { id: 1, username: 'user',  password: 'password123', role: 'user'  },
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
    return new Response(
      JSON.stringify({ success: false, error: 'Invalid credentials' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    )
  }

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
        'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax`,
      },
    }
  )
}
