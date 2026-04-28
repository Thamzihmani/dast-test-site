/**
 * Logout endpoint — clears the session cookie.
 * The spider avoids logout URLs by default (skipLogoutUrls config in Spider.js).
 * This endpoint is safe and just clears the cookie.
 */
export async function POST() {
  return new Response(
    JSON.stringify({ success: true, message: 'Logged out' }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly',
      },
    }
  )
}

export async function GET() {
  return new Response(
    JSON.stringify({ message: 'POST to this endpoint to logout' }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  )
}
