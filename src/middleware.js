/**
 * Fake WAF Middleware
 *
 * PURPOSE: Tests the `fragmentationEnabled` advanced config.
 *
 * HOW IT WORKS:
 *   - Enabled via ENABLE_FAKE_WAF=true in .env
 *   - Blocks requests whose URL contains obvious XSS patterns (whole-string match)
 *   - When fragmentationEnabled=false in DAST: payloads arrive as <script>alert(1) → BLOCKED
 *   - When fragmentationEnabled=true in DAST:  payloads are split across chunks  → NOT BLOCKED
 *     because the WAF only sees individual chunks, not the reconstructed string.
 *
 * TESTING:
 *   1. Set ENABLE_FAKE_WAF=true
 *   2. Run DAST scan with fragmentationEnabled=false → XSS endpoint returns 403, 0 findings
 *   3. Run DAST scan with fragmentationEnabled=true  → XSS endpoint returns 200, findings appear
 */

import { NextResponse } from 'next/server'

// Patterns the fake WAF blocks.
//
// DESIGN: Chosen so that the scanner's payload fragmentation (inserting /**/ at the
// midpoint of the payload) actually bypasses them.
//
// PayloadGenerator splits e.g. "<script>alert(1)</script>" at the midpoint:
//   fragment 1: "<script>alert"   fragment 2: "(1)</script>"
//   joined:     "<script>alert/**/(1)</script>"
//
// Key bypass: /alert\s*\(/ requires no non-whitespace between "alert" and "(".
//   - Normal:      alert(      → matches → BLOCKED
//   - Fragmented:  alert/**/( → /**/ is not \s*, so it does NOT match → BYPASSED
//
// Note: <script> alone is intentionally NOT in the list — the midpoint split
// preserves it intact; only alert() is reliably broken by the mid-payload split.
const BLOCKED_PATTERNS = [
  /alert\s*\(/i,           // blocks alert(   — fragmentation: "alert(" → "alert/**/(""
  /onerror\s*=\s*alert/i,  // blocks onerror=alert
  /onload\s*=\s*alert/i,   // blocks onload=alert
]

export function middleware(request) {
  const { pathname } = request.nextUrl

  // Gate /protected page and /api/protected/* — accept any supported auth scheme
  // Route handler does full credential verification
  if (pathname.startsWith('/protected') || pathname.startsWith('/api/protected/')) {
    const authHeader = request.headers.get('authorization') || ''
    const cookieHeader = request.headers.get('cookie') || ''
    const apiKey = request.headers.get('x-api-key') || ''

    const hasAuth =
      authHeader.toLowerCase().startsWith('bearer ') ||   // bearer / form+tokenPath
      authHeader.toLowerCase().startsWith('basic ')  ||   // basic
      cookieHeader.includes('api-key=')              ||   // cookie
      apiKey.length > 0                                   // header

    if (!hasAuth) {
      if (pathname.startsWith('/api/')) {
        return new NextResponse(
          JSON.stringify({ error: 'Unauthorized' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      }
      const loginUrl = request.nextUrl.clone()
      loginUrl.pathname = '/login'
      return NextResponse.redirect(loginUrl)
    }
  }

  // WAF is off by default — set NEXT_PUBLIC_ENABLE_FAKE_WAF=true in .env to enable
  if (process.env.NEXT_PUBLIC_ENABLE_FAKE_WAF !== 'true') {
    return NextResponse.next()
  }

  let urlString
  try {
    urlString = decodeURIComponent(request.nextUrl.toString())
  } catch {
    urlString = request.nextUrl.toString()
  }

  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(urlString)) {
      return new NextResponse(
        JSON.stringify({
          error: 'WAF: Request blocked by security rule',
          rule: pattern.toString(),
          tip: 'Try running the scan with fragmentationEnabled=true to bypass this WAF.',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }
  }

  return NextResponse.next()
}

export const config = {
  // Apply to protected routes and API routes (for WAF + auth gating)
  matcher: ['/api/:path*', '/protected', '/protected/:path*'],
}
