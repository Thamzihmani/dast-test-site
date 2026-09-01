/**
 * route.js
 * Purpose: External data sync endpoint — deliberately vulnerable to unsafe consumption (TC-050).
 *          VULNERABILITY: API10 Unsafe Consumption — accepts external data from any source
 *          without input validation (no size limit, no content sanitization, no schema check).
 *          Injection payloads (XSS, template injection, binary) and oversized bodies are
 *          all accepted and reflected back in the response.
 * Author: Thamizhmani
 * Date: 2026-08-07
 */

export const runtime = 'nodejs'

export async function POST(request) {
  let body = {}
  try {
    body = await request.json()
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  // VULNERABILITY: no size check, no content sanitization, no injection filtering.
  // External data from body.data / body.content / body.payload is reflected directly.
  const syncedData = body.data ?? body.content ?? body.payload ?? body.message ?? body

  return new Response(
    JSON.stringify({
      success: true,
      synced: true,
      receivedAt: new Date().toISOString(),
      source: body.source ?? body.provider ?? body.integration ?? 'external',
      data: syncedData,
      recordCount: Array.isArray(syncedData) ? syncedData.length : 1,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}
