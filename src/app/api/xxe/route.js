/**
 * XXE (XML External Entity) Test Endpoint
 *
 * VULNERABILITY: Simulates a parser that resolves SYSTEM entity references.
 *   When an XXE payload references /etc/passwd or win.ini, the endpoint returns
 *   the simulated file contents — as a vulnerable real parser would.
 *
 * DETECTOR:      xxe
 * DISCOVERY:     Spider finds the POST form on homepage with input named "xml".
 *                XXEDetector._supportsXml() passes because: method=POST + param named "xml".
 * DETECTION:     Response contains sensitive file patterns:
 *                "root:x:0:0:" (/etc/passwd) or "[fonts]\n[extensions]" (win.ini)
 *
 * ENDPOINT:      POST /api/xxe  body: xml=<data>test</data>
 */

export const runtime = 'nodejs'

export async function POST(request) {
  let body = ''
  try {
    body = await request.text()
  } catch {
    return Response.json({ error: 'Could not read body' }, { status: 400 })
  }

  // VULNERABLE: simulates an XXE-vulnerable XML parser resolving SYSTEM entities

  if (body.includes('SYSTEM') && body.includes('/etc/passwd')) {
    return new Response(
      'root:x:0:0:root:/root:/bin/bash\n' +
      'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
      'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n' +
      'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
      { status: 200, headers: { 'Content-Type': 'text/plain' } }
    )
  }

  if (body.includes('SYSTEM') && body.includes('win.ini')) {
    return new Response(
      '[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]',
      { status: 200, headers: { 'Content-Type': 'text/plain' } }
    )
  }

  return Response.json({ parsed: true, length: body.length })
}
