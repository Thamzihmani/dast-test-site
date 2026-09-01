/**
 * DOM-Based XSS Test Endpoint
 *
 * VULNERABILITY: Inline script reads from location.search (source) and
 *   writes to innerHTML (sink) without sanitization.
 *
 * DETECTOR:      dom-xss
 * DETECTION:     Static sink+source analysis — script block contains both
 *                location.search and innerHTML in the same inline script.
 *
 * ENDPOINT:      GET /api/dom-xss?q=hello
 */

export const runtime = 'nodejs'

export async function GET() {
  const html = `<!DOCTYPE html>
<html>
<head><title>DOM XSS Test</title></head>
<body>
  <h1>Search Results</h1>
  <div id="output"></div>
  <script>
    // VULNERABILITY: user input from URL directly assigned to innerHTML — no sanitization
    var params = new URLSearchParams(location.search);
    var query = params.get('q') || 'no query provided';
    document.getElementById('output').innerHTML = query;
  </script>
</body>
</html>`

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html' },
  })
}
