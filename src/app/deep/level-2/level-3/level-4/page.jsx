export default function DeepLevel4() {
  return (
    <div>
      <h1>Deep — Level 4 ✓</h1>
      <p style={{ color: '#4fc3f7' }}>
        If the DAST scanner discovered this page, <code>spiderMaxDepth=4</code> or higher is working correctly.
      </p>
      <p style={{ color: '#aaa' }}>
        These endpoints are only discoverable at depth 4. They will NOT appear in scans with spiderMaxDepth &lt; 4.
      </p>
      {/* Unique URL-param link — only appears in testableEndpoints when spider reaches depth 4 */}
      <a href="/api/xss?q=depth4-marker">XSS probe (depth-4 only)</a>
      {/* Unique form — only found with deep enough spider */}
      <form action="/api/sqli" method="GET">
        <input name="depth4_id" defaultValue="4" style={{ width: '200px', marginRight: '8px' }} />
        <button type="submit">Deep SQLi Test</button>
      </form>
    </div>
  )
}
