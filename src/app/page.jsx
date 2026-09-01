import './globals.css'

/**
 * Homepage — Spider entry point
 *
 * DAST ROLE: This page is the root URL the spider starts from.
 * It links to all test pages and contains forms pointing to vulnerable endpoints,
 * so the spider can discover the full attack surface.
 */

const ENDPOINTS = [
  {
    category: 'Injection',
    items: [
      { href: '/api/sqli?id=1',          label: 'SQL Injection',      badge: 'high',     desc: 'Unsanitised query param reflected in fake SQL query' },
      { href: '/api/xss?q=hello',         label: 'Reflected XSS',     badge: 'high',     desc: 'Input reflected in HTML without escaping' },
      { href: '/api/path-traversal?file=info.txt', label: 'Path Traversal', badge: 'high', desc: 'File path read without sanitisation' },
    ],
  },
  {
    category: 'Broken Access Control',
    items: [
      { href: '/api/idor?id=1',           label: 'IDOR',               badge: 'high',     desc: 'Returns any user by ID without ownership check' },
      { href: '/admin',                   label: 'Admin Panel',        badge: 'medium',   desc: 'Disallowed in robots.txt — tests ignoreRobotsTxt' },
      { href: '/api/csrf',                label: 'CSRF',               badge: 'medium',   desc: 'State-changing POST with no CSRF token' },
    ],
  },
  {
    category: 'Security Misconfiguration',
    items: [
      { href: '/api/headers',             label: 'Missing Headers',    badge: 'medium',   desc: 'Response has no X-Frame-Options, CSP, HSTS, etc.' },
      { href: '/api/cors',                label: 'CORS Misconfigured', badge: 'medium',   desc: 'Reflects Origin header with credentials: true' },
      { href: '/api/clickjacking',        label: 'Clickjacking',       badge: 'medium',   desc: 'Page served without X-Frame-Options' },
    ],
  },
  {
    category: 'Authentication',
    items: [
      { href: '/api/jwt',                 label: 'JWT Vulnerability',  badge: 'high',     desc: 'Accepts weak secret "secret" and alg:none tokens' },
      { href: '/api/auth/login',          label: 'Login (no rate limit)', badge: 'medium', desc: 'No brute-force protection on login endpoint' },
      { href: '/api/rate-limit',          label: 'No Rate Limiting',   badge: 'low',      desc: 'Sensitive endpoint accepts unlimited requests' },
    ],
  },
  {
    category: 'Server-Side',
    items: [
      { href: '/api/ssrf?url=https://example.com', label: 'SSRF', badge: 'critical', desc: 'Server fetches any URL supplied by the client' },
      { href: '/api/redirect?url=https://example.com', label: 'Open Redirect', badge: 'medium', desc: '302 redirect to attacker-controlled URL' },
      { href: '/api/cmd?input=hello', label: 'Command Injection', badge: 'critical', desc: 'User input injected directly into execSync()' },
    ],
  },
  {
    category: 'Client-Side',
    items: [
      { href: '/api/dom-xss?q=hello', label: 'DOM-Based XSS', badge: 'high', desc: 'location.search reflected into innerHTML without sanitisation' },
    ],
  },
  {
    category: 'Data Formats',
    items: [
      { href: '/api/graphql', label: 'GraphQL (introspection on)', badge: 'medium', desc: 'GraphQL endpoint with introspection and no auth on mutations' },
    ],
  },
]

const BADGE_COLORS = {
  critical: '#7f1d1d',
  high:     '#7c2d12',
  medium:   '#713f12',
  low:      '#1e3a5f',
}

export default function HomePage() {
  return (
    <div>
      <h1>DAST Test App</h1>
      <p style={{ color: '#ff9800', marginBottom: '24px' }}>
        ⚠ This application is <strong>intentionally vulnerable</strong>. Deploy only in isolated environments.
        Built for testing the <strong>Vigilnz DAST scanner</strong>.
      </p>

      {/* Spider discovers these forms and their action endpoints */}
      <div className="card">
        <h2>Search (XSS test)</h2>
        <form action="/api/xss" method="GET">
          <input name="q" defaultValue="hello world" style={{ width: '300px', marginRight: '8px' }} />
          <button type="submit">Search</button>
        </form>
      </div>

      <div className="card">
        <h2>User Lookup (SQLi test)</h2>
        <form action="/api/sqli" method="GET">
          <input name="id" defaultValue="1" style={{ width: '200px', marginRight: '8px' }} />
          <button type="submit">Lookup</button>
        </form>
      </div>

      <div className="card">
        <h2>Profile (IDOR test)</h2>
        <form action="/api/idor" method="GET">
          <input name="id" defaultValue="1" style={{ width: '200px', marginRight: '8px' }} />
          <button type="submit">View Profile</button>
        </form>
      </div>

      <div className="card">
        <h2>File Viewer (Path Traversal test)</h2>
        <form action="/api/path-traversal" method="GET">
          <input name="file" defaultValue="readme.txt" style={{ width: '300px', marginRight: '8px' }} />
          <button type="submit">Read File</button>
        </form>
      </div>

      {/* CSRF test form — POST without token */}
      <div className="card">
        <h2>Update Email (CSRF test)</h2>
        <form action="/api/csrf" method="POST">
          <input name="email" defaultValue="new@example.com" style={{ width: '300px', marginRight: '8px' }} />
          <button type="submit">Update</button>
        </form>
      </div>

      {/* XXE test form — POST form with input named "xml" so XXE detector discovers it */}
      <div className="card">
        <h2>XML Parser (XXE test)</h2>
        <form action="/api/xxe" method="POST">
          <input name="xml" defaultValue="&lt;data&gt;hello&lt;/data&gt;" style={{ width: '300px', marginRight: '8px' }} />
          <button type="submit">Parse XML</button>
        </form>
      </div>

      {/* GraphQL test form — POST form so spider discovers /api/graphql endpoint */}
      <div className="card">
        <h2>GraphQL Query (GraphQL test)</h2>
        <form action="/api/graphql" method="POST">
          <input name="query" defaultValue="{hello}" style={{ width: '300px', marginRight: '8px' }} />
          <button type="submit">Run Query</button>
        </form>
      </div>

      {/* Endpoint reference table */}
      <h2 style={{ marginTop: '32px' }}>All Vulnerable Endpoints</h2>
      {ENDPOINTS.map((group) => (
        <div key={group.category} className="card">
          <h3>{group.category}</h3>
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Vulnerability</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {group.items.map((item) => (
                <tr key={item.href}>
                  <td><a href={item.href}><code>{item.href}</code></a></td>
                  <td>
                    <span className="badge" style={{ background: BADGE_COLORS[item.badge], color: '#fff' }}>
                      {item.badge}
                    </span>
                    {item.label}
                  </td>
                  <td style={{ color: '#aaa', fontSize: '13px' }}>{item.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {/* Authentication test — links to protected endpoints */}
      <div className="card">
        <h2>Authentication Testing</h2>
        <p style={{ color: '#aaa', fontSize: '13px' }}>
          Tests <code>authentication</code> config — endpoints require a valid session cookie.
        </p>
        <a href="/protected">Protected Area →</a>
      </div>

      {/* Deep nesting links — tests spiderMaxDepth */}
      <div className="card">
        <h2>Depth Testing</h2>
        <p style={{ color: '#aaa', fontSize: '13px' }}>
          Tests <code>spiderMaxDepth</code> — each level is one hop deeper.
        </p>
        <a href="/deep">Level 1 →</a>
      </div>

      {/* Many pages link — tests spiderMaxPages */}
      <div className="card">
        <h2>Volume Testing</h2>
        <p style={{ color: '#aaa', fontSize: '13px' }}>
          Tests <code>spiderMaxPages</code> — contains 200 links.
        </p>
        <a href="/pages-list">200-page list →</a>
      </div>
    </div>
  )
}
