/**
 * Dashboard — protected page (tests authentication config)
 *
 * In a real app this would check a session cookie.
 * Here it is intentionally open to show what authenticated scans can discover.
 * When you run a DAST scan with authentication configured, the scanner
 * will reach this page and discover the links below.
 */
export default function DashboardPage() {
  return (
    <div>
      <h1>Dashboard</h1>
      <p style={{ color: '#aaa' }}>
        This page is discoverable by the spider and links to authenticated-only endpoints.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div className="card">
          <h3>My Profile</h3>
          <a href="/api/idor?id=1">View Profile</a>
          <p style={{ color: '#555', fontSize: '12px' }}>
            Without auth: returns public data<br />
            With auth: should return private data (IDOR if ID is changeable)
          </p>
        </div>
        <div className="card">
          <h3>Settings</h3>
          <a href="/api/csrf">Update Settings (CSRF test)</a>
        </div>
        <div className="card">
          <h3>API Tokens</h3>
          <a href="/api/jwt">Validate JWT</a>
        </div>
        <div className="card">
          <h3>Admin Area</h3>
          <a href="/admin">Go to Admin Panel</a>
          <p style={{ color: '#555', fontSize: '12px' }}>Only visible with ignoreRobotsTxt=true</p>
        </div>
      </div>
    </div>
  )
}
