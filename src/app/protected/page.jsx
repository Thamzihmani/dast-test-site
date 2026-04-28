/**
 * Protected Page — tests DAST authentication config
 *
 * This page links to auth-protected endpoints.
 * Spider discovers these links ONLY when the authenticated scan reaches this page.
 *
 * With authentication config:    scanner logs in → session cookie set → this page accessible
 * Without authentication config: scanner has no session → /api/protected/profile returns 401
 */
export default function ProtectedPage() {
  return (
    <div>
      <h1>Protected Area</h1>
      <p style={{ color: '#4fc3f7' }}>
        This page links to authenticated-only endpoints.
        These findings only appear in scans with <code>authentication</code> configured.
      </p>

      {/* IDOR — only testable with valid session cookie */}
      <div className="card">
        <h3>User Profile (IDOR test)</h3>
        <p style={{ color: '#aaa', fontSize: '13px' }}>
          Returns private user data. No ownership check — change id to access any user.
        </p>
        <a href="/api/protected/profile?id=1">View My Profile</a>
        <br />
        <a href="/api/protected/profile?id=2">View Profile (id=2)</a>
      </div>
    </div>
  )
}
