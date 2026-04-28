/**
 * Admin Panel — tests ignoreRobotsTxt
 *
 * This path is listed under "Disallow: /admin" in robots.txt.
 *
 * Expected DAST behaviour:
 *   ignoreRobotsTxt=false (default) → spider SKIPS this page
 *   ignoreRobotsTxt=true            → spider CRAWLS this page and discovers /admin/users, /admin/settings
 */
export default function AdminPage() {
  return (
    <div>
      <h1>Admin Panel</h1>
      <p style={{ color: '#ff9800' }}>
        ⚠ This page is <strong>disallowed in robots.txt</strong>.<br />
        If you see this page in DAST findings, <code>ignoreRobotsTxt=true</code> is working correctly.
      </p>
      <ul>
        {/* Sub-links — spider should discover these when ignoreRobotsTxt=true */}
        <li><a href="/admin/users">Manage Users</a></li>
        <li><a href="/admin/settings">Settings</a></li>
        <li><a href="/api/idor?id=3">Admin Profile (IDOR)</a></li>
      </ul>
    </div>
  )
}
