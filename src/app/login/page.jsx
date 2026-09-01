/**
 * Login Page — tests authentication config
 *
 * DAST authentication config (type: "form"):
 *   loginUrl:  https://<your-app>/api/auth/login
 *   username:  admin
 *   password:  password123
 *
 * The form POSTs to /api/auth/login which returns a JWT in a cookie.
 * After login, the scanner can access protected endpoints like /dashboard and /api/idor.
 */
export default function LoginPage() {
  return (
    <div>
      <h1>Login</h1>
      <p style={{ color: '#aaa' }}>
        Use these credentials for DAST authentication testing:<br />
        <code>admin / password123</code> &nbsp;|&nbsp; <code>user / password123</code>
      </p>

      <div className="card" style={{ maxWidth: '400px' }}>
        {/* Spider discovers this form and its action/method */}
        <form action="/api/auth/login" method="POST">
          <div style={{ marginBottom: '12px' }}>
            <label style={{ display: 'block', marginBottom: '4px', color: '#aaa' }}>Username</label>
            <input name="username" type="text" defaultValue="admin" style={{ width: '100%' }} />
          </div>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '4px', color: '#aaa' }}>Password</label>
            <input name="password" type="password" defaultValue="password123" style={{ width: '100%' }} />
          </div>
          {/* No CSRF token — intentional */}
          <button type="submit" style={{ width: '100%' }}>Login</button>
        </form>
      </div>

      <p style={{ color: '#555', fontSize: '12px', marginTop: '16px' }}>
        Note: No CSRF token on this form (intentional — tests CSRF detector).<br />
        No rate limiting on login endpoint (intentional — tests rate-limiting detector).
      </p>
    </div>
  )
}
