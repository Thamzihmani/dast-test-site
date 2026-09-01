export default function AdminUsersPage() {
  return (
    <div>
      <h1>Admin — User Management</h1>
      <p style={{ color: '#ff9800' }}>
        This sub-page of <code>/admin</code> is also disallowed by robots.txt.
        It is only reachable when <code>ignoreRobotsTxt=true</code>.
      </p>
      <table>
        <thead>
          <tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th></tr>
        </thead>
        <tbody>
          <tr><td>1</td><td>Alice</td><td>alice@example.com</td><td>user</td></tr>
          <tr><td>2</td><td>Bob</td><td>bob@example.com</td><td>user</td></tr>
          <tr><td>3</td><td>Admin</td><td>admin@example.com</td><td>admin</td></tr>
        </tbody>
      </table>
    </div>
  )
}
