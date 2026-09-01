export const metadata = {
  title: 'DAST Test App — Vigilnz',
  description: 'Deliberately vulnerable app for testing the Vigilnz DAST scanner',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head />
      <body style={{ fontFamily: 'monospace', margin: '0', background: '#0f0f0f', color: '#e0e0e0' }}>
        <nav style={{
          background: '#1a1a2e',
          padding: '12px 24px',
          borderBottom: '1px solid #ff4444',
          display: 'flex',
          gap: '16px',
          alignItems: 'center',
          flexWrap: 'wrap',
        }}>
          <span style={{ color: '#ff4444', fontWeight: 'bold', marginRight: '8px' }}>
            ⚠ DAST Test App
          </span>
          <a href="/" style={{ color: '#aaa', textDecoration: 'none' }}>Home</a>
          <a href="/login" style={{ color: '#aaa', textDecoration: 'none' }}>Login</a>
          <a href="/dashboard" style={{ color: '#aaa', textDecoration: 'none' }}>Dashboard</a>
          <a href="/admin" style={{ color: '#aaa', textDecoration: 'none' }}>Admin</a>
        </nav>
        <main style={{ padding: '24px', maxWidth: '960px', margin: '0 auto' }}>
          {children}
        </main>
        <footer style={{
          textAlign: 'center',
          padding: '16px',
          color: '#555',
          borderTop: '1px solid #222',
          fontSize: '12px',
        }}>
          Vigilnz DAST Test App — For authorized security testing only
        </footer>
      </body>
    </html>
  )
}
