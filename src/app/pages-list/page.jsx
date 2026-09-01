/**
 * Pages List — tests spiderMaxPages
 *
 * Generates 200 individual page links.
 * With spiderMaxPages=10: spider stops after 10 pages, most entries in /page/* are skipped.
 * With spiderMaxPages=200+: spider crawls all of them.
 * Check spiderResults.skippedUrls for entries with reason "max-pages-exceeded".
 */
export default function PagesListPage() {
  return (
    <div>
      <h1>Volume Test — 200 Pages</h1>
      <p style={{ color: '#aaa' }}>
        This page links to 200 sub-pages. Use it to test <code>spiderMaxPages</code>.<br />
        Set <code>spiderMaxPages=10</code> to see the spider stop early.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(10, 1fr)', gap: '4px', marginTop: '16px' }}>
        {Array.from({ length: 200 }, (_, i) => (
          <a
            key={i + 1}
            href={`/page/${i + 1}`}
            style={{ fontSize: '12px', textAlign: 'center', padding: '4px', background: '#1e1e2e', borderRadius: '3px' }}
          >
            {i + 1}
          </a>
        ))}
      </div>
    </div>
  )
}
