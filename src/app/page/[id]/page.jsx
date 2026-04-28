/**
 * Dynamic page — one of 200 pages linked from /pages-list
 * Used to test spiderMaxPages cap.
 */
export default function DynamicPage({ params }) {
  return (
    <div>
      <h1>Page {params.id}</h1>
      <p style={{ color: '#aaa' }}>
        This is page <strong>{params.id}</strong> of 200.
        If the scanner visited this page, it consumed one slot of <code>spiderMaxPages</code>.
      </p>
      <a href="/pages-list">← Back to list</a>
    </div>
  )
}
