/**
 * Deep Level 1 — tests spiderMaxDepth
 * Reachable from homepage. Spider must go deeper to find vulnerabilities on level 4.
 */
export default function DeepLevel1() {
  return (
    <div>
      <h1>Deep — Level 1</h1>
      <p style={{ color: '#aaa' }}>
        This page is at <strong>depth 1</strong> from the homepage.<br />
        With <code>spiderMaxDepth=1</code>, the spider stops here.<br />
        With <code>spiderMaxDepth=2+</code>, it follows the link below.
      </p>
      <a href="/deep/level-2">Go to Level 2 →</a>
    </div>
  )
}
