export default function DeepLevel3() {
  return (
    <div>
      <h1>Deep — Level 3</h1>
      <p style={{ color: '#aaa' }}>
        Depth 3 from homepage. Requires <code>spiderMaxDepth=3+</code> to reach.
        This is the <strong>default max depth</strong> — the spider reaches here but not level 4.
      </p>
      <a href="/deep/level-2/level-3/level-4">Go to Level 4 →</a>
    </div>
  )
}
