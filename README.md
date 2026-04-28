# DAST Test App

> ⚠ **Intentionally vulnerable** — deploy in isolated environments only.
> Built specifically to test the **Vigilnz DAST scanner** and its advanced configurations.

---

## Deploy to Vercel (Free Tier)

```bash
# 1. Install dependencies
cd testing-projects/Dast
npm install

# 2. Run locally first
npm run dev
# → http://localhost:3000

# 3. Deploy to Vercel
npm i -g vercel
vercel --prod
# → https://your-app.vercel.app
```

---

## Test Matrix

Use this table to verify each DAST advanced config works correctly.

### Scan Types

| Scan Type | What to expect |
|---|---|
| `spider` | Crawls all pages, returns passive findings only (headers, cors, clickjacking) |
| `active` | Tests the single URL directly — set URL to `/api/sqli?id=1`, gets SQLi findings |
| `full` | Spider first (discovers all endpoints) then active scan (tests each one) |

### Scan Profiles

| Profile | Endpoints that should fire |
|---|---|
| `quick` | `/api/sqli`, `/api/xss`, `/api/headers`, `/api/ssrf` |
| `owasp-top10` | All of the above + `/api/idor`, `/api/cors`, `/api/jwt`, `/api/csrf`, `/api/redirect`, `/api/clickjacking` |
| `api-only` | `/api/sqli`, `/api/xss`, `/api/headers`, `/api/ssrf`, `/api/idor`, `/api/cors`, `/api/jwt` |
| `full` | All endpoints including `/api/path-traversal`, `/api/rate-limit` |

### Advanced Configs

#### `fragmentationEnabled`

1. Set `ENABLE_FAKE_WAF=true` in Vercel environment variables
2. Run scan with `fragmentationEnabled: false` → `/api/xss` returns 403 → 0 XSS findings
3. Run scan with `fragmentationEnabled: true` → WAF bypassed → XSS finding appears

#### `useBrowser`

| Config | Spider discovers |
|---|---|
| `useBrowser: false` | Links in static HTML only |
| `useBrowser: true` | Also discovers endpoints rendered by JavaScript |

Add a JS-rendered link to test this:
```html
<!-- Only visible after JS executes -->
<script>document.write('<a href="/api/idor?id=2">Hidden Link</a>')</script>
```

#### `ignoreRobotsTxt`

| Config | `/admin` page | `/api/idor` | `/api/jwt` | `/api/ssrf` |
|---|---|---|---|---|
| `ignoreRobotsTxt: false` | ❌ Skipped | ❌ Skipped | ❌ Skipped | ❌ Skipped |
| `ignoreRobotsTxt: true` | ✅ Crawled | ✅ Tested | ✅ Tested | ✅ Tested |

Verify: check `spiderResults.robotsTxtRespected` in raw results.

#### `spiderMaxDepth`

| `spiderMaxDepth` | Pages discovered |
|---|---|
| `1` | Homepage + direct links (no `/deep/level-2`) |
| `2` | + `/deep/level-2` |
| `3` | + `/deep/level-2/level-3` (default) |
| `4` | + `/deep/level-2/level-3/level-4` — has hidden SQLi form |

Verify: check `spiderResults.testableEndpoints` length.

#### `spiderMaxPages`

1. Set `spiderMaxPages: 10` and scan — spider should stop early
2. Check `spiderResults.skippedUrls` — entries with reason `max-pages-exceeded`
3. Set `spiderMaxPages: 200` — spider crawls all 200 pages in `/pages-list`

#### `authentication`

**Form auth:**
```json
{
  "type": "form",
  "loginUrl": "https://your-app.vercel.app/api/auth/login",
  "credentials": { "username": "admin", "password": "password123" }
}
```

**Bearer auth:**
```json
{
  "type": "bearer",
  "credentials": { "token": "<JWT from /api/auth/login response>" }
}
```

Without auth: `/api/idor` returns public data
With auth: scanner should still find IDOR (changing `id` param returns other users' data)

---

## Endpoint Reference

| Endpoint | Method | Vulnerability | Triggered by |
|---|---|---|---|
| `/api/sqli?id=1` | GET | SQL Injection | `?id=1'` or `?id=1 OR 1=1` |
| `/api/xss?q=hello` | GET | Reflected XSS | `?q=<script>alert(1)</script>` |
| `/api/redirect?url=https://example.com` | GET | Open Redirect | `?url=https://evil.com` |
| `/api/headers` | GET | Missing Security Headers | Any request |
| `/api/cors` | GET | CORS Misconfiguration | Request with Origin header |
| `/api/ssrf?url=https://example.com` | GET | SSRF | `?url=http://169.254.169.254/` |
| `/api/idor?id=1` | GET | IDOR | `?id=2`, `?id=3`, `?id=4` |
| `/api/jwt` | GET | Weak JWT | Token with `alg:none` or signed with `secret` |
| `/api/csrf` | POST | CSRF | Any POST without token |
| `/api/path-traversal?file=readme.txt` | GET | Path Traversal | `?file=../../etc/passwd` |
| `/api/clickjacking` | GET | Clickjacking | Any request — no X-Frame-Options |
| `/api/rate-limit` | GET | No Rate Limiting | Burst of rapid requests |
| `/api/auth/login` | POST | Weak Auth (no rate limit) | Brute-force attempts |

---

## Environment Variables

Copy `.env.example` to `.env.local` for local dev:

| Variable | Default | Purpose |
|---|---|---|
| `ENABLE_FAKE_WAF` | `false` | Enable fake WAF for fragmentationEnabled testing |
| `JWT_SECRET` | `secret` | Intentionally weak JWT secret |
| `SSRF_TIMEOUT_MS` | `3000` | Timeout for SSRF fetch requests |

---

## Local DAST Scan Example

```js
// Run from: Vigilnz/dast/
const { runDastScans } = require('./lib/index')

const scanContext = {
  dastScanType: 'full',
  scanProfile: 'owasp-top10',
  ignoreRobotsTxt: true,     // crawl /admin, /api/idor, /api/jwt
  spiderMaxDepth: 4,          // reach /deep/level-2/level-3/level-4
  spiderMaxPages: 50,
  authentication: {
    type: 'form',
    loginUrl: 'http://localhost:3000/api/auth/login',
    credentials: { username: 'admin', password: 'password123' },
  },
}

runDastScans('http://localhost:3000', scanContext, (update) => {
  console.log(`[${update.phase}] ${update.progress}% — ${update.message}`)
}).then((results) => {
  console.log('\n=== RESULTS ===')
  console.log('Summary:', results.summary)
  console.log('Spider pages:', results.rawResults?.spider?.pagesVisited)
  console.log('robotsTxtRespected:', results.rawResults?.spider?.robotsTxtRespected)
  results.findings.forEach((f) => {
    console.log(`  [${f.severity}] ${f.alertName} — ${f.url}`)
  })
})
```
