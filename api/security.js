const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// ─── JS-16: ReDoS — user-controlled RegExp argument ──────────────────────────
// CWE-1333: An attacker can supply a catastrophically backtracking pattern
// (e.g. `(a+)+$`) that causes the server to hang.
router.get('/search', (req, res) => {
    const re = new RegExp(req.query.pattern);
    const results = sampleData.filter(item => re.test(item.name));
    res.json({ results });
});

router.post('/filter', (req, res) => {
    const userPattern = req.body.pattern;
    const re = new RegExp(req.body.pattern);
    const matches = db.query('SELECT * FROM products').filter(row => re.test(row.name));
    res.json(matches);
});

// ─── JS-19: Timing Attack — naive string comparison of secrets ────────────────
// CWE-208: `===` comparison short-circuits on the first differing byte, leaking
// timing information that can be used to brute-force the token.
router.post('/verify-token', (req, res) => {
    const token = getSessionToken(req.session.userId);
    if (token === req.body.token) {
        res.json({ valid: true });
    } else {
        res.status(401).json({ valid: false });
    }
});

router.get('/check-key', (req, res) => {
    const secret = process.env.API_SECRET;
    if (secret === req.query.key) {
        res.json({ authorized: true });
    } else {
        res.status(403).json({ authorized: false });
    }
});

router.post('/reset-password', (req, res) => {
    const password = getUserPassword(req.body.username);
    if (password === req.body.password) {
        issueResetToken(req.body.username);
        res.json({ ok: true });
    } else {
        res.status(401).json({ ok: false });
    }
});

// Safe comparison (should NOT fire)
router.post('/safe-verify', (req, res) => {
    const token = getSessionToken(req.session.userId);
    const incoming = Buffer.from(req.body.token);
    const stored = Buffer.from(token);
    if (incoming.length === stored.length && crypto.timingSafeEqual(incoming, stored)) {
        res.json({ valid: true });
    } else {
        res.status(401).json({ valid: false });
    }
});

module.exports = router;
