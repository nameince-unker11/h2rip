const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// ===== Config =====
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'riphack_admin_2026';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'keys.json');

// ===== Database (JSON file) =====
function loadDB() {
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch {
        return { keys: {} };
    }
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Init DB if not exists
if (!fs.existsSync(DB_FILE)) {
    saveDB({ keys: {} });
}

// ===== PUBLIC: Validate key =====
// POST /validate  { key: "...", hwid: "..." }
// Returns: { status: "ok" | "invalid" | "bound" | "activated" }
app.post('/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ status: 'invalid' });

    const db = loadDB();
    const entry = db.keys[key];

    if (!entry) {
        return res.json({ status: 'invalid' }); // Key not found
    }

    if (!entry.hwid) {
        // Key exists but not bound — bind it now
        entry.hwid = hwid;
        entry.activatedAt = new Date().toISOString();
        db.keys[key] = entry;
        saveDB(db);
        return res.json({ status: 'activated' }); // Successfully activated
    }

    if (entry.hwid === hwid) {
        return res.json({ status: 'ok' }); // Already bound to this PC
    }

    return res.json({ status: 'bound' }); // Bound to another PC
});

// ===== PUBLIC: Check existing activation =====
// POST /check  { key: "...", hwid: "..." }
app.post('/check', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false });

    const db = loadDB();
    const entry = db.keys[key];
    if (entry && entry.hwid === hwid) {
        return res.json({ valid: true });
    }
    return res.json({ valid: false });
});

// ===== ADMIN: Middleware =====
function adminAuth(req, res, next) {
    const pass = req.headers['x-admin-password'] || req.body.password;
    if (pass !== ADMIN_PASSWORD) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    next();
}

// ===== ADMIN: List all keys =====
// GET /admin/keys  (header: x-admin-password)
app.get('/admin/keys', adminAuth, (req, res) => {
    const db = loadDB();
    const keys = Object.entries(db.keys).map(([key, data]) => ({
        key,
        hwid: data.hwid || null,
        activatedAt: data.activatedAt || null
    }));
    res.json({ keys });
});

// ===== ADMIN: Add key =====
// POST /admin/add  { password: "...", key: "..." }
app.post('/admin/add', adminAuth, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'Key required' });

    const db = loadDB();
    if (db.keys[key]) return res.json({ status: 'exists' });

    db.keys[key] = { hwid: '', activatedAt: null };
    saveDB(db);
    res.json({ status: 'added', key });
});

// ===== ADMIN: Generate random keys =====
// POST /admin/generate  { password: "...", count: 5 }
app.post('/admin/generate', adminAuth, (req, res) => {
    const count = Math.min(req.body.count || 1, 100);
    const db = loadDB();
    const generated = [];

    for (let i = 0; i < count; i++) {
        const parts = [];
        for (let j = 0; j < 3; j++) {
            const hex = Array.from({ length: 8 }, () =>
                '0123456789ABCDEF'[Math.floor(Math.random() * 16)]
            ).join('');
            parts.push(hex);
        }
        const key = `RIP-${parts.join('-')}`;
        db.keys[key] = { hwid: '', activatedAt: null };
        generated.push(key);
    }

    saveDB(db);
    res.json({ status: 'ok', generated });
});

// ===== ADMIN: Delete key =====
// POST /admin/delete  { password: "...", key: "..." }
app.post('/admin/delete', adminAuth, (req, res) => {
    const { key } = req.body;
    const db = loadDB();
    if (!db.keys[key]) return res.json({ status: 'not_found' });
    delete db.keys[key];
    saveDB(db);
    res.json({ status: 'deleted' });
});

// ===== ADMIN: Reset key (unbind HWID) =====
// POST /admin/reset  { password: "...", key: "..." }
app.post('/admin/reset', adminAuth, (req, res) => {
    const { key } = req.body;
    const db = loadDB();
    if (!db.keys[key]) return res.json({ status: 'not_found' });
    db.keys[key].hwid = '';
    db.keys[key].activatedAt = null;
    saveDB(db);
    res.json({ status: 'reset' });
});

// ===== Health =====
app.get('/', (req, res) => {
    res.json({ name: 'RIP Hack Key Server', status: 'online' });
});

app.listen(PORT, () => {
    console.log(`[RIP Hack] Key server running on port ${PORT}`);
});
