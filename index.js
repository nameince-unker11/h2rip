const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'riphack_admin_2026';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'keys.json');

function loadDB() { try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { keys: {} }; } }
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
if (!fs.existsSync(DB_FILE)) saveDB({ keys: {} });

// ===== PUBLIC: Validate key =====
app.post('/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ status: 'invalid' });
    const db = loadDB();
    const entry = db.keys[key];
    if (!entry) return res.json({ status: 'invalid' });
    if (!entry.hwid) {
        entry.hwid = hwid; entry.activatedAt = new Date().toISOString();
        db.keys[key] = entry; saveDB(db);
        return res.json({ status: 'activated' });
    }
    if (entry.hwid === hwid) return res.json({ status: 'ok' });
    return res.json({ status: 'bound' });
});

app.post('/check', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false });
    const db = loadDB();
    const entry = db.keys[key];
    return res.json({ valid: !!(entry && entry.hwid === hwid) });
});

// ===== ADMIN: Auth =====
function adminAuth(req, res, next) {
    const pass = req.headers['x-admin-password'] || req.body.password;
    if (pass !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Unauthorized' });
    next();
}

app.get('/admin/keys', adminAuth, (req, res) => {
    const db = loadDB();
    const keys = Object.entries(db.keys).map(([key, d]) => ({ key, hwid: d.hwid || null, activatedAt: d.activatedAt || null }));
    res.json({ keys });
});

app.post('/admin/add', adminAuth, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'Key required' });
    const db = loadDB();
    if (db.keys[key]) return res.json({ status: 'exists' });
    db.keys[key] = { hwid: '', activatedAt: null }; saveDB(db);
    res.json({ status: 'added', key });
});

app.post('/admin/generate', adminAuth, (req, res) => {
    const count = Math.min(req.body.count || 1, 100);
    const db = loadDB();
    const generated = [];
    for (let i = 0; i < count; i++) {
        const parts = [];
        for (let j = 0; j < 3; j++) {
            parts.push(Array.from({ length: 8 }, () => '0123456789ABCDEF'[Math.floor(Math.random() * 16)]).join(''));
        }
        const key = `RIP-${parts.join('-')}`;
        db.keys[key] = { hwid: '', activatedAt: null };
        generated.push(key);
    }
    saveDB(db);
    res.json({ status: 'ok', generated });
});

app.post('/admin/delete', adminAuth, (req, res) => {
    const { key } = req.body;
    const db = loadDB();
    if (!db.keys[key]) return res.json({ status: 'not_found' });
    delete db.keys[key]; saveDB(db);
    res.json({ status: 'deleted' });
});

app.post('/admin/reset', adminAuth, (req, res) => {
    const { key } = req.body;
    const db = loadDB();
    if (!db.keys[key]) return res.json({ status: 'not_found' });
    db.keys[key].hwid = ''; db.keys[key].activatedAt = null; saveDB(db);
    res.json({ status: 'reset' });
});

// ===== ADMIN PANEL =====
app.get('/admin', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RIP Hack — Admin Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#121218;color:#dcdceb;font-family:'Segoe UI',sans-serif;min-height:100vh}
.container{max-width:900px;margin:0 auto;padding:20px}
.header{text-align:center;padding:30px 0 20px}
.header h1{font-size:28px;color:#fff;margin-bottom:4px}
.header .sub{color:#8250ff;font-size:14px}
.login-box{background:#1e1e2a;border:1px solid #32324a;border-radius:12px;padding:30px;max-width:400px;margin:60px auto;text-align:center}
.login-box h2{margin-bottom:20px;color:#fff}
input[type=password],input[type=text],input[type=number]{background:#16161e;border:1px solid #32324a;color:#fff;padding:12px 16px;border-radius:8px;width:100%;font-size:14px;outline:none;transition:border .2s}
input:focus{border-color:#8250ff}
.btn{padding:12px 24px;border:none;border-radius:25px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:#8250ff;color:#fff}.btn-primary:hover{background:#9b6eff}
.btn-danger{background:#c83232;color:#fff}.btn-danger:hover{background:#e64646}
.btn-success{background:#50dc82;color:#121218}.btn-success:hover{background:#6ef09a}
.btn-sm{padding:8px 16px;font-size:12px;border-radius:20px}
.btn-outline{background:transparent;border:1px solid #32324a;color:#dcdceb}.btn-outline:hover{border-color:#8250ff;color:#8250ff}
.card{background:#1e1e2a;border:1px solid #32324a;border-radius:12px;padding:20px;margin-bottom:16px}
.card h3{font-size:16px;color:#8250ff;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.stat{background:#16161e;border:1px solid #32324a;border-radius:10px;padding:16px;text-align:center}
.stat .num{font-size:28px;font-weight:700;color:#fff}
.stat .label{font-size:12px;color:#78789a;margin-top:4px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.toolbar input{flex:1;min-width:120px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;color:#78789a;font-size:12px;text-transform:uppercase;border-bottom:1px solid #32324a}
td{padding:10px 12px;border-bottom:1px solid #1a1a24;font-size:13px}
tr:hover td{background:#1a1a24}
.key-text{font-family:Consolas,monospace;color:#50dc82;cursor:pointer;user-select:all}
.key-text.used{color:#ffce3e}
.hwid{font-family:Consolas,monospace;color:#78789a;font-size:12px}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600}
.badge-free{background:#50dc8220;color:#50dc82}
.badge-bound{background:#ffce3e20;color:#ffce3e}
.actions{display:flex;gap:6px}
.toast{position:fixed;bottom:20px;right:20px;background:#1e1e2a;border:1px solid #8250ff;border-radius:10px;padding:12px 20px;color:#fff;font-size:14px;z-index:999;animation:fadeIn .3s}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.hidden{display:none}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>&#9670; RIP HACK</h1>
    <div class="sub">ADMIN PANEL &bull; t.me/cmdsw</div>
  </div>

  <div id="loginSection" class="login-box">
    <h2>&#128274; Authorization</h2>
    <input type="password" id="passInput" placeholder="Admin password" style="margin-bottom:16px">
    <br><button class="btn btn-primary" onclick="doLogin()">LOGIN</button>
    <p id="loginErr" style="color:#ff5050;margin-top:12px" class="hidden"></p>
  </div>

  <div id="mainSection" class="hidden">
    <div class="stats">
      <div class="stat"><div class="num" id="totalKeys">0</div><div class="label">TOTAL KEYS</div></div>
      <div class="stat"><div class="num" id="activeKeys">0</div><div class="label">ACTIVATED</div></div>
      <div class="stat"><div class="num" id="freeKeys">0</div><div class="label">FREE</div></div>
    </div>

    <div class="card">
      <h3>&#128273; Key Management</h3>
      <div class="toolbar">
        <input type="number" id="genCount" value="5" min="1" max="100" style="max-width:80px">
        <button class="btn btn-success btn-sm" onclick="generateKeys()">&#10010; Generate</button>
        <input type="text" id="addKeyInput" placeholder="RIP-XXXXXXXX-XXXXXXXX-XXXXXXXX" style="min-width:250px">
        <button class="btn btn-primary btn-sm" onclick="addKey()">Add Key</button>
        <button class="btn btn-outline btn-sm" onclick="loadKeys()">&#8635; Refresh</button>
      </div>
      <table>
        <thead><tr><th>Key</th><th>Status</th><th>HWID</th><th>Activated</th><th>Actions</th></tr></thead>
        <tbody id="keysTable"></tbody>
      </table>
    </div>
  </div>
</div>

<div id="toast" class="toast hidden"></div>

<script>
let PASS=sessionStorage.getItem('riphack_pass')||'';
const API=window.location.origin;

function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.remove('hidden');setTimeout(()=>t.classList.add('hidden'),2500)}

async function api(method,path,body){
  const opts={method,headers:{'Content-Type':'application/json','x-admin-password':PASS}};
  if(body)opts.body=JSON.stringify({...body,password:PASS});
  const r=await fetch(API+path,opts);
  return r.json();
}

async function doLogin(){
  PASS=document.getElementById('passInput').value;
  try{
    const r=await api('GET','/admin/keys');
    if(r.error){document.getElementById('loginErr').textContent='Wrong password';document.getElementById('loginErr').classList.remove('hidden');PASS='';return}
    sessionStorage.setItem('riphack_pass',PASS);
    document.getElementById('loginSection').classList.add('hidden');
    document.getElementById('mainSection').classList.remove('hidden');
    renderKeys(r.keys);
  }catch(e){document.getElementById('loginErr').textContent='Connection error';document.getElementById('loginErr').classList.remove('hidden')}
}

function renderKeys(keys){
  document.getElementById('totalKeys').textContent=keys.length;
  document.getElementById('activeKeys').textContent=keys.filter(k=>k.hwid).length;
  document.getElementById('freeKeys').textContent=keys.filter(k=>!k.hwid).length;
  const tb=document.getElementById('keysTable');
  tb.innerHTML=keys.map(k=>\`<tr>
    <td class="key-text \${k.hwid?'used':''}" onclick="navigator.clipboard.writeText('\${k.key}');showToast('Copied!')">\${k.key}</td>
    <td><span class="badge \${k.hwid?'badge-bound':'badge-free'}">\${k.hwid?'BOUND':'FREE'}</span></td>
    <td class="hwid">\${k.hwid||'—'}</td>
    <td style="color:#78789a;font-size:12px">\${k.activatedAt?new Date(k.activatedAt).toLocaleString():'—'}</td>
    <td class="actions">
      \${k.hwid?\`<button class="btn btn-outline btn-sm" onclick="resetKey('\${k.key}')">Reset</button>\`:''}
      <button class="btn btn-danger btn-sm" onclick="deleteKey('\${k.key}')">Delete</button>
    </td>
  </tr>\`).join('');
}

async function loadKeys(){try{const r=await api('GET','/admin/keys');renderKeys(r.keys);showToast('Refreshed')}catch(e){showToast('Error: '+e.message)}}
async function generateKeys(){try{const c=parseInt(document.getElementById('genCount').value)||5;await api('POST','/admin/generate',{count:c});showToast(c+' keys generated');await loadKeys()}catch(e){showToast('Error: '+e.message)}}
async function addKey(){try{const k=document.getElementById('addKeyInput').value.trim();if(!k)return;await api('POST','/admin/add',{key:k});document.getElementById('addKeyInput').value='';showToast('Key added');await loadKeys()}catch(e){showToast('Error: '+e.message)}}
async function deleteKey(k){try{const r=await api('POST','/admin/delete',{key:k});showToast(r.status==='deleted'?'Deleted!':'Error: '+r.status);await loadKeys()}catch(e){showToast('Error: '+e.message)}}
async function resetKey(k){try{const r=await api('POST','/admin/reset',{key:k});showToast(r.status==='reset'?'HWID reset!':'Error: '+r.status);await loadKeys()}catch(e){showToast('Error: '+e.message)}}

document.getElementById('passInput').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

// Auto-login if password saved in session
if(PASS){api('GET','/admin/keys').then(r=>{if(!r.error){document.getElementById('loginSection').classList.add('hidden');document.getElementById('mainSection').classList.remove('hidden');renderKeys(r.keys)}else{PASS='';sessionStorage.removeItem('riphack_pass')}}).catch(()=>{})}
</script>
</body>
</html>`);
});

app.get('/', (req, res) => res.json({ name: 'RIP Hack Key Server', status: 'online' }));

app.listen(PORT, () => console.log(`[RIP Hack] Key server running on port ${PORT}`));
