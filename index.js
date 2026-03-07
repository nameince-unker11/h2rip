const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'riphack_admin_2026';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'keys.json');
const SERVER_KEY_FILE = path.join(__dirname, 'server_key.txt');
const KEYS_TXT_FILE = path.join(__dirname, '..', 'keys.txt');

function loadDB() { try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { keys: {}, serverKey: '' }; } }
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
if (!fs.existsSync(DB_FILE)) saveDB({ keys: {}, serverKey: '' });

// ===== Автоимпорт ключей из keys.txt =====
function importKeysFromTxt() {
  try {
    if (!fs.existsSync(KEYS_TXT_FILE)) return;
    const content = fs.readFileSync(KEYS_TXT_FILE, 'utf8').trim();
    if (!content) return;
    const lines = content.split(/\r?\n/).filter(l => l.trim());
    const db = loadDB();
    let imported = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // Формат: KEY или KEY:HWID
      const parts = trimmed.split(':');
      let key, hwid = '';
      if (parts.length >= 4) {
        // Формат RIP-XXXX-XXXX-XXXX:HWID — ключ содержит дефисы, HWID после последнего двоеточия
        // Ключ: всё до последнего ':' если после ':' идёт формат HWID (XXXXXXXX-XXXXXXXX)
        const lastColon = trimmed.lastIndexOf(':');
        const possibleHwid = trimmed.substring(lastColon + 1);
        if (/^[A-F0-9]{8}-[A-F0-9]{8}$/i.test(possibleHwid)) {
          key = trimmed.substring(0, lastColon);
          hwid = possibleHwid;
        } else {
          key = trimmed;
        }
      } else {
        key = trimmed;
      }
      if (!db.keys[key]) {
        db.keys[key] = { hwid: hwid, activatedAt: hwid ? new Date().toISOString() : null };
        imported++;
      } else if (hwid && !db.keys[key].hwid) {
        // Обновить HWID если в txt он есть, а в базе — нет
        db.keys[key].hwid = hwid;
        db.keys[key].activatedAt = db.keys[key].activatedAt || new Date().toISOString();
        imported++;
      }
    }
    if (imported > 0) {
      saveDB(db);
      console.log(`[RIP Hack] Импортировано ${imported} ключей из keys.txt`);
    }
  } catch (e) {
    console.error('[RIP Hack] Ошибка импорта keys.txt:', e.message);
  }
}
importKeysFromTxt();

// Загрузить серверный ключ из файла (если есть)
function getServerKey() {
  const db = loadDB();
  if (db.serverKey) return db.serverKey;
  // Попробовать прочитать из файла server_key.txt
  try {
    const sk = fs.readFileSync(SERVER_KEY_FILE, 'utf8').trim();
    if (sk.length >= 32) {
      db.serverKey = sk;
      saveDB(db);
      return sk;
    }
  } catch { }
  return '';
}

// ===== PUBLIC: Активация ключа =====
app.post('/validate', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ status: 'invalid' });
  const db = loadDB();
  const entry = db.keys[key];
  if (!entry) return res.json({ status: 'invalid' });

  if (!entry.hwid) {
    entry.hwid = hwid;
    entry.activatedAt = new Date().toISOString();
    db.keys[key] = entry;
    saveDB(db);
    return res.json({ status: 'activated' });
  }
  if (entry.hwid === hwid) return res.json({ status: 'ok' });
  return res.json({ status: 'bound' });
});

// ===== PUBLIC: Проверка ключа =====
app.post('/check', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ valid: false });
  const db = loadDB();
  const entry = db.keys[key];
  const isValid = !!(entry && entry.hwid === hwid);
  return res.json({ valid: isValid });
});

// ===== ADMIN: Авторизация =====
function adminAuth(req, res, next) {
  const pass = req.headers['x-admin-password'] || req.body.password;
  if (pass !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Unauthorized' });
  next();
}

// Получить все ключи
app.get('/admin/keys', adminAuth, (req, res) => {
  const db = loadDB();
  const keys = Object.entries(db.keys).map(([key, d]) => ({
    key,
    hwid: (d.hwid && d.hwid.length > 0) ? d.hwid : null,
    activatedAt: d.activatedAt || null
  }));
  // Сортировка: сначала активные (с HWID), потом свободные
  keys.sort((a, b) => {
    if (a.hwid && !b.hwid) return -1;
    if (!a.hwid && b.hwid) return 1;
    return 0;
  });
  const serverKey = getServerKey();
  res.json({ keys, serverKey: serverKey || null });
});

// Добавить один ключ
app.post('/admin/add', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key required' });
  const db = loadDB();
  if (db.keys[key]) return res.json({ status: 'exists' });
  db.keys[key] = { hwid: '', activatedAt: null };
  saveDB(db);
  res.json({ status: 'added', key });
});

// Сгенерировать ключи (формат: RIP-XXXXXXXX-XXXXXXXX-XXXXXXXX)
app.post('/admin/generate', adminAuth, (req, res) => {
  const count = Math.min(req.body.count || 1, 100);
  const db = loadDB();
  const generated = [];
  for (let i = 0; i < count; i++) {
    const buf = crypto.randomBytes(12);
    const part1 = buf.slice(0, 4).toString('hex').toUpperCase();
    const part2 = buf.slice(4, 8).toString('hex').toUpperCase();
    const part3 = buf.slice(8, 12).toString('hex').toUpperCase();
    const key = `RIP-${part1}-${part2}-${part3}`;
    db.keys[key] = { hwid: '', activatedAt: null };
    generated.push(key);
  }
  saveDB(db);
  res.json({ status: 'ok', generated });
});

// Удалить ключ
app.post('/admin/delete', adminAuth, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ status: 'not_found' });
  delete db.keys[key];
  saveDB(db);
  res.json({ status: 'deleted' });
});

// Сбросить HWID ключа
app.post('/admin/reset', adminAuth, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ status: 'not_found' });
  db.keys[key].hwid = '';
  db.keys[key].activatedAt = null;
  saveDB(db);
  res.json({ status: 'reset' });
});

// Установить серверный ключ дешифрования
app.post('/admin/server-key', adminAuth, (req, res) => {
  const { server_key } = req.body;
  if (!server_key || server_key.length < 32) {
    return res.status(400).json({ error: 'server_key должен быть hex-строкой из 32+ символов' });
  }
  // Проверить что это валидный hex
  if (!/^[0-9a-fA-F]+$/.test(server_key)) {
    return res.status(400).json({ error: 'server_key должен содержать только hex-символы' });
  }
  const db = loadDB();
  db.serverKey = server_key.toLowerCase();
  saveDB(db);
  // Также сохранить в файл
  fs.writeFileSync(SERVER_KEY_FILE, server_key.toLowerCase());
  res.json({ status: 'ok', message: 'Серверный ключ обновлён' });
});

// ===== АДМИН-ПАНЕЛЬ =====
app.get('/admin', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RIP Hack — Админ-панель</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a12;color:#dcdceb;font-family:'Segoe UI',sans-serif;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:20px}
.header{text-align:center;padding:30px 0 20px}
.header h1{font-size:28px;color:#fff;margin-bottom:4px;letter-spacing:2px}
.header .sub{color:#8250ff;font-size:13px;letter-spacing:1px}
.login-box{background:linear-gradient(135deg,#1a1a2e,#16162a);border:1px solid #32324a;border-radius:16px;padding:36px;max-width:420px;margin:60px auto;text-align:center;box-shadow:0 8px 32px rgba(130,80,255,0.1)}
.login-box h2{margin-bottom:24px;color:#fff;font-size:20px}
input[type=password],input[type=text],input[type=number]{background:#0e0e1a;border:1px solid #32324a;color:#fff;padding:12px 16px;border-radius:10px;width:100%;font-size:14px;outline:none;transition:border .3s,box-shadow .3s}
input:focus{border-color:#8250ff;box-shadow:0 0 12px rgba(130,80,255,0.2)}
textarea{background:#0e0e1a;border:1px solid #32324a;color:#50dc82;padding:12px 16px;border-radius:10px;width:100%;font-size:13px;font-family:Consolas,monospace;outline:none;resize:vertical;min-height:60px;transition:border .3s}
textarea:focus{border-color:#8250ff}
.btn{padding:12px 24px;border:none;border-radius:25px;font-size:14px;font-weight:600;cursor:pointer;transition:all .25s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:linear-gradient(135deg,#8250ff,#6930d4);color:#fff}.btn-primary:hover{background:linear-gradient(135deg,#9b6eff,#7e4ef5);transform:translateY(-1px);box-shadow:0 4px 16px rgba(130,80,255,0.3)}
.btn-danger{background:linear-gradient(135deg,#c83232,#a82828);color:#fff}.btn-danger:hover{background:linear-gradient(135deg,#e64646,#c83232)}
.btn-success{background:linear-gradient(135deg,#50dc82,#3ab868);color:#0a0a12}.btn-success:hover{background:linear-gradient(135deg,#6ef09a,#50dc82)}
.btn-warn{background:linear-gradient(135deg,#ffce3e,#e6b830);color:#0a0a12}.btn-warn:hover{background:linear-gradient(135deg,#ffe066,#ffce3e)}
.btn-sm{padding:8px 16px;font-size:12px;border-radius:20px}
.btn-outline{background:transparent;border:1px solid #32324a;color:#dcdceb}.btn-outline:hover{border-color:#8250ff;color:#8250ff}
.card{background:linear-gradient(135deg,#141420,#1a1a2e);border:1px solid #28284a;border-radius:14px;padding:24px;margin-bottom:18px;box-shadow:0 4px 20px rgba(0,0,0,0.3)}
.card h3{font-size:15px;color:#8250ff;margin-bottom:18px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:1px;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:22px}
.stat{background:linear-gradient(135deg,#12121e,#16162a);border:1px solid #28284a;border-radius:12px;padding:18px;text-align:center;transition:border .3s}
.stat:hover{border-color:#8250ff}
.stat .num{font-size:32px;font-weight:700;color:#fff;text-shadow:0 0 20px rgba(130,80,255,0.3)}
.stat .label{font-size:11px;color:#78789a;margin-top:6px;text-transform:uppercase;letter-spacing:1px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.toolbar input{flex:1;min-width:110px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;color:#78789a;font-size:11px;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #28284a}
td{padding:10px 12px;border-bottom:1px solid #1a1a24;font-size:13px}
tr:hover td{background:#12121e}
.key-text{font-family:Consolas,monospace;color:#50dc82;cursor:pointer;user-select:all;transition:color .2s}
.key-text:hover{color:#6ef09a}
.key-text.used{color:#ffce3e}
.hwid{font-family:Consolas,monospace;color:#78789a;font-size:12px}
.badge{padding:4px 12px;border-radius:12px;font-size:11px;font-weight:600}
.badge-free{background:#50dc8218;color:#50dc82;border:1px solid #50dc8240}
.badge-bound{background:#ffce3e18;color:#ffce3e;border:1px solid #ffce3e40}
.actions{display:flex;gap:6px}
.filter-btn{background:transparent;border:1px solid #32324a;color:#78789a;transition:all .25s}
.filter-btn:hover{border-color:#8250ff;color:#8250ff}
.filter-btn.active{background:linear-gradient(135deg,#8250ff22,#6930d422);border-color:#8250ff;color:#8250ff}
.server-key-status{font-family:Consolas,monospace;font-size:12px;padding:8px 14px;background:#0e0e1a;border:1px solid #28284a;border-radius:8px;color:#50dc82;word-break:break-all}
.server-key-status.missing{color:#ff5050;border-color:#ff505040}
.toast{position:fixed;bottom:24px;right:24px;background:linear-gradient(135deg,#1a1a2e,#22223a);border:1px solid #8250ff;border-radius:12px;padding:14px 22px;color:#fff;font-size:14px;z-index:999;animation:slideIn .3s;box-shadow:0 8px 24px rgba(130,80,255,0.2)}
@keyframes slideIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
.hidden{display:none}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>&#9670; RIP HACK</h1>
    <div class="sub">АДМИН-ПАНЕЛЬ &bull; FORTRESS v3.0</div>
  </div>

  <div id="loginSection" class="login-box">
    <h2>&#128274; Авторизация</h2>
    <input type="password" id="passInput" placeholder="Пароль администратора" style="margin-bottom:16px">
    <br><button class="btn btn-primary" onclick="doLogin()">ВОЙТИ</button>
    <p id="loginErr" style="color:#ff5050;margin-top:14px" class="hidden"></p>
  </div>

  <div id="mainSection" class="hidden">
    <div class="stats">
      <div class="stat"><div class="num" id="totalKeys">0</div><div class="label">Всего ключей</div></div>
      <div class="stat"><div class="num" id="activeKeys">0</div><div class="label">Активировано</div></div>
      <div class="stat"><div class="num" id="freeKeys">0</div><div class="label">Свободно</div></div>
    </div>

    <div class="card">
      <h3>&#128272; Серверный ключ DLL</h3>
      <p style="font-size:13px;color:#78789a;margin-bottom:12px">Без этого ключа клиент не сможет расшифровать DLL. Вставьте содержимое <code>server_key.txt</code> после сборки.</p>
      <div id="serverKeyStatus" class="server-key-status missing">Не установлен</div>
      <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
        <input type="text" id="serverKeyInput" placeholder="Вставьте hex из server_key.txt (32 символа)" style="flex:1;font-family:Consolas,monospace">
        <button class="btn btn-warn btn-sm" onclick="setServerKey()">&#128273; Установить</button>
      </div>
    </div>

    <div class="card">
      <h3>&#128273; Управление ключами</h3>
      <div class="toolbar">
        <input type="number" id="genCount" value="5" min="1" max="100" style="max-width:80px">
        <button class="btn btn-success btn-sm" onclick="generateKeys()">&#10010; Сгенерировать</button>
        <input type="text" id="addKeyInput" placeholder="RIP-XXXXXXXX-XXXXXXXX-XXXXXXXX" style="min-width:250px">
        <button class="btn btn-primary btn-sm" onclick="addKey()">Добавить</button>
        <button class="btn btn-outline btn-sm" onclick="loadKeys()">&#8635; Обновить</button>
      </div>
      <div class="toolbar" style="margin-top:-8px">
        <button class="btn btn-sm filter-btn active" id="filterAll" onclick="setFilter('all')" style="padding:6px 16px;font-size:11px">Все</button>
        <button class="btn btn-sm filter-btn" id="filterActive" onclick="setFilter('active')" style="padding:6px 16px;font-size:11px">&#9679; Активные</button>
        <button class="btn btn-sm filter-btn" id="filterFree" onclick="setFilter('free')" style="padding:6px 16px;font-size:11px">&#9675; Свободные</button>
        <input type="text" id="searchInput" placeholder="Поиск по ключу или HWID..." oninput="applyFilter()" style="flex:1;min-width:160px;padding:6px 12px;font-size:12px">
      </div>
      <table>
        <thead><tr><th>Ключ</th><th>Статус</th><th>HWID</th><th>Активирован</th><th>Действия</th></tr></thead>
        <tbody id="keysTable"></tbody>
      </table>
    </div>
  </div>
</div>

<div id="toast" class="toast hidden"></div>

<script>
let PASS=sessionStorage.getItem('riphack_pass')||'';
const API=window.location.origin;

function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.remove('hidden');setTimeout(()=>t.classList.add('hidden'),2800)}

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
    if(r.error){document.getElementById('loginErr').textContent='Неверный пароль';document.getElementById('loginErr').classList.remove('hidden');PASS='';return}
    sessionStorage.setItem('riphack_pass',PASS);
    document.getElementById('loginSection').classList.add('hidden');
    document.getElementById('mainSection').classList.remove('hidden');
    renderKeys(r.keys);
    renderServerKey(r.serverKey);
  }catch(e){document.getElementById('loginErr').textContent='Ошибка подключения';document.getElementById('loginErr').classList.remove('hidden')}
}

function renderServerKey(sk){
  const el=document.getElementById('serverKeyStatus');
  if(sk){
    el.textContent='✅ '+sk;
    el.classList.remove('missing');
  }else{
    el.textContent='⚠️ Не установлен — DLL не расшифруется!';
    el.classList.add('missing');
  }
}

let allKeys=[];
let currentFilter='all';

function renderKeys(keys){
  if(!keys||!Array.isArray(keys)){keys=[];}
  allKeys=keys;
  document.getElementById('totalKeys').textContent=keys.length;
  document.getElementById('activeKeys').textContent=keys.filter(k=>k.hwid).length;
  document.getElementById('freeKeys').textContent=keys.filter(k=>!k.hwid).length;
  applyFilter();
}

function setFilter(f){
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(f==='all'?'filterAll':f==='active'?'filterActive':'filterFree').classList.add('active');
  applyFilter();
}

function applyFilter(){
  let filtered=allKeys;
  if(currentFilter==='active') filtered=allKeys.filter(k=>k.hwid);
  else if(currentFilter==='free') filtered=allKeys.filter(k=>!k.hwid);
  const search=(document.getElementById('searchInput')||{}).value||'';
  if(search.trim()){
    const q=search.trim().toLowerCase();
    filtered=filtered.filter(k=>k.key.toLowerCase().includes(q)||(k.hwid&&k.hwid.toLowerCase().includes(q)));
  }
  const tb=document.getElementById('keysTable');
  if(filtered.length===0){
    tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:#78789a;padding:24px">Нет ключей для отображения</td></tr>';
    return;
  }
  tb.innerHTML=filtered.map(k=>\`<tr>
    <td class="key-text \${k.hwid?'used':''}" onclick="navigator.clipboard.writeText('\${k.key}');showToast('Скопировано!')">\${k.key}</td>
    <td><span class="badge \${k.hwid?'badge-bound':'badge-free'}">\${k.hwid?'ПРИВЯЗАН':'СВОБОДЕН'}</span></td>
    <td class="hwid">\${k.hwid||'—'}</td>
    <td style="color:#78789a;font-size:12px">\${k.activatedAt?new Date(k.activatedAt).toLocaleString():'—'}</td>
    <td class="actions">
      \${k.hwid?\`<button class="btn btn-outline btn-sm" onclick="resetKey('\${k.key}')">Сброс</button>\`:''}
      <button class="btn btn-danger btn-sm" onclick="deleteKey('\${k.key}')">Удалить</button>
    </td>
  </tr>\`).join('');
}

async function loadKeys(){try{const r=await api('GET','/admin/keys');renderKeys(r.keys||[]);renderServerKey(r.serverKey);showToast('Обновлено')}catch(e){showToast('Ошибка: '+e.message)}}
async function generateKeys(){try{const c=parseInt(document.getElementById('genCount').value)||5;await api('POST','/admin/generate',{count:c});showToast(c+' ключей сгенерировано');await loadKeys()}catch(e){showToast('Ошибка: '+e.message)}}
async function addKey(){try{const k=document.getElementById('addKeyInput').value.trim();if(!k)return;await api('POST','/admin/add',{key:k});document.getElementById('addKeyInput').value='';showToast('Ключ добавлен');await loadKeys()}catch(e){showToast('Ошибка: '+e.message)}}
async function deleteKey(k){try{const r=await api('POST','/admin/delete',{key:k});showToast(r.status==='deleted'?'Удалён!':'Ошибка: '+r.status);await loadKeys()}catch(e){showToast('Ошибка: '+e.message)}}
async function resetKey(k){try{const r=await api('POST','/admin/reset',{key:k});showToast(r.status==='reset'?'HWID сброшен!':'Ошибка: '+r.status);await loadKeys()}catch(e){showToast('Ошибка: '+e.message)}}

async function setServerKey(){
  const sk=document.getElementById('serverKeyInput').value.trim();
  if(!sk||sk.length<32){showToast('Ошибка: нужна hex-строка из 32 символов');return}
  try{
    const r=await api('POST','/admin/server-key',{server_key:sk});
    if(r.error){showToast('Ошибка: '+r.error);return}
    showToast('Серверный ключ установлен!');
    document.getElementById('serverKeyInput').value='';
    await loadKeys();
  }catch(e){showToast('Ошибка: '+e.message)}
}

document.getElementById('passInput').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

// Авто-логин если пароль сохранён
if(PASS){api('GET','/admin/keys').then(r=>{if(!r.error){document.getElementById('loginSection').classList.add('hidden');document.getElementById('mainSection').classList.remove('hidden');renderKeys(r.keys);renderServerKey(r.serverKey)}else{PASS='';sessionStorage.removeItem('riphack_pass')}}).catch(()=>{})}
</script>
</body>
</html>`);
});

app.get('/', (req, res) => res.json({ name: 'RIP Hack Key Server', version: '3.0', status: 'online' }));

app.listen(PORT, () => console.log(`[RIP Hack] Сервер ключей запущен на порту ${PORT}`));
