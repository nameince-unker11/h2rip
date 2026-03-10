const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'riphack_admin_2026';
const PORT = process.env.PORT || 3000;
const KEYS_TXT_FILE = path.join(__dirname, '..', 'keys.txt');

// ===== MongoDB Atlas URI =====
// Установи через переменную окружения MONGODB_URI или замени строку ниже
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.mongodb.net/riphack?retryWrites=true&w=majority';

// ===== Mongoose Схемы =====
const keySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, index: true },
  hwid: { type: String, default: '' },
  activatedAt: { type: Date, default: null }
}, { timestamps: true });

const settingSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  value: { type: String, default: '' }
});

const Key = mongoose.model('Key', keySchema);
const Setting = mongoose.model('Setting', settingSchema);

// ===== Автоимпорт ключей из keys.txt =====
async function importKeysFromTxt() {
  try {
    if (!fs.existsSync(KEYS_TXT_FILE)) return;
    const content = fs.readFileSync(KEYS_TXT_FILE, 'utf8').trim();
    if (!content) return;
    const lines = content.split(/\r?\n/).filter(l => l.trim());
    let imported = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // Формат: KEY или KEY:HWID
      const parts = trimmed.split(':');
      let keyStr, hwid = '';
      if (parts.length >= 4) {
        // Формат RIP-XXXX-XXXX-XXXX:HWID — ключ содержит дефисы, HWID после последнего двоеточия
        const lastColon = trimmed.lastIndexOf(':');
        const possibleHwid = trimmed.substring(lastColon + 1);
        if (/^[A-F0-9]{8}-[A-F0-9]{8}$/i.test(possibleHwid)) {
          keyStr = trimmed.substring(0, lastColon);
          hwid = possibleHwid;
        } else {
          keyStr = trimmed;
        }
      } else {
        keyStr = trimmed;
      }

      const existing = await Key.findOne({ key: keyStr });
      if (!existing) {
        await Key.create({
          key: keyStr,
          hwid: hwid,
          activatedAt: hwid ? new Date() : null
        });
        imported++;
      } else if (hwid && !existing.hwid) {
        existing.hwid = hwid;
        existing.activatedAt = existing.activatedAt || new Date();
        await existing.save();
        imported++;
      }
    }
    if (imported > 0) {
      console.log(`[RIP Hack] Импортировано ${imported} ключей из keys.txt`);
    }
  } catch (e) {
    console.error('[RIP Hack] Ошибка импорта keys.txt:', e.message);
  }
}

// ===== Загрузить серверный ключ =====
async function getServerKey() {
  const setting = await Setting.findOne({ name: 'serverKey' });
  if (setting && setting.value) return setting.value;
  // Попробовать прочитать из файла server_key.txt
  const SERVER_KEY_FILE = path.join(__dirname, 'server_key.txt');
  try {
    const sk = fs.readFileSync(SERVER_KEY_FILE, 'utf8').trim();
    if (sk.length >= 32) {
      await Setting.findOneAndUpdate(
        { name: 'serverKey' },
        { value: sk },
        { upsert: true }
      );
      return sk;
    }
  } catch { }
  return '';
}

// ===== PUBLIC: Активация ключа =====
app.post('/validate', async (req, res) => {
  try {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ status: 'invalid' });

    const entry = await Key.findOne({ key });
    if (!entry) return res.json({ status: 'invalid' });

    if (!entry.hwid) {
      entry.hwid = hwid;
      entry.activatedAt = new Date();
      await entry.save();
      return res.json({ status: 'activated' });
    }
    if (entry.hwid === hwid) return res.json({ status: 'ok' });
    return res.json({ status: 'bound' });
  } catch (e) {
    console.error('[validate]', e.message);
    res.status(500).json({ status: 'error' });
  }
});

// ===== PUBLIC: Проверка ключа =====
app.post('/check', async (req, res) => {
  try {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false });

    const entry = await Key.findOne({ key });
    const isValid = !!(entry && entry.hwid === hwid);
    return res.json({ valid: isValid });
  } catch (e) {
    console.error('[check]', e.message);
    res.status(500).json({ valid: false });
  }
});

// ===== ADMIN: Авторизация =====
function adminAuth(req, res, next) {
  const pass = req.headers['x-admin-password'] || req.body.password;
  if (pass !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Unauthorized' });
  next();
}

// Получить все ключи
app.get('/admin/keys', adminAuth, async (req, res) => {
  try {
    const keysRaw = await Key.find({}).lean();
    const keys = keysRaw.map(d => ({
      key: d.key,
      hwid: (d.hwid && d.hwid.length > 0) ? d.hwid : null,
      activatedAt: d.activatedAt || null
    }));
    // Сортировка: сначала активные (с HWID), потом свободные
    keys.sort((a, b) => {
      if (a.hwid && !b.hwid) return -1;
      if (!a.hwid && b.hwid) return 1;
      return 0;
    });
    const serverKey = await getServerKey();
    res.json({ keys, serverKey: serverKey || null });
  } catch (e) {
    console.error('[admin/keys]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// Добавить один ключ
app.post('/admin/add', adminAuth, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'Key required' });

    const exists = await Key.findOne({ key });
    if (exists) return res.json({ status: 'exists' });

    await Key.create({ key, hwid: '', activatedAt: null });
    res.json({ status: 'added', key });
  } catch (e) {
    console.error('[admin/add]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// Сгенерировать ключи (формат: RIP-XXXXXXXX-XXXXXXXX-XXXXXXXX)
app.post('/admin/generate', adminAuth, async (req, res) => {
  try {
    const count = Math.min(req.body.count || 1, 100);
    const generated = [];
    const bulkOps = [];
    for (let i = 0; i < count; i++) {
      const buf = crypto.randomBytes(12);
      const part1 = buf.slice(0, 4).toString('hex').toUpperCase();
      const part2 = buf.slice(4, 8).toString('hex').toUpperCase();
      const part3 = buf.slice(8, 12).toString('hex').toUpperCase();
      const key = `RIP-${part1}-${part2}-${part3}`;
      bulkOps.push({ key, hwid: '', activatedAt: null });
      generated.push(key);
    }
    await Key.insertMany(bulkOps, { ordered: false });
    res.json({ status: 'ok', generated });
  } catch (e) {
    console.error('[admin/generate]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// Удалить ключ
app.post('/admin/delete', adminAuth, async (req, res) => {
  try {
    const { key } = req.body;
    const result = await Key.deleteOne({ key });
    if (result.deletedCount === 0) return res.json({ status: 'not_found' });
    res.json({ status: 'deleted' });
  } catch (e) {
    console.error('[admin/delete]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// Сбросить HWID ключа
app.post('/admin/reset', adminAuth, async (req, res) => {
  try {
    const { key } = req.body;
    const entry = await Key.findOne({ key });
    if (!entry) return res.json({ status: 'not_found' });
    entry.hwid = '';
    entry.activatedAt = null;
    await entry.save();
    res.json({ status: 'reset' });
  } catch (e) {
    console.error('[admin/reset]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// Установить серверный ключ дешифрования
app.post('/admin/server-key', adminAuth, async (req, res) => {
  try {
    const { server_key } = req.body;
    if (!server_key || server_key.length < 32) {
      return res.status(400).json({ error: 'server_key должен быть hex-строкой из 32+ символов' });
    }
    if (!/^[0-9a-fA-F]+$/.test(server_key)) {
      return res.status(400).json({ error: 'server_key должен содержать только hex-символы' });
    }
    const normalizedKey = server_key.toLowerCase();
    await Setting.findOneAndUpdate(
      { name: 'serverKey' },
      { value: normalizedKey },
      { upsert: true }
    );
    // Также сохранить в файл (для совместимости)
    const SERVER_KEY_FILE = path.join(__dirname, 'server_key.txt');
    fs.writeFileSync(SERVER_KEY_FILE, normalizedKey);
    res.json({ status: 'ok', message: 'Серверный ключ обновлён' });
  } catch (e) {
    console.error('[admin/server-key]', e.message);
    res.status(500).json({ error: 'Database error' });
  }
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
.db-badge{display:inline-block;background:#50dc8220;color:#50dc82;border:1px solid #50dc8240;padding:3px 10px;border-radius:8px;font-size:11px;font-weight:600;margin-left:8px}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>&#9670; RIP HACK</h1>
    <div class="sub">АДМИН-ПАНЕЛЬ &bull; FORTRESS v3.0 <span class="db-badge">MongoDB Atlas</span></div>
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
    el.textContent='\u2705 '+sk;
    el.classList.remove('missing');
  }else{
    el.textContent='\u26a0\ufe0f Не установлен — DLL не расшифруется!';
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
    <td class="hwid">\${k.hwid||'\u2014'}</td>
    <td style="color:#78789a;font-size:12px">\${k.activatedAt?new Date(k.activatedAt).toLocaleString():'\u2014'}</td>
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

app.get('/', (req, res) => res.json({ name: 'RIP Hack Key Server', version: '3.0', db: 'MongoDB Atlas', status: 'online' }));

// ===== Запуск сервера =====
async function startServer() {
  try {
    console.log('[RIP Hack] Подключение к MongoDB Atlas...');
    await mongoose.connect(MONGODB_URI);
    console.log('[RIP Hack] ✅ MongoDB Atlas подключена!');

    // Импорт ключей из keys.txt при старте
    await importKeysFromTxt();

    app.listen(PORT, () => console.log(`[RIP Hack] Сервер ключей запущен на порту ${PORT}`));
  } catch (e) {
    console.error('[RIP Hack] ❌ Ошибка подключения к MongoDB:', e.message);
    process.exit(1);
  }
}

startServer();
