// server.js
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Multer untuk upload script (file .lua / .txt) =================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024 // 2 MB
  }
});

// ===== Upstash / KV config =========================================

const KV_URL = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const hasKV = !!(KV_URL && KV_TOKEN);

/**
 * Call REST API KV.
 * pathPart: "GET/key", "INCR/key", "SET/key/value", dst.
 * Return: data.result (kalau ada) atau null.
 */
async function kvRequest(pathPart) {
  if (!hasKV || typeof fetch === 'undefined') return null;

  const url = `${KV_URL}/${pathPart}`;
  try {
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${KV_TOKEN}`
      }
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error('KV error', res.status, text);
      return null;
    }

    const data = await res.json().catch(() => null);
    if (data && Object.prototype.hasOwnProperty.call(data, 'result')) {
      return data.result;
    }
    return null;
  } catch (err) {
    console.error('KV request failed:', err);
    return null;
  }
}

function kvPath(cmd, ...segments) {
  const encoded = segments.map((s) => encodeURIComponent(String(s)));
  return `${cmd}/${encoded.join('/')}`;
}

async function kvGet(key) {
  return kvRequest(kvPath('GET', key));
}
async function kvSet(key, value) {
  return kvRequest(kvPath('SET', key, value));
}
async function kvIncr(key) {
  return kvRequest(kvPath('INCR', key));
}
async function kvSAdd(key, member) {
  return kvRequest(kvPath('SADD', key, member));
}
async function kvSCard(key) {
  return kvRequest(kvPath('SCARD', key));
}

async function kvGetInt(key) {
  const result = await kvGet(key);
  if (result == null) return 0;
  const n = parseInt(result, 10);
  return Number.isNaN(n) ? 0 : n;
}

/**
 * Sinkronisasi uses/users manual dari Admin ke KV.
 */
async function syncScriptCountersToKV(script) {
  if (!hasKV) return;
  const baseKey = `exhub:script:${script.id}`;
  try {
    await Promise.all([
      kvSet(`${baseKey}:uses`, String(script.uses || 0)),
      kvSet(`${baseKey}:users`, String(script.users || 0))
    ]);
  } catch (e) {
    console.error('syncScriptCountersToKV error:', e);
  }
}

// ===== Paths untuk seed JSON lokal (dev only) ======================

const SCRIPTS_PATH = path.join(__dirname, 'config', 'scripts.json');
const REDEEMED_PATH = path.join(__dirname, 'config', 'redeemed-keys.json');
// file untuk menyimpan data tracking eksekusi user (fallback lokal)
const EXEC_USERS_PATH = path.join(__dirname, 'config', 'exec-users.json');

// direktori & KV key untuk body script (raw Lua/txt)
const SCRIPTS_RAW_DIR = path.join(__dirname, 'scripts-raw');
const KV_SCRIPTS_META_KEY = 'exhub:scripts-meta';
const KV_REDEEMED_KEY = 'exhub:redeemed-keys';
// key KV untuk data tracking eksekusi user
const KV_EXEC_USERS_KEY = 'exhub:exec-users';
// prefix KV untuk body script
const KV_SCRIPT_BODY_PREFIX = 'exhub:script-body:';

// file & dir untuk Private Raw Files
const RAW_FILES_PATH = path.join(__dirname, 'config', 'raw-files.json');
const RAW_FILES_DIR = path.join(__dirname, 'private-raw');
const KV_RAW_FILES_META_KEY = 'exhub:raw-files-meta';
const KV_RAW_BODY_PREFIX = 'exhub:raw-body:';

// ---- helper file lokal (fallback) ---------------------------------

function loadScriptsFromFile() {
  try {
    if (!fs.existsSync(SCRIPTS_PATH)) return [];
    const raw = fs.readFileSync(SCRIPTS_PATH, 'utf8');
    if (!raw.trim()) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load scripts.json (file):', err);
    return [];
  }
}

function saveScriptsToFile(scripts) {
  try {
    const dir = path.dirname(SCRIPTS_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(SCRIPTS_PATH, JSON.stringify(scripts, null, 2), 'utf8');
  } catch (err) {
    // Di Vercel biasanya read-only, jadi wajar kalau gagal.
    console.error('Failed to save scripts.json (file):', err);
  }
}

function loadRedeemedFromFile() {
  try {
    if (!fs.existsSync(REDEEMED_PATH)) return [];
    const raw = fs.readFileSync(REDEEMED_PATH, 'utf8');
    if (!raw.trim()) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load redeemed-keys.json (file):', err);
    return [];
  }
}

function saveRedeemedToFile(list) {
  try {
    const dir = path.dirname(REDEEMED_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(REDEEMED_PATH, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save redeemed-keys.json (file):', err);
  }
}

// file helper untuk exec-users (tracking per user/script/hwid)

function loadExecUsersFromFile() {
  try {
    if (!fs.existsSync(EXEC_USERS_PATH)) return [];
    const raw = fs.readFileSync(EXEC_USERS_PATH, 'utf8');
    if (!raw.trim()) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load exec-users.json (file):', err);
    return [];
  }
}

function saveExecUsersToFile(list) {
  try {
    const dir = path.dirname(EXEC_USERS_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(EXEC_USERS_PATH, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save exec-users.json (file):', err);
  }
}

// file helper untuk raw-files meta

function loadRawFilesFromFile() {
  try {
    if (!fs.existsSync(RAW_FILES_PATH)) return [];
    const raw = fs.readFileSync(RAW_FILES_PATH, 'utf8');
    if (!raw.trim()) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load raw-files.json (file):', err);
    return [];
  }
}

function saveRawFilesToFile(list) {
  try {
    const dir = path.dirname(RAW_FILES_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(RAW_FILES_PATH, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save raw-files.json (file):', err);
  }
}

// helper untuk nama file safe (hindari karakter aneh)
function safeScriptFileName(scriptId) {
  return String(scriptId).replace(/[^a-zA-Z0-9._-]/g, '_');
}

function ensureScriptsRawDir() {
  try {
    if (!fs.existsSync(SCRIPTS_RAW_DIR)) {
      fs.mkdirSync(SCRIPTS_RAW_DIR, { recursive: true });
    }
  } catch (err) {
    console.error('Failed to ensure scripts-raw dir:', err);
  }
}

function ensureRawFilesDir() {
  try {
    if (!fs.existsSync(RAW_FILES_DIR)) {
      fs.mkdirSync(RAW_FILES_DIR, { recursive: true });
    }
  } catch (err) {
    console.error('Failed to ensure private-raw dir:', err);
  }
}

// ---- helper utama (KV dulu, baru file) ----------------------------

async function loadScripts() {
  if (hasKV) {
    const raw = await kvGet(KV_SCRIPTS_META_KEY);
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        console.error('Failed to parse scripts meta from KV:', e);
      }
    }
    // Belum ada di KV → seed dari file
    const seeded = loadScriptsFromFile();
    try {
      await kvSet(KV_SCRIPTS_META_KEY, JSON.stringify(seeded));
    } catch (e) {
      console.error('Failed to seed scripts meta to KV:', e);
    }
    return seeded;
  }
  return loadScriptsFromFile();
}

async function saveScripts(scripts) {
  const json = JSON.stringify(scripts);
  if (hasKV) {
    try {
      await kvSet(KV_SCRIPTS_META_KEY, json);
    } catch (e) {
      console.error('Failed to save scripts meta to KV:', e);
    }
  }
  // best-effort untuk dev lokal
  saveScriptsToFile(scripts);
}

async function loadRedeemedKeys() {
  if (hasKV) {
    const raw = await kvGet(KV_REDEEMED_KEY);
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        console.error('Failed to parse redeemed keys from KV:', e);
      }
    }
  }
  return loadRedeemedFromFile();
}

async function saveRedeemedKeys(list) {
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_REDEEMED_KEY, json);
    } catch (e) {
      console.error('Failed to save redeemed keys to KV:', e);
    }
  }
  saveRedeemedToFile(list);
}

// helper utama untuk exec-users (tracking user/player)

async function loadExecUsers() {
  if (hasKV) {
    const raw = await kvGet(KV_EXEC_USERS_KEY);
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        console.error('Failed to parse exec users from KV:', e);
      }
    }
    // Seed dari file kalau KV belum punya
    const seeded = loadExecUsersFromFile();
    try {
      await kvSet(KV_EXEC_USERS_KEY, JSON.stringify(seeded));
    } catch (e) {
      console.error('Failed to seed exec users to KV:', e);
    }
    return seeded;
  }
  return loadExecUsersFromFile();
}

async function saveExecUsers(list) {
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_EXEC_USERS_KEY, json);
    } catch (e) {
      console.error('Failed to save exec users to KV:', e);
    }
  }
  saveExecUsersToFile(list);
}

// helper utama untuk raw-files meta

async function loadRawFiles() {
  if (hasKV) {
    const raw = await kvGet(KV_RAW_FILES_META_KEY);
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        console.error('Failed to parse raw files from KV:', e);
      }
    }
    // seed dari file kalau KV belum punya data
    const seeded = loadRawFilesFromFile();
    try {
      await kvSet(KV_RAW_FILES_META_KEY, JSON.stringify(seeded));
    } catch (e) {
      console.error('Failed to seed raw files to KV:', e);
    }
    return seeded;
  }
  return loadRawFilesFromFile();
}

async function saveRawFiles(list) {
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_RAW_FILES_META_KEY, json);
    } catch (e) {
      console.error('Failed to save raw files to KV:', e);
    }
  }
  saveRawFilesToFile(list);
}

// ---- helper body script (raw) -------------------------------------

/**
 * Ambil body script:
 * 1) Dari KV (exhub:script-body:<id>)
 * 2) Fallback file dev lokal (scripts-raw/<id>.lua)
 * 3) Fallback legacy file di /scripts sesuai scriptFile
 */
async function loadScriptBody(script) {
  if (!script || !script.id) return null;

  // 1) KV
  if (hasKV) {
    try {
      const kvKey = KV_SCRIPT_BODY_PREFIX + String(script.id);
      const raw = await kvGet(kvKey);
      if (raw && typeof raw === 'string' && raw.trim() !== '') {
        return raw;
      }
    } catch (err) {
      console.error('Failed to load script body from KV:', err);
    }
  }

  // 2) File lokal /scripts-raw
  try {
    ensureScriptsRawDir();
    const fileName = safeScriptFileName(script.id) + '.lua';
    const localPath = path.join(SCRIPTS_RAW_DIR, fileName);
    if (fs.existsSync(localPath)) {
      return fs.readFileSync(localPath, 'utf8');
    }
  } catch (err) {
    console.error('Failed to load script body from local file:', err);
  }

  // 3) Legacy file di /scripts
  try {
    if (script.scriptFile) {
      const legacyPath = path.join(__dirname, 'scripts', script.scriptFile);
      if (fs.existsSync(legacyPath)) {
        return fs.readFileSync(legacyPath, 'utf8');
      }
    }
  } catch (err) {
    console.error('Failed to load script body from legacy path:', err);
  }

  return null;
}

/**
 * Simpan body script:
 * - Simpan di KV (utama, untuk production)
 * - Best-effort simpan juga di /scripts-raw (dev lokal)
 */
async function saveScriptBody(scriptId, body) {
  if (!scriptId) return;
  const strBody = String(body ?? '');

  // 1) KV
  if (hasKV) {
    try {
      const kvKey = KV_SCRIPT_BODY_PREFIX + String(scriptId);
      await kvSet(kvKey, strBody);
    } catch (err) {
      console.error('Failed to save script body to KV:', err);
    }
  }

  // 2) File lokal (dev only)
  try {
    ensureScriptsRawDir();
    const fileName = safeScriptFileName(scriptId) + '.lua';
    const localPath = path.join(SCRIPTS_RAW_DIR, fileName);
    fs.writeFileSync(localPath, strBody, 'utf8');
  } catch (err) {
    console.error('Failed to save script body to local file:', err);
  }
}

// ---- helper body untuk Private Raw Files --------------------------

async function loadRawBody(rawId) {
  if (!rawId) return null;

  // 1) KV
  if (hasKV) {
    try {
      const kvKey = KV_RAW_BODY_PREFIX + String(rawId);
      const raw = await kvGet(kvKey);
      if (raw && typeof raw === 'string' && raw.trim() !== '') {
        return raw;
      }
    } catch (err) {
      console.error('Failed to load raw body from KV:', err);
    }
  }

  // 2) File lokal /private-raw
  try {
    ensureRawFilesDir();
    const base = safeScriptFileName(rawId);
    const exts = ['.lua', '.txt', '.raw'];
    for (const ext of exts) {
      const filePath = path.join(RAW_FILES_DIR, base + ext);
      if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8');
      }
    }
  } catch (err) {
    console.error('Failed to load raw body from local file:', err);
  }

  return null;
}

async function saveRawBody(rawId, body) {
  if (!rawId) return;
  const strBody = String(body ?? '');

  // 1) KV
  if (hasKV) {
    try {
      const kvKey = KV_RAW_BODY_PREFIX + String(rawId);
      await kvSet(kvKey, strBody);
    } catch (err) {
      console.error('Failed to save raw body to KV:', err);
    }
  }

  // 2) File lokal /private-raw
  try {
    ensureRawFilesDir();
    const base = safeScriptFileName(rawId);
    const filePath = path.join(RAW_FILES_DIR, base + '.lua');
    fs.writeFileSync(filePath, strBody, 'utf8');
  } catch (err) {
    console.error('Failed to save raw body to local file:', err);
  }
}

async function removeRawBody(rawId) {
  if (!rawId) return;

  // KV: cukup set kosong (karena akses raw link pakai meta rawFiles, body orphan tidak akan terpakai)
  if (hasKV) {
    try {
      const kvKey = KV_RAW_BODY_PREFIX + String(rawId);
      await kvSet(kvKey, '');
    } catch (err) {
      console.error('Failed to clear raw body from KV:', err);
    }
  }

  // File lokal: hapus kalau ada
  try {
    ensureRawFilesDir();
    const base = safeScriptFileName(rawId);
    ['.lua', '.txt', '.raw'].forEach((ext) => {
      const filePath = path.join(RAW_FILES_DIR, base + ext);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    });
  } catch (err) {
    console.error('Failed to remove raw body local file:', err);
  }
}

// ---- stats helpers ------------------------------------------------

function computeStats(scripts) {
  const totalGames = scripts.length;
  const totalExecutions = scripts.reduce((acc, s) => acc + (s.uses || 0), 0);
  const totalUsers = scripts.reduce((acc, s) => acc + (s.users || 0), 0);
  return { totalGames, totalExecutions, totalUsers };
}

/**
 * Build stats lengkap untuk Admin Dashboard berdasarkan:
 * - scripts meta (loadScripts + hydrateScriptsWithKV)
 * - exec-users (hasil /api/exec)
 * period: '24h' | '7d' | '30d' | 'all'
 *
 * Return { stats, scripts }
 */
async function buildAdminStats(period) {
  const now = new Date();
  const MS_24H = 24 * 60 * 60 * 1000;
  const MS_7D = 7 * MS_24H;
  const MS_30D = 30 * MS_24H;

  function parseDateSafe(iso) {
    if (!iso) return null;
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function inSelectedPeriod(entry) {
    if (period === 'all' || !period) return true;
    const d = parseDateSafe(entry.lastExecuteAt);
    if (!d) return false;
    const diff = now - d;
    if (diff < 0) return false;
    if (period === '24h') return diff <= MS_24H;
    if (period === '7d') return diff <= MS_7D;
    if (period === '30d') return diff <= MS_30D;
    return true;
  }

  // 1) scripts + KV
  let scripts = await loadScripts();
  scripts = await hydrateScriptsWithKV(scripts);

  // 2) exec-users dari KV/file
  const execUsers = await loadExecUsers();

  const totalScripts = scripts.length;
  const totalGames = scripts.length;

  const uniqueUsersSet = new Set();
  const uniqueHwidsSet = new Set();
  const active24hUsers = new Set();

  let totalExecLifetime = 0;
  let executions24h = 0;

  execUsers.forEach((u) => {
    const totalExec = u.totalExecutes || 0;
    totalExecLifetime += totalExec;

    if (u.userId) uniqueUsersSet.add(String(u.userId));
    if (u.hwid) uniqueHwidsSet.add(String(u.hwid));

    const d = parseDateSafe(u.lastExecuteAt);
    if (d) {
      const diff = now - d;
      if (diff >= 0 && diff <= MS_24H) {
        executions24h += totalExec;
        if (u.userId) active24hUsers.add(String(u.userId));
      }
    }
  });

  const filteredExec = execUsers.filter(inSelectedPeriod);

  const totalUsers = uniqueUsersSet.size;
  const uniqueHwids = uniqueHwidsSet.size;
  const activeUsers24h = active24hUsers.size;

  const avgExecPerUser = totalUsers
    ? Number((totalExecLifetime / totalUsers).toFixed(1))
    : 0;
  const avgExecPerHwid = uniqueHwids
    ? Number((totalExecLifetime / uniqueHwids).toFixed(1))
    : 0;

  function timeAgoString(dateStr) {
    const d = parseDateSafe(dateStr);
    if (!d) return '-';
    const diffMs = now - d;
    if (diffMs < 0) return '-';
    const sec = Math.floor(diffMs / 1000);
    if (sec < 60) return `${sec}s lalu`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m lalu`;
    const h = Math.floor(min / 60);
    if (h < 48) return `${h}j lalu`;
    const day = Math.floor(h / 24);
    return `${day}h lalu`;
  }

  // 3) recentExecutions
  const recentExecutions = filteredExec
    .slice()
    .sort((a, b) => {
      const da = parseDateSafe(a.lastExecuteAt) || 0;
      const db = parseDateSafe(b.lastExecuteAt) || 0;
      return db - da;
    })
    .slice(0, 100)
    .map((u) => {
      const d = parseDateSafe(u.lastExecuteAt);
      const scriptMeta = scripts.find((s) => s.id === u.scriptId) || {};
      return {
        timeAgo: timeAgoString(u.lastExecuteAt),
        executedAtIso: u.lastExecuteAt || null,
        executedAtHuman: d ? d.toLocaleString('id-ID') : u.lastExecuteAt || '',
        scriptId: u.scriptId,
        scriptName: scriptMeta.name || u.scriptId || '-',
        userId: u.userId,
        username: u.username || null,
        displayName: u.displayName || null,
        hwid: u.hwid || null,
        executorUse: u.executorUse || null,
        key: u.keyToken || null,
        executeCount: u.clientExecuteCount || u.totalExecutes || 1,
        mapName: u.mapName || null,
        placeId: u.placeId || null,
        serverId: u.serverId || null
      };
    });

  // 4) Top Scripts
  const scriptMap = new Map();
  execUsers.forEach((u) => {
    const id = u.scriptId || 'unknown';
    const cur = scriptMap.get(id) || {
      id,
      executions: 0,
      name: id,
      gameName: ''
    };
    cur.executions += u.totalExecutes || 0;
    scriptMap.set(id, cur);
  });
  scripts.forEach((s) => {
    const cur = scriptMap.get(s.id);
    if (cur) {
      cur.name = s.name || s.id;
      cur.gameName = s.gameName || '';
    }
  });
  const topScripts = Array.from(scriptMap.values())
    .sort((a, b) => b.executions - a.executions)
    .slice(0, 10);

  // 5) Top Users
  const userMap = new Map();
  execUsers.forEach((u) => {
    if (!u.userId) return;
    const id = String(u.userId);
    const cur = userMap.get(id) || {
      userId: id,
      username: u.username || '',
      displayName: u.displayName || '',
      executions: 0
    };
    cur.executions += u.totalExecutes || 0;
    if (u.username) cur.username = u.username;
    if (u.displayName) cur.displayName = u.displayName;
    userMap.set(id, cur);
  });
  const topUsers = Array.from(userMap.values())
    .sort((a, b) => b.executions - a.executions)
    .slice(0, 10);

  // 6) Top HWID
  const hwidMap = new Map();
  execUsers.forEach((u) => {
    if (!u.hwid) return;
    const id = String(u.hwid);
    const cur = hwidMap.get(id) || {
      hwid: id,
      lastUsername: u.username || '',
      executions: 0
    };
    cur.executions += u.totalExecutes || 0;
    if (u.username) cur.lastUsername = u.username;
    hwidMap.set(id, cur);
  });
  const topHwids = Array.from(hwidMap.values())
    .sort((a, b) => b.executions - a.executions)
    .slice(0, 10);

  // 7) Loader Users list (list semua player)
  const loaderUsers = execUsers
    .slice()
    .sort((a, b) => {
      const da = parseDateSafe(a.lastExecuteAt) || 0;
      const db = parseDateSafe(b.lastExecuteAt) || 0;
      return db - da;
    })
    .map((u) => {
      const scriptMeta = scripts.find((s) => s.id === u.scriptId) || {};
      return {
        key: u.key || `${u.scriptId}:${u.userId}:${u.hwid}`,
        scriptId: u.scriptId,
        scriptName: scriptMeta.name || u.scriptId || '-',
        userId: u.userId,
        username: u.username || '',
        displayName: u.displayName || '',
        hwid: u.hwid || '',
        executorUse: u.executorUse || '',
        totalExecutes: u.totalExecutes || 0,
        lastExecuteAt: u.lastExecuteAt || '',
        lastIp: u.lastIp || '',
        keyToken: u.keyToken || null,
        keyCreatedAt: u.keyCreatedAt || null,
        keyExpiresAt: u.keyExpiresAt || null
      };
    });

  const stats = {
    period: period || '24h',
    totalGames,
    totalScripts,
    totalExecutions: totalExecLifetime,
    executions24h,
    totalUsers,
    activeUsers24h,
    uniqueHwids,
    avgExecPerUser,
    avgExecPerHwid,
    recentExecutions,
    topScripts,
    topUsers,
    topHwids,
    loaderUsers
  };

  return { stats, scripts };
}

/**
 * Ambil uses/users dari KV untuk setiap script.
 */
async function hydrateScriptsWithKV(scripts) {
  if (!hasKV) return scripts;

  await Promise.all(
    scripts.map(async (s) => {
      const baseKey = `exhub:script:${s.id}`;
      s.uses = await kvGetInt(`${baseKey}:uses`);
      s.users = await kvGetInt(`${baseKey}:users`);
    })
  );

  return scripts;
}

/**
 * Tambah counter uses dan users unik (IP-based) di KV ketika loader dipanggil.
 */
async function incrementCountersKV(script, req) {
  if (!hasKV) return;

  const baseKey = `exhub:script:${script.id}`;
  const usesKey = `${baseKey}:uses`;
  const ipSetKey = `${baseKey}:ips`;
  const usersKey = `${baseKey}:users`;

  // 1) INCR uses
  kvIncr(usesKey).catch((err) => console.error('KV INCR error:', err));

  // 2) unique users berdasarkan IP
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown';

  if (!ip || ip === 'unknown') return;

  try {
    await kvSAdd(ipSetKey, ip);
    const count = await kvSCard(ipSetKey);
    if (count != null) {
      await kvSet(usersKey, String(count));
    }
  } catch (err) {
    console.error('KV user counter error:', err);
  }
}

// ===================================================================
// View engine & static files
// ===================================================================

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Parser body:
// - urlencoded untuk form admin / get-key
// - json untuk API (misalnya /api/exec)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  cookieSession({
    name: 'session',
    keys: [process.env.SESSION_SECRET || 'dev-secret'],
    maxAge: 24 * 60 * 60 * 1000
  })
);

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.redirect('/admin/login');
}

// ===================================================================
// Public pages
// ===================================================================

app.get('/', async (req, res) => {
  let scripts = await loadScripts();
  scripts = await hydrateScriptsWithKV(scripts);
  const stats = computeStats(scripts);

  res.render('index', {
    stats,
    scripts
  });
});

app.get('/scripts', async (req, res) => {
  let scripts = await loadScripts();
  scripts = await hydrateScriptsWithKV(scripts);
  const stats = computeStats(scripts);

  res.render('scripts', {
    scripts,
    stats
  });
});

// Get Key page
app.get('/get-key', (req, res) => {
  res.render('get-key', { result: null });
});

// Backend Redeem Key
app.post('/get-key/redeem', async (req, res) => {
  const rawKey = (req.body.key || '').trim().toUpperCase();
  const keyPattern = /^EXHUB-[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$/;

  let status = 'error';
  let message = '';

  if (!rawKey) {
    message = 'Key tidak boleh kosong.';
  } else if (!keyPattern.test(rawKey)) {
    message = 'Format key tidak valid. Gunakan format EXHUB-XXX-XXX-XXX.';
  } else {
    const redeemedList = await loadRedeemedKeys();
    const existing = redeemedList.find((k) => k.key === rawKey);

    if (existing) {
      status = 'error';
      message = 'Key ini sudah pernah diredeem sebelumnya.';
    } else {
      const ip =
        (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
        req.socket.remoteAddress ||
        'unknown';

      redeemedList.push({
        key: rawKey,
        redeemedAt: new Date().toISOString(),
        ip
      });

      await saveRedeemedKeys(redeemedList);

      status = 'success';
      message = 'Key berhasil diredeem. Terima kasih telah menggunakan ExHub.';
    }
  }

  return res.render('get-key', {
    result: { status, message }
  });
});

// ===================================================================
// Loader API
// ===================================================================

app.get('/api/script/:id', async (req, res) => {
  const scripts = await loadScripts();
  const script = scripts.find((s) => s.id === req.params.id);

  // snippet loader yang akan ditampilkan di api-404.ejs
  const loaderSnippet = `loadstring(game:HttpGet("https://excc-webs.vercel.app/api/script/${req.params.id}", true))()`;

  // Script tidak terdaftar
  if (!script) {
    return res.status(404).render('api-404', {
      scriptId: req.params.id,
      loaderSnippet,
      reason: 'not_found'
    });
  }

  // Jika status "down" → paksa mati (maintenance / disable)
  if (script.status === 'down') {
    return res.status(503).render('api-404', {
      scriptId: script.id,
      loaderSnippet,
      reason: 'down'
    });
  }

  const expectedKey = process.env.LOADER_KEY;
  const loaderKey = req.headers['x-loader-key'];

  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const isRobloxUA = ua.includes('roblox');

  const hasValidHeader = expectedKey && loaderKey === expectedKey;

  // Kalau bukan Roblox & tidak punya header valid → forbidden page
  if (!hasValidHeader && !isRobloxUA) {
    return res.status(403).render('api-404', {
      scriptId: script.id,
      loaderSnippet,
      reason: 'forbidden'
    });
  }

  try {
    const content = await loadScriptBody(script);
    if (!content) {
      console.error('Script body not found for id:', script.id);
      return res.status(500).send('Server error (script body missing).');
    }

    // update meta uses (untuk dev lokal)
    script.uses = (script.uses || 0) + 1;
    await saveScripts(scripts);

    // update counter di KV
    try {
      await incrementCountersKV(script, req);
    } catch (e) {
      console.error('incrementCountersKV failed:', e);
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send(content);
  } catch (err) {
    console.error('Failed to serve /api/script:', err);
    return res.status(500).send('Server error.');
  }
});

// ===================================================================
// API tracking eksekusi per user/player
// ===================================================================

/**
 * Endpoint yang dipanggil dari loader / script Roblox untuk melaporkan eksekusi.
 */
app.post('/api/exec', async (req, res) => {
  try {
    const {
      scriptId,
      userId,
      username,
      displayName,
      hwid,
      executorUse,
      executeCount,
      clientExecuteCount,
      key,
      Key,
      createdAt,
      expiresAt,
      mapName,
      placeId,
      serverId
    } = req.body || {};

    if (!scriptId || !userId || !hwid) {
      return res.status(400).json({
        error: 'missing_fields',
        required: ['scriptId', 'userId', 'hwid']
      });
    }

    // normalisasi executeCount (boleh kirim executeCount atau clientExecuteCount)
    let execCountNum = null;
    const rawExecCount =
      executeCount !== undefined && executeCount !== null
        ? executeCount
        : clientExecuteCount;

    if (rawExecCount !== undefined && rawExecCount !== null) {
      const n = parseInt(rawExecCount, 10);
      if (!Number.isNaN(n)) {
        execCountNum = n;
      }
    }

    // normalisasi key (boleh "key" atau "Key")
    const keyToken = key || Key || null;

    // createdAt & expiresAt (bisa ISO string atau timestamp dari work.ink)
    const createdAtStr =
      createdAt !== undefined && createdAt !== null ? String(createdAt) : null;
    const expiresAtStr =
      expiresAt !== undefined && expiresAt !== null ? String(expiresAt) : null;

    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket.remoteAddress ||
      'unknown';

    let execUsers = await loadExecUsers();
    const compositeKey = `${String(scriptId)}:${String(userId)}:${String(
      hwid
    )}`;
    const now = new Date().toISOString();

    let entry = execUsers.find((u) => u.key === compositeKey);

    if (!entry) {
      entry = {
        key: compositeKey,
        scriptId: String(scriptId),
        userId: String(userId),
        username: username || null,
        displayName: displayName || null,
        hwid: String(hwid),
        executorUse: executorUse || null,
        clientExecuteCount: execCountNum,
        keyToken: keyToken || null,
        keyCreatedAt: createdAtStr || null,
        keyExpiresAt: expiresAtStr || null,
        firstExecuteAt: now,
        lastExecuteAt: now,
        lastIp: ip,
        totalExecutes: 1,
        mapName: mapName || null,
        placeId: placeId || null,
        serverId: serverId || null
      };
      execUsers.push(entry);
    } else {
      // Update info terbaru
      entry.username = username || entry.username;
      entry.displayName = displayName || entry.displayName;
      entry.lastExecuteAt = now;
      entry.lastIp = ip;
      entry.totalExecutes = (entry.totalExecutes || 0) + 1;

      if (executorUse && executorUse !== '') {
        entry.executorUse = executorUse;
      }

      if (execCountNum != null) {
        entry.clientExecuteCount = execCountNum;
      }

      if (keyToken) {
        entry.keyToken = keyToken;
      }

      if (createdAtStr) {
        entry.keyCreatedAt = createdAtStr;
      }

      if (expiresAtStr) {
        entry.keyExpiresAt = expiresAtStr;
      }

      if (mapName) {
        entry.mapName = mapName;
      }
      if (placeId) {
        entry.placeId = placeId;
      }
      if (serverId) {
        entry.serverId = serverId;
      }
    }

    await saveExecUsers(execUsers);

    return res.json({
      ok: true,
      received: {
        scriptId,
        userId,
        username,
        displayName,
        hwid,
        executorUse,
        executeCount: execCountNum,
        key: keyToken,
        createdAt: createdAtStr,
        expiresAt: expiresAtStr,
        mapName,
        placeId,
        serverId
      }
    });
  } catch (err) {
    console.error('Failed to handle /api/exec:', err);
    return res.status(500).json({ error: 'exec_error' });
  }
});

/**
 * GET /api/exec
 * Endpoint sederhana untuk melihat data exec-users (debug / monitoring).
 */
app.get('/api/exec', async (req, res) => {
  try {
    const execUsers = await loadExecUsers();
    return res.json({ data: execUsers });
  } catch (err) {
    console.error('Failed to load exec users (GET /api/exec):', err);
    return res.status(500).json({ error: 'exec_users_error' });
  }
});

// ===================================================================
// API stats untuk live update di UI
// ===================================================================

app.get('/api/stats', async (req, res) => {
  try {
    let scripts = await loadScripts();
    scripts = await hydrateScriptsWithKV(scripts);
    const stats = computeStats(scripts);

    res.json({
      stats,
      scripts: scripts.map((s) => ({
        id: s.id,
        uses: s.uses || 0,
        users: s.users || 0
      }))
    });
  } catch (err) {
    console.error('Failed to build /api/stats:', err);
    res.status(500).json({ error: 'stats_error' });
  }
});

// ===================================================================
// Admin Auth & Dashboard
// ===================================================================

app.get('/admin/login', (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.redirect('/admin');
  }
  res.render('admin-login', { error: null });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  const ADMIN_USER = process.env.ADMIN_USER || 'admin';
  const ADMIN_PASS = process.env.ADMIN_PASS || 'password';

  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }

  return res.status(401).render('admin-login', {
    error: 'Username / password salah.'
  });
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session = null;
  res.redirect('/');
});

// Dashboard utama
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const period = req.query.period || '24h';
    const { stats, scripts } = await buildAdminStats(period);
    const rawFiles = await loadRawFiles();

    res.render('admin-dashboard', {
      scripts,
      stats,
      keyCheck: null,
      userSearch: null,
      rawFiles
    });
  } catch (err) {
    console.error('Error rendering /admin dashboard:', err);
    return res.status(500).send('Admin dashboard error.');
  }
});

// Key Checker (search key / username / userId di data exec)
app.get('/admin/key-check', requireAdmin, async (req, res) => {
  try {
    const period = req.query.period || 'all';
    const rawQ = (req.query.q || '').trim();

    const { stats, scripts } = await buildAdminStats(period);
    const rawFiles = await loadRawFiles();

    let keyCheck = null;

    if (rawQ) {
      const qLower = rawQ.toLowerCase();
      const loaderUsers = stats.loaderUsers || [];

      const matches = loaderUsers.filter((u) => {
        if (!u) return false;
        if (u.keyToken && String(u.keyToken).toLowerCase().includes(qLower)) {
          return true;
        }
        if (u.username && u.username.toLowerCase().includes(qLower)) {
          return true;
        }
        if (u.displayName && u.displayName.toLowerCase().includes(qLower)) {
          return true;
        }
        if (u.userId && String(u.userId).includes(rawQ)) {
          return true;
        }
        return false;
      });

      keyCheck = {
        query: rawQ,
        period,
        total: matches.length,
        matches: matches.slice(0, 200)
      };
    } else {
      keyCheck = {
        query: '',
        period,
        total: 0,
        matches: []
      };
    }

    res.render('admin-dashboard', {
      scripts,
      stats,
      keyCheck,
      userSearch: null,
      rawFiles
    });
  } catch (err) {
    console.error('Error rendering /admin/key-check:', err);
    return res.status(500).send('Key check error.');
  }
});

// Quick Search Username/UserId – pakai API Roblox
app.get('/admin/search/user', requireAdmin, async (req, res) => {
  const q = (req.query.q || '').trim();
  const period = req.query.period || '24h';

  try {
    const { stats, scripts } = await buildAdminStats(period);
    const rawFiles = await loadRawFiles();

    const userSearch = {
      query: q,
      result: null,
      error: null
    };

    if (!q) {
      userSearch.error = 'Masukkan username atau userId Roblox.';
      return res.render('admin-dashboard', {
        scripts,
        stats,
        keyCheck: null,
        userSearch,
        rawFiles
      });
    }

    let robloxUser = null;

    // Jika full numeric -> treat sebagai UserId, pakai users.roblox.com/v1/users/{id}
    if (/^\d+$/.test(q)) {
      try {
        const resp = await fetch(`https://users.roblox.com/v1/users/${q}`);
        if (!resp.ok) {
          throw new Error(`Roblox users API error: ${resp.status}`);
        }
        const data = await resp.json();
        robloxUser = {
          id: data.id,
          username: data.name,
          displayName: data.displayName,
          created: data.created,
          description: data.description || ''
        };
      } catch (err) {
        console.error('Roblox users/{id} error:', err);
        userSearch.error = 'UserId tidak ditemukan di Roblox.';
      }
    } else {
      // Kalau bukan full numeric -> treat sebagai Username, pakai usernames/users
      try {
        const resp = await fetch('https://users.roblox.com/v1/usernames/users', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            usernames: [q],
            excludeBannedUsers: false
          })
        });

        if (!resp.ok) {
          throw new Error(`Roblox usernames API error: ${resp.status}`);
        }

        const data = await resp.json();
        if (data && Array.isArray(data.data) && data.data.length > 0) {
          const u = data.data[0];
          robloxUser = {
            id: u.id,
            username: u.name,
            displayName: u.displayName,
            created: null,
            description: ''
          };

          // Lengkapi data created/description lewat /v1/users/{id}
          try {
            const detailResp = await fetch(
              `https://users.roblox.com/v1/users/${u.id}`
            );
            if (detailResp.ok) {
              const detail = await detailResp.json();
              robloxUser.created = detail.created;
              robloxUser.description = detail.description || '';
            }
          } catch (detailErr) {
            console.error('Roblox user detail error:', detailErr);
          }
        } else {
          userSearch.error = 'Username tidak ditemukan di Roblox.';
        }
      } catch (err) {
        console.error('Roblox usernames/users error:', err);
        userSearch.error = 'Gagal menghubungi API Roblox (username).';
      }
    }

    // Ambil avatar image
    if (robloxUser && robloxUser.id != null) {
      let avatarUrl = null;
      try {
        const thumbResp = await fetch(
          `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${robloxUser.id}&size=150x150&format=Png&isCircular=false`
        );
        if (thumbResp.ok) {
          const thumbData = await thumbResp.json();
          if (
            thumbData &&
            Array.isArray(thumbData.data) &&
            thumbData.data[0] &&
            thumbData.data[0].imageUrl
          ) {
            avatarUrl = thumbData.data[0].imageUrl;
          }
        }
      } catch (err) {
        console.error('Roblox avatar thumbnail error:', err);
      }

      userSearch.result = {
        id: robloxUser.id,
        username: robloxUser.username,
        displayName: robloxUser.displayName,
        created: robloxUser.created,
        description: robloxUser.description,
        avatarUrl,
        profileUrl: `https://www.roblox.com/users/${robloxUser.id}/profile`
      };
    }

    if (!userSearch.result && !userSearch.error) {
      userSearch.error = 'User tidak ditemukan di Roblox.';
    }

    return res.render('admin-dashboard', {
      scripts,
      stats,
      keyCheck: null,
      userSearch,
      rawFiles
    });
  } catch (err) {
    console.error('Error in /admin/search/user:', err);
    // Kalau gagal total, set error umum
    const fallback = await buildAdminStats('24h').catch(() => null);
    const stats = fallback ? fallback.stats : { period: '24h' };
    const scripts = fallback ? fallback.scripts : [];
    const userSearch = {
      query: q,
      result: null,
      error: 'Terjadi kesalahan saat mencari user Roblox.'
    };
    let rawFiles = [];
    try {
      rawFiles = await loadRawFiles();
    } catch (e) {
      rawFiles = [];
    }
    return res.render('admin-dashboard', {
      scripts,
      stats,
      keyCheck: null,
      userSearch,
      rawFiles
    });
  }
});

// Delete satu entry player (scriptId:userId:hwid)
app.post('/admin/exec-users/delete', requireAdmin, async (req, res) => {
  try {
    const entryKey = (req.body.entryKey || '').trim();
    const back = req.get('Referrer') || '/admin';

    if (!entryKey) {
      return res.redirect(back);
    }

    let list = await loadExecUsers();
    const before = list.length;
    list = list.filter((u) => u.key !== entryKey);

    if (list.length !== before) {
      await saveExecUsers(list);
    }

    return res.redirect(back);
  } catch (err) {
    console.error('Failed to delete exec user entry:', err);
    const back = req.get('Referrer') || '/admin';
    return res.redirect(back);
  }
});

// Update script (metadata + optional upload body)
app.post(
  '/admin/scripts/:id',
  requireAdmin,
  upload.single('scriptUpload'),
  async (req, res) => {
    const scripts = await loadScripts();
    const idx = scripts.findIndex((s) => s.id === req.params.id);
    if (idx === -1) return res.redirect('/admin');

    const s = scripts[idx];

    s.name = req.body.name || s.name;
    s.gameName = req.body.gameName || s.gameName;
    s.version = req.body.version || s.version;
    s.status = req.body.status || s.status;
    s.isFree = req.body.isFree === 'on';
    s.uses = parseInt(req.body.uses || s.uses || 0, 10);
    s.users = parseInt(req.body.users || s.users || 0, 10);
    s.thumbnail = req.body.thumbnail || s.thumbnail;
    s.scriptFile = req.body.scriptFile || s.scriptFile;

    // Body script dari textarea / upload file
    const scriptBodyText = (req.body.scriptBody || '').trim();
    let uploadedBody = null;

    if (req.file && req.file.buffer && req.file.size > 0) {
      uploadedBody = req.file.buffer.toString('utf8');
    }

    // Prioritas: kalau textarea diisi, pakai itu; kalau kosong tapi ada file, pakai file
    let finalBody = null;
    if (uploadedBody) {
      finalBody = uploadedBody;
    }
    if (scriptBodyText) {
      finalBody = scriptBodyText;
    }

    if (finalBody != null) {
      try {
        await saveScriptBody(s.id, finalBody);
      } catch (err) {
        console.error('Failed to save script body (update):', err);
      }
    }

    await saveScripts(scripts);

    try {
      await syncScriptCountersToKV(s);
    } catch (e) {
      console.error('syncScriptCountersToKV failed:', e);
    }

    res.redirect('/admin');
  }
);

// Tambah script baru (metadata + optional upload body)
app.post(
  '/admin/scripts',
  requireAdmin,
  upload.single('scriptUpload'),
  async (req, res) => {
    const scripts = await loadScripts();
    const id = (req.body.id || '').trim();

    if (!id || scripts.some((s) => s.id === id)) {
      return res.redirect('/admin');
    }

    const newScript = {
      id,
      name: req.body.name || id,
      gameName: req.body.gameName || '',
      version: req.body.version || 'v1.0.0',
      isFree: req.body.isFree === 'on',
      status: req.body.status || 'working',
      uses: parseInt(req.body.uses || 0, 10),
      users: parseInt(req.body.users || 0, 10),
      thumbnail: req.body.thumbnail || '',
      scriptFile: req.body.scriptFile || ''
    };

    scripts.push(newScript);
    await saveScripts(scripts);

    // Simpan body script kalau ada (textarea / upload)
    const scriptBodyText = (req.body.scriptBody || '').trim();
    let uploadedBody = null;
    if (req.file && req.file.buffer && req.file.size > 0) {
      uploadedBody = req.file.buffer.toString('utf8');
    }

    let finalBody = null;
    if (uploadedBody) finalBody = uploadedBody;
    if (scriptBodyText) finalBody = scriptBodyText;

    if (finalBody != null) {
      try {
        await saveScriptBody(newScript.id, finalBody);
      } catch (err) {
        console.error('Failed to save script body (new):', err);
      }
    }

    try {
      await syncScriptCountersToKV(newScript);
    } catch (e) {
      console.error('syncScriptCountersToKV (new) failed:', e);
    }

    res.redirect('/admin');
  }
);

// ===================================================================
// Admin API untuk Private Raw Files
// ===================================================================

// Update / delete existing private raw file
app.post(
  '/admin/raw-files/:id',
  requireAdmin,
  upload.single('rawUpload'),
  async (req, res) => {
    const id = (req.params.id || '').trim();
    if (!id) return res.redirect('/admin#raw-files');

    let rawFiles = await loadRawFiles();
    const idx = rawFiles.findIndex((f) => f.id === id);
    if (idx === -1) return res.redirect('/admin#raw-files');

    const action = (req.body._action || '').trim();

    if (action === 'delete') {
      // Hapus meta + body
      rawFiles = rawFiles.filter((f) => f.id !== id);
      await saveRawFiles(rawFiles);
      try {
        await removeRawBody(id);
      } catch (err) {
        console.error('Failed to remove raw body on delete:', err);
      }
      return res.redirect('/admin#raw-files');
    }

    const file = rawFiles[idx];
    file.name = req.body.name || file.name || '';
    file.note = req.body.note || file.note || '';

    const now = new Date().toISOString();

    const bodyText = req.body.body || '';
    let uploadedBody = null;
    if (req.file && req.file.buffer && req.file.size > 0) {
      uploadedBody = req.file.buffer.toString('utf8');
    }

    let finalBody = null;
    if (uploadedBody) {
      finalBody = uploadedBody;
    }
    if (bodyText.trim() !== '') {
      finalBody = bodyText;
    }

    if (finalBody != null) {
      try {
        await saveRawBody(id, finalBody);
        file.preview = finalBody.slice(0, 800);
      } catch (err) {
        console.error('Failed to save raw body (update):', err);
      }
      file.updatedAt = now;
    } else {
      // Tidak ada perubahan body, tetap update timestamp minimal sekali
      file.updatedAt = file.updatedAt || now;
    }

    await saveRawFiles(rawFiles);

    return res.redirect('/admin#raw-files');
  }
);

// Tambah private raw file baru
app.post(
  '/admin/raw-files',
  requireAdmin,
  upload.single('rawUpload'),
  async (req, res) => {
    const id = (req.body.id || '').trim();
    if (!id) return res.redirect('/admin#raw-files');

    let rawFiles = await loadRawFiles();
    if (rawFiles.some((f) => f.id === id)) {
      // ID sudah dipakai
      return res.redirect('/admin#raw-files');
    }

    const now = new Date().toISOString();

    const bodyText = req.body.body || '';
    let uploadedBody = null;
    if (req.file && req.file.buffer && req.file.size > 0) {
      uploadedBody = req.file.buffer.toString('utf8');
    }

    let finalBody = '';
    if (uploadedBody) finalBody = uploadedBody;
    if (bodyText.trim() !== '') finalBody = bodyText;

    const newFile = {
      id,
      name: req.body.name || '',
      note: req.body.note || '',
      updatedAt: now,
      preview: finalBody ? finalBody.slice(0, 800) : ''
    };

    rawFiles.push(newFile);
    await saveRawFiles(rawFiles);

    if (finalBody) {
      try {
        await saveRawBody(id, finalBody);
      } catch (err) {
        console.error('Failed to save raw body (new):', err);
      }
    }

    return res.redirect('/admin#raw-files');
  }
);

// ===================================================================
// Admin API untuk melihat data exec-users
// ===================================================================

app.get('/admin/api/exec-users', requireAdmin, async (req, res) => {
  try {
    const execUsers = await loadExecUsers();
    res.json({ data: execUsers });
  } catch (err) {
    console.error('Failed to load exec users:', err);
    res.status(500).json({ error: 'exec_users_error' });
  }
});

app.get('/admin/api/exec-users/:scriptId', requireAdmin, async (req, res) => {
  try {
    const execUsers = await loadExecUsers();
    const filtered = execUsers.filter(
      (u) => u.scriptId === String(req.params.scriptId)
    );
    res.json({ data: filtered });
  } catch (err) {
    console.error('Failed to load exec users by scriptId:', err);
    res.status(500).json({ error: 'exec_users_error' });
  }
});

// ===================================================================
// Public endpoint untuk Private Raw Links: /:id.raw
// ===================================================================

app.get('/:rawId.raw', async (req, res, next) => {
  try {
    const rawId = (req.params.rawId || '').trim();
    if (!rawId) return next();

    const rawFiles = await loadRawFiles();
    const fileMeta = rawFiles.find((f) => f.id === rawId);
    if (!fileMeta) {
      // Tidak terdaftar sebagai private raw file → biarkan 404 fallback
      return next();
    }

    const body = await loadRawBody(rawId);
    if (!body) {
      return res.status(404).send('Raw file not found.');
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send(body);
  } catch (err) {
    console.error('Failed to serve raw link:', err);
    return res.status(500).send('Server error (raw).');
  }
});

// ===================================================================
// Fallback 404 untuk route lain
// ===================================================================

app.use(async (req, res) => {
  let scripts = await loadScripts();
  scripts = await hydrateScriptsWithKV(scripts);
  const stats = computeStats(scripts);
  res.status(404).render('index', {
    stats,
    scripts
  });
});

// ===================================================================
// Export untuk Vercel / listen untuk lokal
// ===================================================================

// Jika dijalankan langsung: `node server.js` (lokal)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`ExHub site running on http://localhost:${PORT}`);
  });
}

// Selalu export app untuk Vercel
module.exports = app;
