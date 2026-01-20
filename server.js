// server.js
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
// Waktu start app (untuk uptime API bot)
const PROCESS_START_TIME = Date.now();

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
async function kvSMembers(key) {
  return kvRequest(kvPath('SMEMBERS', key));
}
async function kvSRem(key, member) {
  return kvRequest(kvPath('SREM', key, member));
}
async function kvDel(key) {
  return kvRequest(kvPath('DEL', key));
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
  const baseKey = `noctyra:script:${script.id}`;
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
// file untuk menyimpan daftar key yang dihapus manual (admin)
const DELETED_PATH = path.join(__dirname, 'config', 'deleted-keys.json');
// file untuk menyimpan data tracking eksekusi user (fallback lokal)
const EXEC_USERS_PATH = path.join(__dirname, 'config', 'exec-users.json');

// direktori & KV key untuk body script (raw Lua/txt)
const SCRIPTS_RAW_DIR = path.join(__dirname, 'scripts-raw');
const KV_SCRIPTS_META_KEY = 'noctyra:scripts-meta';
const KV_REDEEMED_KEY = 'noctyra:redeemed-keys';
const KV_DELETED_KEYS_KEY = 'noctyra:deleted-keys';
// key KV untuk data tracking eksekusi user (format legacy: array besar)
const KV_EXEC_USERS_KEY = 'noctyra:exec-users';
// format baru: per-entry + index
const KV_EXEC_ENTRY_PREFIX = 'noctyra:exec-user:'; // noctyra:exec-user:<entryKey>
const KV_EXEC_INDEX_KEY = 'noctyra:exec-users:index'; // set berisi entryKey
// prefix KV untuk body script
const KV_SCRIPT_BODY_PREFIX = 'noctyra:script-body:';

// file & dir untuk Private Raw Files
const RAW_FILES_PATH = path.join(__dirname, 'config', 'raw-files.json');
const RAW_FILES_DIR = path.join(__dirname, 'private-raw');
const KV_RAW_FILES_META_KEY = 'noctyra:raw-files-meta';
const KV_RAW_BODY_PREFIX = 'noctyra:raw-body:';

// file & dir untuk konfigurasi site & web-keys (Generate Key)
const SITE_CONFIG_PATH = path.join(__dirname, 'config', 'site-config.json');
const WEB_KEYS_PATH = path.join(__dirname, 'config', 'web-keys.json');
const KV_SITE_CONFIG_KEY = 'noctyra:site-config';
const KV_WEB_KEYS_KEY = 'noctyra:web-keys';

// Konfigurasi halaman generatekey (Luarmor-style)
const MAX_KEYS_PER_IP = parseInt(process.env.MAX_KEYS_PER_IP || '10', 10);
const DEFAULT_KEY_HOURS = parseInt(process.env.DEFAULT_KEY_HOURS || '24', 10);

// Wajibkan “selesai iklan” sebelum bisa ambil key (per 1 key).
// Set di env: REQUIRE_ADS_CHECKPOINT=1
const REQUIRE_ADS_CHECKPOINT = process.env.REQUIRE_ADS_CHECKPOINT === '1';

// Linkvertise utama untuk tombol Start.
// Bisa dioverride via ENV: GENERATEKEY_ADS_URL
const GENERATEKEY_ADS_URL =
  process.env.GENERATEKEY_ADS_URL ||
  'https://linkvertise.com/2995260/0xLAgWUZzCns?o=sharing';

// Maksimal umur checkpoint Start → Ads (default 10 menit = 600000 ms)
const ADS_CHECKPOINT_MAX_AGE_MS = parseInt(
  process.env.ADS_CHECKPOINT_MAX_AGE_MS || '600000',
  10
);

// ---- helper umum (IP, UA, scripts+KV) -----------------------------

function getClientIp(req) {
  const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (xff) return xff;
  if (req.socket && req.socket.remoteAddress) {
    return req.socket.remoteAddress;
  }
  return 'unknown';
}

function isRobloxUserAgent(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return ua.includes('roblox');
}

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

// file helper untuk deleted-keys (key yang dihapus manual)
function loadDeletedFromFile() {
  try {
    if (!fs.existsSync(DELETED_PATH)) return [];
    const raw = fs.readFileSync(DELETED_PATH, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    return [];
  } catch (err) {
    console.error('Failed to load deleted-keys.json (file):', err);
    return [];
  }
}

function saveDeletedToFile(list) {
  try {
    const dir = path.dirname(DELETED_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(DELETED_PATH, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save deleted-keys.json (file):', err);
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

// file helper untuk site-config (defaultKeyHours, maxKeysPerIp)
function loadSiteConfigFromFile() {
  try {
    if (!fs.existsSync(SITE_CONFIG_PATH)) return {};
    const raw = fs.readFileSync(SITE_CONFIG_PATH, 'utf8');
    if (!raw.trim()) return {};
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      return parsed;
    }
    return {};
  } catch (err) {
    console.error('Failed to load site-config.json (file):', err);
    return {};
  }
}

function saveSiteConfigToFile(cfg) {
  try {
    const dir = path.dirname(SITE_CONFIG_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(SITE_CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save site-config.json (file):', err);
  }
}

// file helper untuk web-keys (generatekey)
function loadWebKeysFromFile() {
  try {
    if (!fs.existsSync(WEB_KEYS_PATH)) return [];
    const raw = fs.readFileSync(WEB_KEYS_PATH, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    return [];
  } catch (err) {
    console.error('Failed to load web-keys.json (file):', err);
    return [];
  }
}

function saveWebKeysToFile(list) {
  try {
    const dir = path.dirname(WEB_KEYS_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(WEB_KEYS_PATH, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save web-keys.json (file):', err);
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

// helper utama untuk deleted-keys (key yang dihapus manual admin)
async function loadDeletedKeys() {
  if (hasKV) {
    try {
      const raw = await kvGet(KV_DELETED_KEYS_KEY);
      if (raw && typeof raw === 'string') {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (err) {
      console.error('Failed to load deleted keys from KV:', err);
    }
  }
  return loadDeletedFromFile();
}

async function saveDeletedKeys(list) {
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_DELETED_KEYS_KEY, json);
    } catch (err) {
      console.error('Failed to save deleted keys to KV:', err);
    }
  }
  saveDeletedToFile(list);
}

// helper utama untuk exec-users (tracking user/player)
/**
 * Format baru (KV):
 * - Index: SADD noctyra:exec-users:index <entryKey>
 * - Entry: SET noctyra:exec-user:<entryKey> "<json>"
 * Di local dev / tanpa KV tetap pakai file exec-users.json (array).
 */
async function loadExecUsers() {
  // Prefer data di KV (format baru per-entry)
  if (hasKV) {
    try {
      const index = await kvSMembers(KV_EXEC_INDEX_KEY);
      if (Array.isArray(index) && index.length > 0) {
        const results = [];
        for (const entryKey of index) {
          if (!entryKey) continue;
          const raw = await kvGet(KV_EXEC_ENTRY_PREFIX + entryKey);
          if (!raw || typeof raw !== 'string' || !raw.trim()) continue;
          try {
            const obj = JSON.parse(raw);
            if (obj && typeof obj === 'object') {
              obj.key = obj.key || entryKey;
              results.push(obj);
            }
          } catch (e) {
            console.error(
              'Failed to parse exec-user from KV for key',
              entryKey,
              e
            );
          }
        }
        if (results.length) {
          return results;
        }
      }
    } catch (err) {
      console.error('Failed to load exec-users from KV index:', err);
    }

    // Fallback legacy: 1 key berisi array besar
    try {
      const rawLegacy = await kvGet(KV_EXEC_USERS_KEY);
      if (rawLegacy && typeof rawLegacy === 'string') {
        const parsed = JSON.parse(rawLegacy);
        if (Array.isArray(parsed)) {
          return parsed;
        }
      }
    } catch (e) {
      console.error('Failed to load legacy exec-users from KV:', e);
    }
  }

  // Terakhir: file lokal (dev)
  return loadExecUsersFromFile();
}

async function saveExecUsers(list) {
  // Sekarang hanya digunakan sebagai fallback / dev.
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_EXEC_USERS_KEY, json);
    } catch (e) {
      console.error('Failed to save exec users to KV (legacy key):', e);
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

// helper utama untuk site-config (defaultKeyHours, maxKeysPerIp)
async function loadSiteConfig() {
  const base = {
    defaultKeyHours: DEFAULT_KEY_HOURS,
    maxKeysPerIp: MAX_KEYS_PER_IP
  };

  if (hasKV) {
    try {
      const raw = await kvGet(KV_SITE_CONFIG_KEY);
      if (raw && typeof raw === 'string') {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          return { ...base, ...parsed };
        }
      }
    } catch (err) {
      console.error('Failed to load site-config from KV:', err);
    }
  }

  const fileCfg = loadSiteConfigFromFile();
  const merged = { ...base, ...fileCfg };

  if (hasKV) {
    try {
      await kvSet(KV_SITE_CONFIG_KEY, JSON.stringify(merged));
    } catch (err) {
      console.error('Failed to seed site-config to KV:', err);
    }
  }

  return merged;
}

async function saveSiteConfig(cfg) {
  const merged = {
    defaultKeyHours: Number.isFinite(cfg.defaultKeyHours)
      ? cfg.defaultKeyHours
      : DEFAULT_KEY_HOURS,
    maxKeysPerIp: Number.isFinite(cfg.maxKeysPerIp)
      ? cfg.maxKeysPerIp
      : MAX_KEYS_PER_IP
  };

  const json = JSON.stringify(merged);
  if (hasKV) {
    try {
      await kvSet(KV_SITE_CONFIG_KEY, json);
    } catch (err) {
      console.error('Failed to save site-config to KV:', err);
    }
  }
  saveSiteConfigToFile(merged);
}

// helper utama untuk web-keys (Generate Key)
async function loadWebKeys() {
  if (hasKV) {
    try {
      const raw = await kvGet(KV_WEB_KEYS_KEY);
      if (raw && typeof raw === 'string') {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (err) {
      console.error('Failed to load web-keys from KV:', err);
    }
  }
  return loadWebKeysFromFile();
}

async function saveWebKeys(list) {
  const json = JSON.stringify(list);
  if (hasKV) {
    try {
      await kvSet(KV_WEB_KEYS_KEY, json);
    } catch (err) {
      console.error('Failed to save web-keys to KV:', err);
    }
  }
  saveWebKeysToFile(list);
}

// ---- helper body script (raw) -------------------------------------

/**
 * Ambil body script:
 * 1) Dari KV (noctyra:script-body:<id>)
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

// ---- util token & time-left ---------------------------------------

function generateRandomToken(length = 32) {
  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(length);
  let token = '';
  for (let i = 0; i < length; i++) {
    const idx = bytes[i] % alphabet.length;
    token += alphabet[idx];
  }
  return token;
}

function formatTimeLeft(diffMs) {
  if (diffMs == null || diffMs <= 0) return 'Expired';
  const totalSeconds = Math.floor(diffMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const pad = (n) => (n < 10 ? '0' + n : String(n));
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

// Format waktu WITA + WIB untuk label Admin Key
const DATE_TIME_FORMAT_OPTIONS_TZ = {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false
};

function formatDualTimeLabelMs(ms) {
  if (!ms || !Number.isFinite(ms)) return '-';
  try {
    const date = new Date(ms);

    const fmtWIB = new Intl.DateTimeFormat('id-ID', {
      ...DATE_TIME_FORMAT_OPTIONS_TZ,
      timeZone: 'Asia/Jakarta'
    });
    const fmtWITA = new Intl.DateTimeFormat('id-ID', {
      ...DATE_TIME_FORMAT_OPTIONS_TZ,
      timeZone: 'Asia/Makassar'
    });

    const wib = fmtWIB.format(date);
    const wita = fmtWITA.format(date);
    return `${wib} WIB / ${wita} WITA`;
  } catch (err) {
    console.error('formatDualTimeLabelMs error:', err);
    return new Date(ms).toLocaleString('id-ID');
  }
}

// Parser format relatif admin: "HH:MM:SS" atau "1h 10m 20s" → ms absolute (now + durasi)
function parseRelativeExpiresInput(raw, nowMs) {
  if (!raw) return null;
  const str = String(raw).trim();
  if (!str) return null;

  // 1) Format "HH:MM:SS" (contoh: "00:20:20")
  const hhmmss = str.match(/^(\d{1,2}):(\d{1,2}):(\d{1,2})$/);
  if (hhmmss) {
    let h = parseInt(hhmmss[1], 10) || 0;
    let m = parseInt(hhmmss[2], 10) || 0;
    let s = parseInt(hhmmss[3], 10) || 0;

    if (h < 0) h = 0;
    if (m < 0) m = 0;
    if (s < 0) s = 0;

    const totalMs = (h * 3600 + m * 60 + s) * 1000;
    if (totalMs <= 0) return null;

    return nowMs + totalMs;
  }

  // 2) Format lama: "1h 10m 20s", "20m", "30m 5s", dll.
  const re =
    /^\s*(?:(\d+)\s*h(?:hours?)?)?\s*(?:(\d+)\s*m(?:in(?:utes?)?)?)?\s*(?:(\d+)\s*s(?:ec(?:onds?)?)?)?\s*$/i;
  const m2 = str.match(re);
  if (!m2) return null;

  const h2 = m2[1] ? parseInt(m2[1], 10) : 0;
  const min2 = m2[2] ? parseInt(m2[2], 10) : 0;
  const s2 = m2[3] ? parseInt(m2[3], 10) : 0;

  if (Number.isNaN(h2) || Number.isNaN(min2) || Number.isNaN(s2)) return null;

  const totalMs2 = (h2 * 3600 + min2 * 60 + s2) * 1000;
  if (totalMs2 <= 0) return null;

  return nowMs + totalMs2;
}

// ---- stats helpers ------------------------------------------------

function computeStats(scripts) {
  const totalGames = scripts.length;
  const totalExecutions = scripts.reduce((acc, s) => acc + (s.uses || 0), 0);
  const totalUsers = scripts.reduce((acc, s) => acc + (s.users || 0), 0);
  return { totalGames, totalExecutions, totalUsers };
}

// uptime (detik) untuk API bot
function getApiUptimeSeconds() {
  const diffMs = Date.now() - PROCESS_START_TIME;
  if (!Number.isFinite(diffMs) || diffMs < 0) return 0;
  return Math.floor(diffMs / 1000);
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
  const scripts = await loadScriptsHydrated();

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
        serverId: u.serverId || null,
        gameId: u.gameId || null,
        allMapList: Array.isArray(u.allMapList) ? u.allMapList : []
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
        keyExpiresAt: u.keyExpiresAt || null,
        mapName: u.mapName || null,
        placeId: u.placeId || null,
        serverId: u.serverId || null,
        gameId: u.gameId || null,
        allMapList: Array.isArray(u.allMapList) ? u.allMapList : []
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
      const baseKey = `noctyra:script:${s.id}`;
      s.uses = await kvGetInt(`${baseKey}:uses`);
      s.users = await kvGetInt(`${baseKey}:users`);
    })
  );

  return scripts;
}

/**
 * Helper gabungan: load scripts + hydrate KV.
 */
async function loadScriptsHydrated() {
  const scripts = await loadScripts();
  return hydrateScriptsWithKV(scripts);
}

/**
 * Tambah counter uses dan users unik (IP-based) di KV ketika loader dipanggil.
 */
async function incrementCountersKV(script, req) {
  if (!hasKV) return;

  const baseKey = `noctyra:script:${script.id}`;
  const usesKey = `${baseKey}:uses`;
  const ipSetKey = `${baseKey}:ips`;
  const usersKey = `${baseKey}:users`;

  // 1) INCR uses
  kvIncr(usesKey).catch((err) => console.error('KV INCR error:', err));

  // 2) unique users berdasarkan IP
  const ip = getClientIp(req);

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
// Admin – Web Key Manager (helper build data)
// ===================================================================

async function buildWebKeysAdminData() {
  const siteConfig = await loadSiteConfig();
  const defaultKeyHours =
    typeof siteConfig.defaultKeyHours === 'number'
      ? siteConfig.defaultKeyHours
      : DEFAULT_KEY_HOURS;
  const maxKeysPerIp =
    typeof siteConfig.maxKeysPerIp === 'number'
      ? siteConfig.maxKeysPerIp
      : MAX_KEYS_PER_IP;

  const webKeys = await loadWebKeys();
  const nowMs = Date.now();

  const ipMap = new Map();

  for (const k of webKeys) {
    if (!k || !k.token) continue;
    const ip = (k.ip || 'unknown').trim() || 'unknown';
    if (!ipMap.has(ip)) ipMap.set(ip, []);
    ipMap.get(ip).push(k);
  }

  function parseMs(value) {
    if (!value) return 0;
    const t = Date.parse(value);
    return Number.isNaN(t) ? 0 : t;
  }

  function computeExpiresMs(entry, createdMs) {
    let expiresMs = null;
    if (entry.expiresAt) {
      const t = Date.parse(entry.expiresAt);
      if (!Number.isNaN(t)) {
        expiresMs = t;
      }
    }
    if (!expiresMs && createdMs && defaultKeyHours > 0) {
      expiresMs = createdMs + defaultKeyHours * 60 * 60 * 1000;
    }
    return expiresMs;
  }

  const ipStats = [];
  const ipDetails = new Map();

  let totalKeys = 0;
  let activeKeys = 0;

  ipMap.forEach((entries, ip) => {
    let total = 0;
    let active = 0;
    let lastCreatedMs = 0;
    let lastExpiresMs = 0;

    const detailList = [];

    for (const entry of entries) {
      total += 1;
      totalKeys += 1;

      const createdMs = parseMs(entry.createdAt || '');
      const expiresMs = computeExpiresMs(entry, createdMs);

      const expired = !!(expiresMs && expiresMs <= nowMs);
      if (!expired) {
        active += 1;
        activeKeys += 1;
      }

      if (createdMs > lastCreatedMs) lastCreatedMs = createdMs;
      if (expiresMs && expiresMs > lastExpiresMs) lastExpiresMs = expiresMs;

      const diff = expiresMs ? expiresMs - nowMs : null;
      const timeLeftLabel =
        expiresMs && !expired ? formatTimeLeft(diff) : 'Expired';

      detailList.push({
        token: entry.token,
        ip,
        userId: entry.userId || null,
        createdAt: entry.createdAt || '',
        expiresAt: entry.expiresAt || '',
        expiresAtMs: expiresMs || null,
        createdAtLabel: createdMs ? formatDualTimeLabelMs(createdMs) : '-',
        expiresAtLabel: expiresMs ? formatDualTimeLabelMs(expiresMs) : '-',
        timeLeftLabel,
        status: expired ? 'Expired' : 'Active'
      });
    }

    ipDetails.set(ip, detailList);

    ipStats.push({
      ip,
      totalKeys: total,
      activeKeys: active,
      lastCreatedAt:
        lastCreatedMs > 0 ? formatDualTimeLabelMs(lastCreatedMs) : '-',
      lastExpiresAt:
        lastExpiresMs > 0 ? formatDualTimeLabelMs(lastExpiresMs) : '-'
    });
  });

  return {
    ipStats,
    ipDetails,
    totalIpCount: ipStats.length,
    totalKeysCount: totalKeys,
    activeKeysCount: activeKeys,
    defaultKeyHours,
    maxKeysPerIp
  };
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
  const scripts = await loadScriptsHydrated();
  const stats = computeStats(scripts);

  res.render('index', {
    stats,
    scripts
  });
});

app.get('/scripts', async (req, res) => {
  const scripts = await loadScriptsHydrated();
  const stats = computeStats(scripts);

  res.render('scripts', {
    scripts,
    stats
  });
});

// ===================================================================
// Generate Key PAGE (Luarmor-style, strict checkpoint per 1 key)
// ===================================================================

// Step 1: user klik Start → catat checkpoint & userId, lalu redirect ke Linkvertise
app.get('/generatekey/ads-start', async (req, res) => {
  try {
    const ip = getClientIp(req);

    const currentUserId = (req.query.userId || '').trim() || null;
    const now = Date.now();

    // Simpan checkpoint di session (akan dicek saat balik ke ?done=1)
    req.session.adsCheckpoint = {
      startedAt: now,
      ip,
      userId: currentUserId
    };

    return res.redirect(GENERATEKEY_ADS_URL);
  } catch (err) {
    console.error('Failed to handle /generatekey/ads-start:', err);
    const parts = [
      'errorMessage=' +
      encodeURIComponent('Failed to start ads step. Please try again.')
    ];
    const uid = (req.query.userId || '').trim();
    if (uid) parts.push('userId=' + encodeURIComponent(uid));
    const qs = '?' + parts.join('&');
    return res.redirect('/generatekey' + qs);
  }
});

app.get('/generatekey', async (req, res) => {
  try {
    const host = req.get('host') || '';
    const baseUrl = `${req.protocol}://${host}`;

    const ip = getClientIp(req);
    const currentUserId = (req.query.userId || '').trim();

    const siteConfig = await loadSiteConfig();
    const defaultKeyHours =
      typeof siteConfig.defaultKeyHours === 'number'
        ? siteConfig.defaultKeyHours
        : DEFAULT_KEY_HOURS;
    const maxKeysPerIp =
      typeof siteConfig.maxKeysPerIp === 'number'
        ? siteConfig.maxKeysPerIp
        : MAX_KEYS_PER_IP;

    // ===== Load web-keys (Generate Key) tanpa menghapus expired =====
    const webKeys = await loadWebKeys();
    const nowMs = Date.now();

    const myKeys = [];

    for (const k of webKeys) {
      if (!k || !k.token) continue;
      if (k.ip !== ip) continue;

      const createdMs = Date.parse(k.createdAt || '') || 0;
      let expiresMs = null;

      if (k.expiresAt) {
        const t = Date.parse(k.expiresAt);
        if (!Number.isNaN(t)) {
          expiresMs = t;
        }
      }

      if (!expiresMs && defaultKeyHours > 0 && createdMs) {
        expiresMs = createdMs + defaultKeyHours * 60 * 60 * 1000;
      }

      if (!createdMs && !expiresMs) continue;

      const expired = !!(expiresMs && expiresMs <= nowMs);
      const diff = expiresMs ? expiresMs - nowMs : null;

      const status = expired ? 'Expired' : 'Active';
      const timeLeftLabel = expiresMs
        ? expired
          ? 'Expired'
          : formatTimeLeft(diff)
        : '-';

      myKeys.push({
        token: k.token,
        timeLeftLabel,
        status,
        expiresAtMs: expiresMs || null,
        expiresAt: k.expiresAt || null,
        expiresAfter: expiresMs || null
      });
    }

    // ================== BUILD URL START (selalu lewat /generatekey/ads-start) ==================

    const adsParams = [];
    if (currentUserId) {
      adsParams.push('userId=' + encodeURIComponent(currentUserId));
    }
    const adsQs = adsParams.length ? '?' + adsParams.join('&') : '';
    const adsStartUrl = '/generatekey/ads-start' + adsQs;

    // ================== CHECKPOINT IKLAN + VALIDASI ==================

    let allowGenerate = true;
    let headerState = 'start';
    const headerTimerLabel = null;

    if (REQUIRE_ADS_CHECKPOINT) {
      const fromAds =
        req.query.done === '1' ||
        req.query.ok === '1' ||
        req.query.checkpoint === '1' ||
        req.query.ads === '1';

      if (fromAds) {
        const cp = req.session.adsCheckpoint || null;
        const now = Date.now();
        let checkpointValid = false;

        if (cp && typeof cp.startedAt === 'number') {
          const age = now - cp.startedAt;
          if (age >= 0 && age <= ADS_CHECKPOINT_MAX_AGE_MS) {
            checkpointValid = true;
          }
        }

        if (!checkpointValid) {
          const params = [
            'errorMessage=' +
            encodeURIComponent(
              'Checkpoint expired or invalid. Please click Start again from noctyra page.'
            )
          ];
          if (currentUserId) {
            params.push('userId=' + encodeURIComponent(currentUserId));
          }
          const qs = '?' + params.join('&');
          return res.redirect('/generatekey' + qs);
        }

        // checkpoint valid → unlock generateKey sekali
        req.session.generateKeyAdsOk = true;
        req.session.adsCheckpoint = null;

        const params = [];
        if (currentUserId) {
          params.push('userId=' + encodeURIComponent(currentUserId));
        }
        const qs = params.length ? '?' + params.join('&') : '';
        return res.redirect('/generatekey' + qs);
      }

      const sessionOk = !!req.session.generateKeyAdsOk;
      allowGenerate = sessionOk;
      headerState = sessionOk ? 'done' : 'start';
    } else {
      // tanpa checkpoint → langsung boleh generate
      allowGenerate = true;
      headerState = 'done';
    }

    return res.render('generatekey', {
      title: 'noctyra - Generate Key',
      keys: myKeys,
      maxKeys: maxKeysPerIp,
      adsUrl: adsStartUrl, // penting: sekarang ke /generatekey/ads-start
      errorMessage: (req.query.errorMessage || '').trim() || null,
      defaultKeyHours,
      headerState,
      headerTimerLabel,
      allowGenerate,
      keyAction: '/getkey/new',
      renewAction: '/getkey/renew',
      currentUserId,
      baseUrl,
      requestHost: host
    });
  } catch (err) {
    console.error('Failed to render /generatekey:', err);

    let defaultKeyHours = DEFAULT_KEY_HOURS;
    let maxKeys = MAX_KEYS_PER_IP;
    try {
      const cfg = await loadSiteConfig();
      if (typeof cfg.defaultKeyHours === 'number') {
        defaultKeyHours = cfg.defaultKeyHours;
      }
      if (typeof cfg.maxKeysPerIp === 'number') {
        maxKeys = cfg.maxKeysPerIp;
      }
    } catch (e) {
      // ignore
    }

    return res.status(500).render('generatekey', {
      title: 'noctyra - Generate Key',
      keys: [],
      maxKeys,
      adsUrl: '/generatekey/ads-start',
      errorMessage: 'Internal server error.',
      defaultKeyHours,
      headerState: 'start',
      headerTimerLabel: null,
      allowGenerate: !REQUIRE_ADS_CHECKPOINT,
      keyAction: '/getkey/new',
      renewAction: '/getkey/renew',
      currentUserId: '',
      baseUrl: '',
      requestHost: ''
    });
  }
});

// Endpoint untuk benar-benar generate key baru (dipanggil dari tombol "Get A New Key")
app.post('/getkey/new', async (req, res) => {
  try {
    const ip = getClientIp(req);
    const currentUserId = (req.body.userId || '').trim() || '';

    const siteConfig = await loadSiteConfig();
    const defaultKeyHours =
      typeof siteConfig.defaultKeyHours === 'number'
        ? siteConfig.defaultKeyHours
        : DEFAULT_KEY_HOURS;
    const maxKeysPerIp =
      typeof siteConfig.maxKeysPerIp === 'number'
        ? siteConfig.maxKeysPerIp
        : MAX_KEYS_PER_IP;

    // WAJIB: kalau checkpoint diaktifkan, tapi belum ada flag sessionOk → tolak
    if (REQUIRE_ADS_CHECKPOINT && !req.session.generateKeyAdsOk) {
      const parts = [];
      parts.push(
        'errorMessage=' +
        encodeURIComponent('Complete the Start / ads step first.')
      );
      if (currentUserId) {
        parts.push('userId=' + encodeURIComponent(currentUserId));
      }
      const qs = parts.length ? '?' + parts.join('&') : '';
      return res.redirect('/generatekey' + qs);
    }

    let webKeys = await loadWebKeys();
    const nowMs = Date.now();

    let activeForIp = 0;

    for (const k of webKeys) {
      if (!k || !k.token) continue;

      const createdMs = Date.parse(k.createdAt || '') || 0;
      let expiresMs = null;

      if (k.expiresAt) {
        const t = Date.parse(k.expiresAt);
        if (!Number.isNaN(t)) {
          expiresMs = t;
        }
      }

      if (!expiresMs && defaultKeyHours > 0 && createdMs) {
        expiresMs = createdMs + defaultKeyHours * 60 * 60 * 1000;
      }

      if (!createdMs && !expiresMs) continue;

      const expired = !!(expiresMs && expiresMs <= nowMs);

      if (!expired && k.ip === ip) {
        activeForIp += 1;
      }
    }

    if (activeForIp >= maxKeysPerIp) {
      const msg =
        'Limit active keys reached for this IP (' +
        activeForIp +
        '/' +
        maxKeysPerIp +
        ').';
      const params = ['errorMessage=' + encodeURIComponent(msg)];
      if (currentUserId) {
        params.push('userId=' + encodeURIComponent(currentUserId));
      }
      const qs = params.length ? '?' + params.join('&') : '';
      return res.redirect('/generatekey' + qs);
    }

    const existingTokens = new Set(webKeys.map((k) => String(k.token)));
    let token = '';
    do {
      token = generateRandomToken(32);
    } while (existingTokens.has(token));

    const createdAtIso = new Date().toISOString();
    const expiresAtIso = new Date(
      nowMs + defaultKeyHours * 60 * 60 * 1000
    ).toISOString();

    const newEntry = {
      token,
      ip,
      userId: currentUserId || null,
      createdAt: createdAtIso,
      expiresAt: expiresAtIso
    };

    webKeys.push(newEntry);
    await saveWebKeys(webKeys);

    // Setelah BERHASIL ambil 1 key, flag “sudah lewat iklan” direset,
    // sehingga untuk key ke-2 wajib klik Start & selesaikan iklan lagi.
    if (REQUIRE_ADS_CHECKPOINT) {
      req.session.generateKeyAdsOk = false;
      req.session.adsCheckpoint = null;
    }

    const params = [];
    if (currentUserId) {
      params.push('userId=' + encodeURIComponent(currentUserId));
    }
    const qs = params.length ? '?' + params.join('&') : '';
    return res.redirect('/generatekey' + qs);
  } catch (err) {
    console.error('Failed to handle /getkey/new:', err);
    const params = [
      'errorMessage=' + encodeURIComponent('Failed to generate key.')
    ];
    const qs = params.length ? '?' + params.join('&') : '';
    return res.redirect('/generatekey' + qs);
  }
});

// Endpoint Renew key (per IP, dari halaman generatekey)
app.post('/getkey/renew', async (req, res) => {
  try {
    const ip = getClientIp(req);
    const currentUserId = (req.body.userId || '').trim() || '';
    const token = (req.body.token || '').trim();

    const backParams = [];
    if (currentUserId) {
      backParams.push('userId=' + encodeURIComponent(currentUserId));
    }

    if (!token) {
      backParams.push(
        'errorMessage=' + encodeURIComponent('Missing token for renew.')
      );
      const qs = backParams.length ? '?' + backParams.join('&') : '';
      return res.redirect('/generatekey' + qs);
    }

    // WAJIB: kalau checkpoint diaktifkan, tapi belum ada flag sessionOk → tolak Renew
    if (REQUIRE_ADS_CHECKPOINT && !req.session.generateKeyAdsOk) {
      backParams.push(
        'errorMessage=' +
        encodeURIComponent('Complete the Start / ads step first.')
      );
      const qs = backParams.length ? '?' + backParams.join('&') : '';
      return res.redirect('/generatekey' + qs);
    }

    const siteConfig = await loadSiteConfig();
    const defaultKeyHours =
      typeof siteConfig.defaultKeyHours === 'number'
        ? siteConfig.defaultKeyHours
        : DEFAULT_KEY_HOURS;

    let webKeys = await loadWebKeys();
    const nowMs = Date.now();
    const extendMs = defaultKeyHours * 60 * 60 * 1000;

    let changed = false;

    webKeys = webKeys.map((k) => {
      if (!k || !k.token) return k;
      if (String(k.token) !== String(token)) return k;
      // User-route: hanya boleh renew key milik IP yang sama
      if (k.ip !== ip) return k;

      const updated = { ...k };
      const newExpiresMs = nowMs + extendMs;
      updated.expiresAt = new Date(newExpiresMs).toISOString();
      changed = true;
      return updated;
    });

    if (!changed) {
      backParams.push(
        'errorMessage=' +
        encodeURIComponent('Key not found or cannot be renewed.')
      );
      const qs = backParams.length ? '?' + backParams.join('&') : '';
      return res.redirect('/generatekey' + qs);
    }

    await saveWebKeys(webKeys);

    // Setelah Renew sukses, konsumsi juga checkpoint iklan (1x per sesi)
    if (REQUIRE_ADS_CHECKPOINT) {
      req.session.generateKeyAdsOk = false;
      req.session.adsCheckpoint = null;
    }

    const qs = backParams.length ? '?' + backParams.join('&') : '';
    return res.redirect('/generatekey' + qs);
  } catch (err) {
    console.error('Failed to handle /getkey/renew:', err);
    const params = [
      'errorMessage=' + encodeURIComponent('Failed to renew key.')
    ];
    const qs = params.length ? '?' + params.join('&') : '';
    return res.redirect('/generatekey' + qs);
  }
});

// ===================================================================
// Get Key page (lama) – tetap utuh
// ===================================================================

app.get('/get-key', (req, res) => {
  res.render('get-key', { result: null });
});

// Backend Redeem Key
app.post('/get-key/redeem', async (req, res) => {
  const rawKey = (req.body.key || '').trim().toUpperCase();
  const keyPattern = /^noctyra-[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$/;

  let status = 'error';
  let message = '';
  if (!rawKey) {
    message = 'Key tidak boleh kosong.';
  } else if (!keyPattern.test(rawKey)) {
    message = 'Format key tidak valid. Gunakan format noctyra-XXX-XXX-XXX.';
  } else {
    const redeemedList = await loadRedeemedKeys();
    const existing = redeemedList.find((k) => k.key === rawKey);

    if (existing) {
      status = 'error';
      message = 'Key ini sudah pernah diredeem sebelumnya.';
    } else {
      const ip = getClientIp(req);

      redeemedList.push({
        key: rawKey,
        redeemedAt: new Date().toISOString(),
        ip
      });

      await saveRedeemedKeys(redeemedList);

      status = 'success';
      message = 'Key berhasil diredeem. Terima kasih telah menggunakan noctyra.';
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
  const loaderSnippet = `loadstring(game:HttpGet("https://wes-silk.vercel.app/api/script/${req.params.id}", true))()`;

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

  const isRobloxUA = isRobloxUserAgent(req);
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
 * Helper untuk mengisi / mendeduplikasi riwayat map (allMapList)
 * - Tidak ada duplikasi per kombinasi (gameId, placeId, mapName)
 * - Menyimpan daftar unik serverIds per map
 * - serverId di-set ke server terakhir (kompatibilitas UI lama)
 */
function upsertMapHistory(entry, opts) {
  if (!entry || !opts) return;

  const mapName = opts.mapName || null;
  const placeIdRaw = opts.placeId;
  const gameIdRaw = opts.gameId;
  const serverIdRaw = opts.serverId;

  const placeId =
    placeIdRaw !== undefined && placeIdRaw !== null && placeIdRaw !== ''
      ? String(placeIdRaw)
      : null;
  const gameId =
    gameIdRaw !== undefined && gameIdRaw !== null && gameIdRaw !== ''
      ? String(gameIdRaw)
      : null;
  const serverId =
    serverIdRaw !== undefined && serverIdRaw !== null && serverIdRaw !== ''
      ? String(serverIdRaw)
      : null;

  if (!mapName && !placeId && !gameId && !serverId) return;

  const existing = Array.isArray(entry.allMapList) ? entry.allMapList : [];
  const rawList = existing.slice();

  // Masukkan record baru ke rawList, supaya digabung dengan yang lama
  rawList.push({
    mapName,
    placeId,
    gameId,
    serverId
  });

  const mapByKey = new Map();

  rawList.forEach((m) => {
    if (!m) return;

    const mName = m.mapName || null;
    const pId =
      m.placeId !== undefined && m.placeId !== null && m.placeId !== ''
        ? String(m.placeId)
        : null;
    const gId =
      m.gameId !== undefined && m.gameId !== null && m.gameId !== ''
        ? String(m.gameId)
        : null;

    if (!mName && !pId && !gId) return;

    const key = `${gId || ''}|${pId || ''}|${mName || ''}`;

    let target = mapByKey.get(key);
    if (!target) {
      target = {
        mapName: mName,
        placeId: pId,
        gameId: gId,
        serverIds: [],
        serverId: null
      };
      mapByKey.set(key, target);
    }

    const tmpServerIds = [];

    if (Array.isArray(m.serverIds)) {
      m.serverIds.forEach((sid) => {
        if (sid !== undefined && sid !== null && sid !== '') {
          tmpServerIds.push(String(sid));
        }
      });
    }

    if (m.serverId !== undefined && m.serverId !== null && m.serverId !== '') {
      tmpServerIds.push(String(m.serverId));
    }

    tmpServerIds.forEach((sid) => {
      if (!target.serverIds.includes(sid)) {
        target.serverIds.push(sid);
      }
    });

    if (target.serverIds.length) {
      target.serverId = target.serverIds[target.serverIds.length - 1];
    }
  });

  entry.allMapList = Array.from(mapByKey.values());
}

/**
 * Upsert 1 entry exec-user di KV (format baru).
 */
async function upsertExecUserKV(meta) {
  if (!hasKV) return null;

  const {
    scriptId,
    userId,
    username,
    displayName,
    hwid,
    executorUse,
    execCountNum,
    keyToken,
    createdAtStr,
    expiresAtStr,
    ip,
    mapName,
    placeId,
    serverId,
    gameId
  } = meta;

  const compositeKey = `${String(scriptId)}:${String(userId)}:${String(
    hwid
  )}`;
  const nowIso = new Date().toISOString();

  let entry = null;
  try {
    const raw = await kvGet(KV_EXEC_ENTRY_PREFIX + compositeKey);
    if (raw && typeof raw === 'string' && raw.trim() !== '') {
      entry = JSON.parse(raw);
    }
  } catch (err) {
    console.error('Failed to read exec-user from KV:', err);
  }

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
      firstExecuteAt: nowIso,
      lastExecuteAt: nowIso,
      lastIp: ip,
      totalExecutes: 1,
      mapName: mapName || null,
      placeId:
        placeId !== undefined && placeId !== null ? String(placeId) : null,
      serverId: serverId || null,
      gameId:
        gameId !== undefined && gameId !== null ? String(gameId) : null,
      allMapList: []
    };
  } else {
    entry.username = username || entry.username;
    entry.displayName = displayName || entry.displayName;
    entry.lastExecuteAt = nowIso;
    entry.lastIp = ip;
    entry.totalExecutes = (entry.totalExecutes || 0) + 1;

    if (executorUse) entry.executorUse = executorUse;
    if (execCountNum != null) entry.clientExecuteCount = execCountNum;
    if (keyToken) entry.keyToken = keyToken;
    if (createdAtStr) entry.keyCreatedAt = createdAtStr;
    if (expiresAtStr) entry.keyExpiresAt = expiresAtStr;

    if (mapName) entry.mapName = mapName;
    if (placeId !== undefined && placeId !== null) {
      entry.placeId = String(placeId);
    }
    if (serverId) {
      entry.serverId = serverId;
    }
    if (gameId !== undefined && gameId !== null) {
      entry.gameId = String(gameId);
    }

    if (!Array.isArray(entry.allMapList)) {
      entry.allMapList = [];
    }
  }

  // update riwayat map
  upsertMapHistory(entry, { mapName, placeId, serverId, gameId });

  try {
    await kvSet(KV_EXEC_ENTRY_PREFIX + compositeKey, JSON.stringify(entry));
    await kvSAdd(KV_EXEC_INDEX_KEY, compositeKey);
  } catch (err) {
    console.error('Failed to upsert exec-user to KV:', err);
  }

  return entry;
}

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
      serverId,
      gameId
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
      expiresAt !== undefined && expiresAt !== null
        ? String(expiresAt)
        : null;

    const ip = getClientIp(req);

    if (hasKV) {
      await upsertExecUserKV({
        scriptId,
        userId,
        username,
        displayName,
        hwid,
        executorUse,
        execCountNum,
        keyToken,
        createdAtStr,
        expiresAtStr,
        ip,
        mapName,
        placeId,
        serverId,
        gameId
      });
    } else {
      // Fallback local file (dev mode)
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
          placeId:
            placeId !== undefined && placeId !== null ? String(placeId) : null,
          serverId: serverId || null,
          gameId:
            gameId !== undefined && gameId !== null ? String(gameId) : null,
          allMapList: []
        };

        upsertMapHistory(entry, { mapName, placeId, serverId, gameId });
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
        if (placeId !== undefined && placeId !== null) {
          entry.placeId = String(placeId);
        }
        if (serverId) {
          entry.serverId = serverId;
        }
        if (gameId !== undefined && gameId !== null) {
          entry.gameId = String(gameId);
        }

        if (!Array.isArray(entry.allMapList)) {
          entry.allMapList = [];
        }
        upsertMapHistory(entry, { mapName, placeId, serverId, gameId });
      }

      await saveExecUsers(execUsers);
    }

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
        serverId,
        gameId
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
// API isValidate – Luarmor-like JSON (valid/deleted/info)
// ===================================================================

app.get('/api/isValidate/:key', async (req, res) => {
  try {
    const rawKey = (req.params.key || '').trim();
    if (!rawKey) {
      return res.status(400).json({
        valid: false,
        deleted: false,
        info: null
      });
    }

    const normKey = rawKey.toUpperCase();

    const execUsers = await loadExecUsers();
    const redeemedList = await loadRedeemedKeys();
    const webKeys = await loadWebKeys();
    const deletedList = await loadDeletedKeys();
    const siteConfig = await loadSiteConfig();

    const nowMs = Date.now();
    const defaultKeyHours =
      typeof siteConfig.defaultKeyHours === 'number'
        ? siteConfig.defaultKeyHours
        : DEFAULT_KEY_HOURS;

    // Cari data key dari exec-users (keyToken)
    let sourceExec = null;
    for (const u of execUsers) {
      if (!u || !u.keyToken) continue;
      if (String(u.keyToken).toUpperCase() === normKey) {
        sourceExec = u;
        break;
      }
    }

    // Cari entry di web-keys (Generate Key) – ini yang diprioritaskan untuk expiry
    let webEntry = null;
    for (const k of webKeys) {
      if (!k || !k.token) continue;
      if (String(k.token).toUpperCase() === normKey) {
        webEntry = k;
        break;
      }
    }

    // Kalau tidak ketemu di web-keys maupun exec-users → cek redeemed-keys lama
    let redeemed = null;
    if (!webEntry && !sourceExec) {
      for (const k of redeemedList) {
        if (!k || !k.key) continue;
        if (String(k.key).toUpperCase() === normKey) {
          redeemed = k;
          break;
        }
      }
    }

    // Cek apakah pernah dihapus manual melalui Admin
    let deletedEntry = null;
    for (const d of deletedList) {
      if (!d || !d.token) continue;
      if (String(d.token).toUpperCase() === normKey) {
        deletedEntry = d;
        break;
      }
    }

    // Helper konversi ke timestamp ms
    const toMs = (value, fallbackMs) => {
      if (value == null) return fallbackMs;
      if (typeof value === 'number') return value;
      const str = String(value);
      if (/^\d+$/.test(str)) {
        const n = parseInt(str, 10);
        if (!Number.isNaN(n)) return n;
      }
      const d = new Date(str);
      const t = d.getTime();
      if (!Number.isNaN(t)) return t;
      return fallbackMs;
    };

    let valid = false;
    let deleted = false;
    let info = null;

    if (webEntry) {
      // ====== Sumber utama expiry: web-keys (Generate Key) ======
      const createdMs = toMs(webEntry.createdAt, nowMs);

      let expiresMs = null;
      if (webEntry.expiresAfter != null) {
        expiresMs = toMs(webEntry.expiresAfter, null);
      }
      if (expiresMs == null) {
        expiresMs = toMs(webEntry.expiresAt, null);
      }
      if (expiresMs == null && createdMs && defaultKeyHours > 0) {
        expiresMs = createdMs + defaultKeyHours * 60 * 60 * 1000;
      }

      const expired = expiresMs != null && expiresMs <= nowMs;
      valid = !expired;

      let userIdNum = null;
      if (sourceExec && sourceExec.userId != null) {
        const n = Number(sourceExec.userId);
        userIdNum = Number.isNaN(n) ? null : n;
      } else if (webEntry.userId != null) {
        const n = Number(webEntry.userId);
        userIdNum = Number.isNaN(n) ? null : n;
      }

      info = {
        token: normKey,
        createdAt: createdMs,
        byIp:
          (sourceExec && sourceExec.lastIp) ||
          webEntry.ip ||
          '0.0.0.0',
        linkId: webEntry.linkId || null,
        userId: userIdNum,
        expiresAfter: expiresMs
      };
    } else if (sourceExec) {
      // ====== Fallback ke exec-users (key sudah dipakai) ======
      valid = true;

      const createdMs = toMs(sourceExec.keyCreatedAt, nowMs);
      const expiresMs =
        sourceExec.keyExpiresAt != null
          ? toMs(sourceExec.keyExpiresAt, null)
          : null;

      info = {
        token: normKey,
        createdAt: createdMs,
        byIp: sourceExec.lastIp || '0.0.0.0',
        linkId: null,
        userId: sourceExec.userId ? Number(sourceExec.userId) : null,
        expiresAfter: expiresMs
      };
    } else if (redeemed) {
      // ====== Sistem redeem lama ======
      valid = true;

      const createdMs = toMs(redeemed.redeemedAt, nowMs);

      info = {
        token: normKey,
        createdAt: createdMs,
        byIp: redeemed.ip || '0.0.0.0',
        linkId: null,
        userId: null,
        expiresAfter: null
      };
    } else {
      // ====== key tidak dikenal ======
      valid = false;
      info = null;
    }

    // Override jika pernah dihapus manual
    if (deletedEntry) {
      deleted = true;
      valid = false;

      const deletedAtMs = toMs(deletedEntry.deletedAt, nowMs);

      if (!info) {
        info = {
          token: normKey,
          createdAt: null,
          byIp: deletedEntry.ip || '0.0.0.0',
          linkId: null,
          userId: null,
          expiresAfter: null
        };
      }
      info.deletedAt = deletedAtMs;
    }

    return res.json({
      valid,
      deleted,
      info
    });
  } catch (err) {
    console.error('Failed to handle /api/isValidate:', err);
    return res.status(500).json({
      valid: false,
      deleted: false,
      info: null
    });
  }
});

// ===================================================================
// API stats untuk live update di UI
// ===================================================================

app.get('/api/stats', async (req, res) => {
  try {
    const scripts = await loadScriptsHydrated();
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

    if (hasKV) {
      try {
        await kvSRem(KV_EXEC_INDEX_KEY, entryKey);
        await kvDel(KV_EXEC_ENTRY_PREFIX + entryKey);
      } catch (err) {
        console.error('Failed to delete exec-user entry from KV:', err);
      }
    } else {
      let list = await loadExecUsers();
      const before = list.length;
      list = list.filter((u) => u.key !== entryKey);

      if (list.length !== before) {
        await saveExecUsers(list);
      }
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
// Admin – Web Key Manager (monitor IP & tokens)
// ===================================================================

// Dashboard Key Manager
app.get('/admin/keys', requireAdmin, async (req, res) => {
  try {
    const selectedIp = (req.query.ip || '').trim();
    const queryRaw = (req.query.q || '').trim();
    const query = queryRaw.toLowerCase();

    const {
      ipStats,
      ipDetails,
      totalIpCount,
      totalKeysCount,
      activeKeysCount,
      defaultKeyHours,
      maxKeysPerIp
    } = await buildWebKeysAdminData();

    let filteredIpStats = ipStats;

    if (query) {
      // Filter IP yang mengandung query (atau ada token/userId yang match)
      const matchIp = new Set();

      // Cek IP langsung
      ipStats.forEach((row) => {
        if (row.ip.toLowerCase().includes(query)) {
          matchIp.add(row.ip);
        }
      });

      // Cek token/userId
      ipDetails.forEach((list, ip) => {
        if (matchIp.has(ip)) return;
        const hit = list.some((k) => {
          const token = (k.token || '').toLowerCase();
          const uidStr = k.userId != null ? String(k.userId) : '';
          return (
            token.includes(query) ||
            uidStr.includes(queryRaw) // userId numeric
          );
        });
        if (hit) matchIp.add(ip);
      });

      filteredIpStats = ipStats.filter((row) => matchIp.has(row.ip));
    }

    let selectedKeys = [];
    if (selectedIp && ipDetails.has(selectedIp)) {
      selectedKeys = ipDetails.get(selectedIp) || [];
    }

    return res.render('admin-dashboardkey', {
      title: 'Admin – Web Key Manager',
      query: queryRaw,
      ipStats: filteredIpStats,
      selectedIp,
      selectedKeys,
      totalIpCount,
      totalKeysCount,
      activeKeysCount,
      defaultKeyHours,
      maxKeysPerIp
    });
  } catch (err) {
    console.error('Error rendering /admin/keys:', err);
    return res.status(500).send('Admin key dashboard error.');
  }
});

// Update default expiry (hours) dari admin-dashboardkey
app.post('/admin/keys/update-default', requireAdmin, async (req, res) => {
  try {
    const raw = (req.body.defaultKeyHours || '').toString().trim();
    let hours = parseInt(raw, 10);

    const currentCfg = await loadSiteConfig();

    if (!Number.isFinite(hours)) {
      hours =
        typeof currentCfg.defaultKeyHours === 'number'
          ? currentCfg.defaultKeyHours
          : DEFAULT_KEY_HOURS;
    } else {
      if (hours < 1) hours = 1;
      if (hours > 168) hours = 168;
    }

    const updatedCfg = {
      ...currentCfg,
      defaultKeyHours: hours
    };

    await saveSiteConfig(updatedCfg);
  } catch (err) {
    console.error(
      'Failed to update defaultKeyHours via /admin/keys/update-default:',
      err
    );
  }

  return res.redirect('/admin/keys');
});

// Delete semua key untuk 1 IP
app.post('/admin/keys/delete-ip', requireAdmin, async (req, res) => {
  try {
    const ip = (req.body.ip || '').trim();
    const back = '/admin/keys';

    if (!ip) {
      return res.redirect(back);
    }

    let webKeys = await loadWebKeys();
    let deletedKeys = await loadDeletedKeys();
    const before = webKeys.length;
    const nowIso = new Date().toISOString();

    // simpan semua token yang dihapus ke deleted-keys
    const toDelete = webKeys.filter((k) => k && k.ip === ip);
    if (toDelete.length > 0) {
      for (const k of toDelete) {
        if (!k || !k.token) continue;
        const tok = String(k.token);
        const exists = deletedKeys.some(
          (d) => d && String(d.token) === tok
        );
        if (!exists) {
          deletedKeys.push({
            token: tok,
            deletedAt: nowIso,
            ip: k.ip || ip,
            reason: 'delete-ip'
          });
        }
      }
      await saveDeletedKeys(deletedKeys);
    }

    webKeys = webKeys.filter((k) => k && k.ip !== ip);

    if (webKeys.length !== before) {
      await saveWebKeys(webKeys);
    }

    return res.redirect(back);
  } catch (err) {
    console.error('Failed to delete keys by IP:', err);
    return res.redirect('/admin/keys');
  }
});

// Delete 1 key (per token)
app.post('/admin/keys/delete-key', requireAdmin, async (req, res) => {
  try {
    const token = (req.body.token || '').trim();
    const ip = (req.body.ip || '').trim();
    const back = ip
      ? `/admin/keys?ip=${encodeURIComponent(ip)}`
      : '/admin/keys';

    if (!token) {
      return res.redirect(back);
    }

    let webKeys = await loadWebKeys();
    let deletedKeys = await loadDeletedKeys();
    const before = webKeys.length;
    const nowIso = new Date().toISOString();

    let removedEntry = null;
    const remaining = [];

    for (const k of webKeys) {
      if (!k) continue;
      if (!removedEntry && String(k.token) === String(token)) {
        removedEntry = k;
        continue;
      }
      remaining.push(k);
    }

    webKeys = remaining;

    if (removedEntry) {
      const tok = String(removedEntry.token);
      const exists = deletedKeys.some(
        (d) => d && String(d.token) === tok
      );
      if (!exists) {
        deletedKeys.push({
          token: tok,
          deletedAt: nowIso,
          ip: removedEntry.ip || ip || 'unknown',
          reason: 'delete-key'
        });
        await saveDeletedKeys(deletedKeys);
      }
    }

    if (webKeys.length !== before) {
      await saveWebKeys(webKeys);
    }

    return res.redirect(back);
  } catch (err) {
    console.error('Failed to delete key:', err);
    return res.redirect('/admin/keys');
  }
});

// Update createdAt & expiresAt untuk 1 token
app.post('/admin/keys/update-key', requireAdmin, async (req, res) => {
  try {
    const token = (req.body.token || '').trim();
    const ip = (req.body.ip || '').trim();
    const newCreatedAt = (req.body.createdAt || '').trim();
    const newExpiresAtRaw = (req.body.expiresAt || '').trim();

    const backBase = ip
      ? `/admin/keys?ip=${encodeURIComponent(ip)}`
      : '/admin/keys';
    const back =
      token && ip
        ? backBase + `#token-${encodeURIComponent(token)}`
        : backBase;

    if (!token) {
      return res.redirect(backBase);
    }

    let webKeys = await loadWebKeys();
    let changed = false;
    const nowMs = Date.now();

    webKeys = webKeys.map((k) => {
      if (!k || String(k.token) !== String(token)) return k;
      const updated = { ...k };

      // createdAt bisa diisi bebas (ISO / timestamp / string lain) – Admin tanggung jawab
      updated.createdAt = newCreatedAt;

      let finalExpiresAt = newExpiresAtRaw;

      if (newExpiresAtRaw) {
        // Coba parse sebagai durasi relatif "01:10:20" / "1h 10m 20s" → jadikan absolute ISO
        const relMs = parseRelativeExpiresInput(newExpiresAtRaw, nowMs);
        if (relMs) {
          finalExpiresAt = new Date(relMs).toISOString();
        }
      } else {
        // Jika dikosongkan, biarkan empty string: akan pakai defaultKeyHours di Admin view,
        // dan di isValidate expiresAfter akan dihitung dari defaultKeyHours.
        finalExpiresAt = '';
      }

      updated.expiresAt = finalExpiresAt;
      changed = true;
      return updated;
    });

    if (changed) {
      await saveWebKeys(webKeys);
    }

    return res.redirect(back);
  } catch (err) {
    console.error('Failed to update key timestamps:', err);
    return res.redirect('/admin/keys');
  }
});

// Renew 1 key (per token) dari Admin
app.post('/admin/keys/renew-key', requireAdmin, async (req, res) => {
  try {
    const token = (req.body.token || '').trim();
    const ip = (req.body.ip || '').trim();

    const backBase = ip
      ? `/admin/keys?ip=${encodeURIComponent(ip)}`
      : '/admin/keys';
    const back =
      token && ip
        ? backBase + `#token-${encodeURIComponent(token)}`
        : backBase;

    if (!token) {
      return res.redirect(backBase);
    }

    const siteConfig = await loadSiteConfig();
    const defaultKeyHours =
      typeof siteConfig.defaultKeyHours === 'number'
        ? siteConfig.defaultKeyHours
        : DEFAULT_KEY_HOURS;

    let webKeys = await loadWebKeys();
    const nowMs = Date.now();
    const extendMs = defaultKeyHours * 60 * 60 * 1000;

    let changed = false;

    webKeys = webKeys.map((k) => {
      if (!k || String(k.token) !== String(token)) return k;
      const updated = { ...k };
      const newExpiresMs = nowMs + extendMs;
      updated.expiresAt = new Date(newExpiresMs).toISOString();
      changed = true;
      return updated;
    });

    if (changed) {
      await saveWebKeys(webKeys);
    }

    return res.redirect(back);
  } catch (err) {
    console.error('Failed to renew key via admin:', err);
    return res.redirect('/admin/keys');
  }
});

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

app.get(
  '/admin/api/exec-users/:scriptId',
  requireAdmin,
  async (req, res) => {
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
  }
);

// ===================================================================
// Public Bot API untuk Discord (/api/bot/*)
// ===================================================================

// Helper: build payload stats ringan untuk bot
async function buildBotStatsPayload() {
  const { stats } = await buildAdminStats('all');
  let totalKeys = 0;
  let activeKeys = 0;

  try {
    const webKeysData = await buildWebKeysAdminData();
    totalKeys = webKeysData.totalKeysCount || 0;
    activeKeys = webKeysData.activeKeysCount || 0;
  } catch (err) {
    console.error('buildWebKeysAdminData in /api/bot/stats failed:', err);
  }

  let lastExecutionAt = null;
  if (
    stats &&
    Array.isArray(stats.recentExecutions) &&
    stats.recentExecutions.length
  ) {
    lastExecutionAt = stats.recentExecutions[0].executedAtIso;
  }

  return {
    ok: true,
    totalExecutions: stats.totalExecutions || 0,
    usersCount: stats.totalUsers || 0,
    scriptsCount: stats.totalScripts || stats.totalGames || 0,
    totalKeys,
    activeKeys,
    lastExecutionAt,
    apiUptimeSeconds: getApiUptimeSeconds()
  };
}

app.get('/api/bot/stats', async (req, res) => {
  try {
    const payload = await buildBotStatsPayload();
    return res.json(payload);
  } catch (err) {
    console.error('Failed to handle /api/bot/stats:', err);
    return res.status(500).json({
      ok: false,
      error: 'bot_stats_error'
    });
  }
});

// Helper: simple tier berdasarkan totalExec
function deriveUserTier(totalExec) {
  if (!Number.isFinite(totalExec) || totalExec <= 0) return 'NEW';
  if (totalExec > 5000) return 'DIAMOND';
  if (totalExec > 2000) return 'PLATINUM';
  if (totalExec > 500) return 'GOLD';
  if (totalExec > 100) return 'SILVER';
  if (totalExec > 10) return 'BRONZE';
  return 'NEW';
}

// Helper: ambil profile user berdasarkan "userId" yang sama dengan discordId
async function buildBotUserInfoPayload(discordId, discordTag) {
  const id = String(discordId || '').trim();
  const tag = discordTag ? String(discordTag).trim() : null;

  if (!id) {
    return {
      success: false,
      message: 'Missing discordId',
      discordId: null,
      discordTag: tag,
      userTier: null,
      totalExecutions: 0,
      lastExecutionAt: null,
      keys: []
    };
  }

  const execUsers = await loadExecUsers();
  const webKeys = await loadWebKeys();

  const relatedExec = execUsers.filter(
    (u) => u && String(u.userId || '') === id
  );

  let totalExecutions = 0;
  let lastExecutionAt = null;

  const pickLatest = (a, b) => {
    const ta = a ? Date.parse(a) : NaN;
    const tb = b ? Date.parse(b) : NaN;
    if (Number.isNaN(ta) && Number.isNaN(tb)) return null;
    if (Number.isNaN(ta)) return b;
    if (Number.isNaN(tb)) return a;
    return tb > ta ? b : a;
  };

  const keyObjects = [];

  relatedExec.forEach((u) => {
    const exec = u.totalExecutes || 0;
    totalExecutions += exec;
    lastExecutionAt = pickLatest(lastExecutionAt, u.lastExecuteAt);

    if (u.keyToken) {
      keyObjects.push({
        key: String(u.keyToken),
        token: String(u.keyToken),
        source: 'exec',
        scriptId: u.scriptId || null,
        lastExecuteAt: u.lastExecuteAt || null
      });
    }
  });

  // webKeys userId disamakan dengan discordId (opsional)
  webKeys.forEach((k) => {
    if (!k || !k.token) return;
    if (k.userId != null && String(k.userId) === id) {
      keyObjects.push({
        key: String(k.token),
        token: String(k.token),
        source: 'generate',
        createdAt: k.createdAt || null,
        expiresAt: k.expiresAt || null,
        ip: k.ip || null
      });
    }
  });

  // Dedup token
  const seen = new Set();
  const uniqueKeys = [];
  for (const k of keyObjects) {
    const tok = String(k.token || k.key || '');
    if (!tok || seen.has(tok)) continue;
    seen.add(tok);
    uniqueKeys.push(k);
  }

  if (!relatedExec.length && !uniqueKeys.length) {
    return {
      success: false,
      message: 'No noctyra data linked for this ID.',
      discordId: id,
      discordTag: tag,
      userTier: null,
      totalExecutions: 0,
      lastExecutionAt: null,
      keys: []
    };
  }

  const tier = deriveUserTier(totalExecutions);

  return {
    success: true,
    discordId: id,
    discordTag: tag,
    userTier: tier,
    totalExecutions,
    lastExecutionAt,
    keys: uniqueKeys
  };
}

async function handleBotUserInfo(req, res) {
  try {
    const body = req.body || {};
    const discordId =
      body.discordId ||
      req.query.discordId ||
      null;
    const discordTag =
      body.discordTag ||
      req.query.discordTag ||
      null;

    const payload = await buildBotUserInfoPayload(discordId, discordTag);
    return res.json(payload);
  } catch (err) {
    console.error('Failed to handle /api/bot/user-info:', err);
    return res.status(500).json({
      success: false,
      message: 'internal_error'
    });
  }
}

app.post('/api/bot/user-info', handleBotUserInfo);
app.get('/api/bot/user-info', handleBotUserInfo);

// Optional ping endpoint untuk healthcheck bot
app.get('/api/bot/ping', (req, res) => {
  res.json({
    ok: true,
    uptimeSeconds: getApiUptimeSeconds()
  });
});

// ===================================================================
// MOUNT DISCORD OAUTH + DASHBOARD (serverv2.js)
// ===================================================================

// Di sini kita mount semua route baru (/discord-login, /auth/discord, /dashboard, dll)
// dari file serverv2.js tanpa membuat server Express kedua.
try {
  require('./serverv2')(app);
  console.log('[server] serverv2 routes mounted.');
} catch (err) {
  console.error('[server] Failed to mount serverv2 routes:', err);
}

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
  const scripts = await loadScriptsHydrated();
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
    console.log(`noctyra site running on http://localhost:${PORT}`);
  });
}

// Selalu export app untuk Vercel
module.exports = app;
