// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key + Paid Key API
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

// ---------------------------------------------------------
// Helper: base API ExHub (saat ini tidak lagi dipakai user-info HTTP)
// ---------------------------------------------------------
function resolveExHubApiBase() {
  const SITE_BASE =
    process.env.EXHUB_SITE_BASE || "https://exc-webs.vercel.app";
  let base = process.env.EXHUB_API_BASE;
  if (!base) {
    base = new URL("/api/", SITE_BASE).toString();
  }
  if (!base.endsWith("/")) base += "/";
  return base;
}

// ---------------------------------------------------------
// Upstash KV khusus Free Key & Paid Key & Discord Profile
// ---------------------------------------------------------
const KV_REST_API_URL = process.env.KV_REST_API_URL;
const KV_REST_API_TOKEN = process.env.KV_REST_API_TOKEN;
const hasFreeKeyKV = !!(KV_REST_API_URL && KV_REST_API_TOKEN);

// Index semua user Discord yang pernah login
const DISCORD_USER_INDEX_KEY = "exhub:discord:userindex";

async function kvRequest(pathPart) {
  if (!hasFreeKeyKV || typeof fetch === "undefined") return null;

  const url = `${KV_REST_API_URL}/${pathPart}`;
  try {
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${KV_REST_API_TOKEN}`,
      },
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      console.error("[serverv2] KV error", res.status, text);
      return null;
    }

    const data = await res.json().catch(() => null);
    if (data && Object.prototype.hasOwnProperty.call(data, "result")) {
      return data.result;
    }
    return null;
  } catch (err) {
    console.error("[serverv2] KV request failed:", err);
    return null;
  }
}

function kvPath(cmd, ...segments) {
  const encoded = segments.map((s) => encodeURIComponent(String(s)));
  return `${cmd}/${encoded.join("/")}`;
}

async function kvGetJson(key) {
  const raw = await kvRequest(kvPath("GET", key));
  if (raw == null || typeof raw !== "string" || raw === "") return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function kvSetJson(key, value) {
  const raw = JSON.stringify(value);
  await kvRequest(kvPath("SET", key, raw));
}

// ---------------------------------------------------------
// Util time
// ---------------------------------------------------------
function nowMs() {
  return Date.now();
}

function pad2(n) {
  return n < 10 ? "0" + n : String(n);
}

function formatDateLabelMs(ms, offsetHours, suffix) {
  if (!ms || typeof ms !== "number") return null;
  const d = new Date(ms + offsetHours * 3600000); // pakai UTC + offset
  const y = d.getUTCFullYear();
  const m = pad2(d.getUTCMonth() + 1);
  const day = pad2(d.getUTCDate());
  const h = pad2(d.getUTCHours());
  const min = pad2(d.getUTCMinutes());
  const s = pad2(d.getUTCSeconds());
  return `${y}-${m}-${day} ${h}:${min}:${s} ${suffix}`;
}

function formatDualTimeLabelMs(ms) {
  if (!ms || typeof ms !== "number") {
    return { wita: null, wib: null, label: null };
  }
  const wita = formatDateLabelMs(ms, 8, "WITA");
  const wib = formatDateLabelMs(ms, 7, "WIB");
  let label = null;
  if (wita && wib) label = `${wita} • ${wib}`;
  else label = wita || wib || null;
  return { wita, wib, label };
}

function formatTimeLeftLabelFromMs(expiresMs) {
  if (!expiresMs || typeof expiresMs !== "number") return "-";
  const diff = expiresMs - nowMs();
  if (diff <= 0) return "Expired";
  const totalSeconds = Math.floor(diff / 1000);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${pad2(h)}:${pad2(m)}:${pad2(s)}`;
}

function parseDateOrTimestamp(value) {
  if (value == null) return null;
  const str = String(value).trim();
  if (!str) return null;

  // numeric only -> timestamp
  if (/^\d+$/.test(str)) {
    const num = parseInt(str, 10);
    if (Number.isNaN(num)) return null;
    // Jika kurang dari 1e12, anggap detik -> ms
    if (num < 1e12) return num * 1000;
    return num;
  }

  const d = new Date(str);
  const ms = d.getTime();
  if (Number.isNaN(ms)) return null;
  return ms;
}

function parseHHMMSS(value) {
  if (!value) return null;
  const str = String(value).trim();
  if (!str) return null;

  const parts = str.split(":");
  let h = 0,
    m = 0,
    s = 0;

  if (parts.length === 3) {
    h = parseInt(parts[0], 10) || 0;
    m = parseInt(parts[1], 10) || 0;
    s = parseInt(parts[2], 10) || 0;
  } else if (parts.length === 2) {
    m = parseInt(parts[0], 10) || 0;
    s = parseInt(parts[1], 10) || 0;
  } else if (parts.length === 1) {
    s = parseInt(parts[0], 10) || 0;
  }

  const totalSeconds = h * 3600 + m * 60 + s;
  if (totalSeconds <= 0) return null;
  return totalSeconds * 1000;
}

// ---------------------------------------------------------
// Global config (UI Get Free Key + TTL free & paid) via KV
// ---------------------------------------------------------

const FREE_KEY_UI_CONFIG_KEY = "exhub:freekey:ui-config";
const PAID_PLAN_CONFIG_KEY = "exhub:paidplan:config";

const FREE_KEY_TTL_DEFAULT_HOURS = Number(
  process.env.FREE_KEY_TTL_HOURS || 3
);
const PAID_MONTH_DEFAULT_DAYS = Number(process.env.PAID_MONTH_DAYS || 30);
const PAID_LIFETIME_DEFAULT_DAYS = Number(
  process.env.PAID_LIFETIME_DAYS || 365
);

let cachedFreeKeyUiConfig = null;
let cachedPaidPlanConfig = null;
let cachedGlobalConfigLoadedAt = 0;
const GLOBAL_CONFIG_CACHE_MS = 60 * 1000;

function normalizeFreeKeyTtlHours(uiCfg) {
  if (!uiCfg || typeof uiCfg !== "object") {
    return FREE_KEY_TTL_DEFAULT_HOURS;
  }

  let raw =
    uiCfg.ttlHours ??
    uiCfg.freeKeyTtlHours ??
    (uiCfg.global && uiCfg.global.ttlHours);

  if (raw == null && uiCfg.global && typeof uiCfg.global.freeKeyTtlHours === "number") {
    raw = uiCfg.global.freeKeyTtlHours;
  }

  let n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) n = FREE_KEY_TTL_DEFAULT_HOURS;
  if (n > 72) n = 72; // batas aman
  return n;
}

function normalizePaidPlanConfig(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {};
  let monthDays = Number(cfg.monthDays);
  let lifetimeDays = Number(cfg.lifetimeDays);

  if (!Number.isFinite(monthDays) || monthDays <= 0) {
    monthDays = PAID_MONTH_DEFAULT_DAYS;
  }
  if (!Number.isFinite(lifetimeDays) || lifetimeDays <= 0) {
    lifetimeDays = PAID_LIFETIME_DEFAULT_DAYS;
  }

  return { monthDays, lifetimeDays };
}

async function loadGlobalKeyConfig() {
  const now = nowMs();

  if (
    cachedGlobalConfigLoadedAt &&
    now - cachedGlobalConfigLoadedAt < GLOBAL_CONFIG_CACHE_MS &&
    cachedFreeKeyUiConfig !== null &&
    cachedPaidPlanConfig !== null
  ) {
    const freeTtl = normalizeFreeKeyTtlHours(cachedFreeKeyUiConfig);
    const paidCfg = normalizePaidPlanConfig(cachedPaidPlanConfig);
    return {
      freeKeyUiConfig: cachedFreeKeyUiConfig,
      freeKeyTtlHours: freeTtl,
      paidPlanConfig: paidCfg,
    };
  }

  let uiCfgRaw = null;
  let paidCfgRaw = null;

  if (hasFreeKeyKV) {
    try {
      [uiCfgRaw, paidCfgRaw] = await Promise.all([
        kvGetJson(FREE_KEY_UI_CONFIG_KEY),
        kvGetJson(PAID_PLAN_CONFIG_KEY),
      ]);
    } catch (err) {
      console.warn(
        "[serverv2] loadGlobalKeyConfig KV error (gunakan default):",
        err
      );
    }
  }

  cachedFreeKeyUiConfig = uiCfgRaw || {};
  cachedPaidPlanConfig = paidCfgRaw || {};
  cachedGlobalConfigLoadedAt = now;

  const freeTtl = normalizeFreeKeyTtlHours(cachedFreeKeyUiConfig);
  const paidCfg = normalizePaidPlanConfig(cachedPaidPlanConfig);

  return {
    freeKeyUiConfig: cachedFreeKeyUiConfig,
    freeKeyTtlHours: freeTtl,
    paidPlanConfig: paidCfg,
  };
}

async function getFreeKeyTtlMs() {
  const { freeKeyTtlHours } = await loadGlobalKeyConfig();
  const ttlHours =
    typeof freeKeyTtlHours === "number" && freeKeyTtlHours > 0
      ? freeKeyTtlHours
      : FREE_KEY_TTL_DEFAULT_HOURS;
  return ttlHours * 60 * 60 * 1000;
}

async function getPaidDurationsMs() {
  const { paidPlanConfig } = await loadGlobalKeyConfig();
  const cfg = normalizePaidPlanConfig(paidPlanConfig);
  const dayMs = 24 * 60 * 60 * 1000;
  return {
    monthMs: cfg.monthDays * dayMs,
    lifetimeMs: cfg.lifetimeDays * dayMs,
  };
}

// ---------------------------------------------------------
// Konfigurasi Free Key (persisten via Upstash)
// ---------------------------------------------------------

const FREE_KEY_PREFIX = "EXHUBFREE";
const FREE_KEY_TTL_HOURS = FREE_KEY_TTL_DEFAULT_HOURS; // default, bisa di-override via KV
const FREE_KEY_MAX_PER_USER = 5;

const REQUIRE_FREEKEY_ADS_CHECKPOINT =
  String(process.env.REQUIREFREEKEY_ADS_CHECKPOINT || "1") === "1";

const FREEKEY_ADS_COOLDOWN_MS = Number(
  process.env.FREEKEY_ADS_COOLDOWN_MS || 5 * 60 * 1000
);

function userIndexKey(userId) {
  return `exhub:freekey:user:${userId}`;
}

function tokenKey(token) {
  return `exhub:freekey:token:${token}`;
}

function discordUserProfileKey(discordId) {
  return `exhub:discord:userprofile:${discordId}`;
}

function discordUserIndexKey() {
  return DISCORD_USER_INDEX_KEY;
}

function generateFreeKeyToken() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  function chunk(len) {
    let out = "";
    for (let i = 0; i < len; i++) {
      out += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return out;
  }
  return `${FREE_KEY_PREFIX}-${chunk(3)}-${chunk(4)}-${chunk(5)}`;
}

async function createFreeKeyRecordPersistent({ userId, provider, ip }) {
  const createdAt = nowMs();
  const ttlMs = await getFreeKeyTtlMs();
  const expiresAfter = createdAt + ttlMs;

  let token;
  for (;;) {
    token = generateFreeKeyToken();
    const existing = await kvGetJson(tokenKey(token));
    if (!existing) break;
  }

  const rec = {
    token,
    userId: String(userId),
    provider, // 'workink' atau 'linkvertise'
    createdAt,
    byIp: ip || null,
    linkId: null,
    expiresAfter,
    deleted: false,
    valid: true,
  };

  await kvSetJson(tokenKey(token), rec);

  const idxKey = userIndexKey(userId);
  let index = await kvGetJson(idxKey);
  if (!Array.isArray(index)) index = [];
  if (!index.includes(token)) {
    index.push(token);
    await kvSetJson(idxKey, index);
  }

  return rec;
}

async function extendFreeKeyPersistent(token) {
  const key = tokenKey(token);
  const rec = await kvGetJson(key);
  if (!rec) return null;

  const ttlMs = await getFreeKeyTtlMs();
  const now = nowMs();

  rec.expiresAfter = now + ttlMs;
  rec.valid = true;
  rec.deleted = false;

  await kvSetJson(key, rec);
  return rec;
}

// Delete free key + bersihkan index user
async function deleteFreeKeyPersistent(token, userIdCheck) {
  const key = tokenKey(token);
  const rec = await kvGetJson(key);
  if (!rec) return { ok: true, updated: false };

  if (userIdCheck && String(rec.userId) !== String(userIdCheck)) {
    return { ok: false, reason: "USER_MISMATCH" };
  }

  rec.deleted = true;
  rec.valid = false;

  await kvSetJson(key, rec);

  if (hasFreeKeyKV && rec.userId) {
    try {
      const idxKey = userIndexKey(rec.userId);
      let index = await kvGetJson(idxKey);
      if (Array.isArray(index)) {
        const filtered = index.filter((t) => t && t !== token);
        await kvSetJson(idxKey, filtered);
      }
    } catch (err) {
      console.error("[serverv2] deleteFreeKeyPersistent index cleanup error:", err);
    }
  }

  return { ok: true, updated: true };
}

async function getFreeKeysForUserPersistent(userId) {
  if (!hasFreeKeyKV) return [];

  const idxKey = userIndexKey(userId);
  const index = await kvGetJson(idxKey);
  const tokens = Array.isArray(index) ? index : [];
  const now = nowMs();
  const result = [];

  for (const token of tokens) {
    if (!token) continue;
    const rec = await kvGetJson(tokenKey(token));
    if (!rec) continue;
    if (rec.deleted) continue;

    const msLeft = rec.expiresAfter - now;
    const isExpired = msLeft <= 0;

    const timeLeftLabel = formatTimeLeftLabelFromMs(rec.expiresAfter);

    let providerLabel = rec.provider || "ExHub Free";
    const p = String(providerLabel).toLowerCase();
    if (p === "workink" || p === "work.ink") providerLabel = "Work.ink";
    else if (p.indexOf("linkvertise") !== -1) providerLabel = "Linkvertise";

    result.push({
      token: rec.token,
      provider: providerLabel,
      timeLeftLabel,
      status: isExpired ? "Expired" : "Active",
      expiresAfter: rec.expiresAfter,
      tier: "Free",
    });
  }

  result.sort((a, b) => {
    const sa = a.status === "Active" ? 0 : 1;
    const sb = b.status === "Active" ? 0 : 1;
    if (sa !== sb) return sa - sb;
    return a.expiresAfter - b.expiresAfter;
  });

  return result;
}

// ---------------------------------------------------------
// Konfigurasi Paid Key (Premium Keys) via KV
// ---------------------------------------------------------

const PAID_KEY_PREFIX = "EXHUBPAID";

function paidTokenKey(token) {
  return `exhub:paidkey:token:${token}`;
}

function paidUserIndexKey(discordId) {
  return `exhub:paidkey:user:${discordId}`;
}

function normalizePaidKeyRecord(raw) {
  if (!raw) return null;
  return {
    token: raw.token,
    createdAt: raw.createdAt || 0,
    byIp: raw.byIp || null,
    expiresAfter: raw.expiresAfter || 0,
    type: raw.type || raw.tier || null,
    valid: !!raw.valid,
    deleted: !!raw.deleted,
    ownerDiscordId: raw.ownerDiscordId || null,
  };
}

async function getPaidKeyRecord(token) {
  const rec = await kvGetJson(paidTokenKey(token));
  if (!rec) return null;
  return normalizePaidKeyRecord(rec);
}

async function setPaidKeyRecord(payload) {
  if (!payload || !payload.token) return null;

  const now = nowMs();
  const token = payload.token;
  const ownerDiscordId = payload.ownerDiscordId
    ? String(payload.ownerDiscordId)
    : null;

  const existingRaw = await kvGetJson(paidTokenKey(token));
  const existing = existingRaw || null;
  const previousOwnerId =
    existing && existing.ownerDiscordId
      ? String(existing.ownerDiscordId)
      : null;

  const rec = {
    token,
    createdAt: payload.createdAt || (existing && existing.createdAt) || now,
    byIp: payload.byIp || (existing && existing.byIp) || null,
    expiresAfter:
      typeof payload.expiresAfter === "number"
        ? payload.expiresAfter
        : existing && typeof existing.expiresAfter === "number"
        ? existing.expiresAfter
        : 0,
    type: payload.type || (existing && existing.type) || null,
    valid:
      typeof payload.valid === "boolean"
        ? !!payload.valid
        : existing
        ? !!existing.valid
        : false,
    deleted:
      typeof payload.deleted === "boolean"
        ? !!payload.deleted
        : existing
        ? !!existing.deleted
        : false,
    ownerDiscordId: ownerDiscordId || previousOwnerId || null,
  };

  await kvSetJson(paidTokenKey(rec.token), rec);

  const newOwnerId = rec.ownerDiscordId;

  // Hapus dari index owner lama jika pindah
  if (previousOwnerId && previousOwnerId !== newOwnerId) {
    const oldIdxKey = paidUserIndexKey(previousOwnerId);
    let oldIdx = await kvGetJson(oldIdxKey);
    if (Array.isArray(oldIdx)) {
      const filtered = oldIdx.filter((t) => t !== token);
      await kvSetJson(oldIdxKey, filtered);
    }
  }

  // Tambahkan ke index owner baru
  if (newOwnerId) {
    const newIdxKey = paidUserIndexKey(newOwnerId);
    let newIdx = await kvGetJson(newIdxKey);
    if (!Array.isArray(newIdx)) newIdx = [];
    if (!newIdx.includes(token)) {
      newIdx.push(token);
      await kvSetJson(newIdxKey, newIdx);
    }
  }

  return normalizePaidKeyRecord(rec);
}

// Paid keys per user – skip yang deleted (hilang dari dashboard & user-info)
async function getPaidKeysForUserPersistent(discordId) {
  if (!hasFreeKeyKV) return [];

  const idxKey = paidUserIndexKey(discordId);
  const index = await kvGetJson(idxKey);
  const tokens = Array.isArray(index) ? index : [];
  const result = [];

  for (const token of tokens) {
    if (!token) continue;
    const raw = await kvGetJson(paidTokenKey(token));
    if (!raw) continue;
    const rec = normalizePaidKeyRecord(raw);
    if (!rec) continue;

    const now = nowMs();
    const expired =
      rec.expiresAfter && typeof rec.expiresAfter === "number"
        ? now > rec.expiresAfter
        : false;
    const deleted = !!rec.deleted;

    // Jangan tampilkan key yang sudah dihapus (deleted=true)
    if (deleted) {
      continue;
    }

    let providerLabel = "ExHub Paid";
    const t = (rec.type || "").toString().toLowerCase();
    if (t === "month") providerLabel = "PAID MONTH";
    else if (t === "lifetime") providerLabel = "PAID LIFETIME";

    let statusLabel;
    if (expired) statusLabel = "Expired";
    else if (rec.valid) statusLabel = "Active";
    else statusLabel = "Pending";

    const expiresAtMs = rec.expiresAfter || null;
    const timeLeftLabel = expiresAtMs
      ? formatTimeLeftLabelFromMs(expiresAtMs)
      : "-";

    result.push({
      key: rec.token,
      token: rec.token,
      provider: providerLabel,
      timeLeft: timeLeftLabel,
      status: statusLabel,
      tier: "Paid",
      expiresAtMs,
      expiresAfter: rec.expiresAfter || null,
      valid: rec.valid,
      expired,
      deleted: false,
      type: rec.type || null,
      createdAt: rec.createdAt || null,
      ownerDiscordId: rec.ownerDiscordId || null,
    });
  }

  result.sort((a, b) => {
    const aTs = typeof a.expiresAfter === "number" ? a.expiresAfter : 0;
    const bTs = typeof b.expiresAfter === "number" ? b.expiresAfter : 0;
    return aTs - bTs;
  });

  return result;
}

// ---------------------------------------------------------
// Discord user profile & index helpers
// ---------------------------------------------------------
async function addDiscordUserToIndex(discordId) {
  if (!hasFreeKeyKV) return;
  const key = discordUserIndexKey();
  let arr = await kvGetJson(key);
  if (!Array.isArray(arr)) arr = [];
  const sId = String(discordId);
  if (!arr.includes(sId)) {
    arr.push(sId);
    await kvSetJson(key, arr);
  }
}

async function getAllDiscordUserIds() {
  if (!hasFreeKeyKV) return [];
  const key = discordUserIndexKey();
  const arr = await kvGetJson(key);
  if (!Array.isArray(arr)) return [];
  return arr.map((v) => String(v));
}

async function getDiscordUserProfile(discordId) {
  if (!hasFreeKeyKV) return null;
  return kvGetJson(discordUserProfileKey(discordId));
}

async function setDiscordUserProfilePersistent(discordId, partial) {
  if (!hasFreeKeyKV) return null;
  const key = discordUserProfileKey(discordId);
  let existing = await kvGetJson(key);
  if (!existing || typeof existing !== "object") {
    existing = { id: String(discordId) };
  }
  const merged = Object.assign({}, existing, partial || {});
  if (!merged.id) merged.id = String(discordId);
  await kvSetJson(key, merged);
  await addDiscordUserToIndex(discordId);
  return merged;
}

async function isDiscordUserBanned(discordId) {
  if (!hasFreeKeyKV) return false;
  try {
    const profile = await getDiscordUserProfile(discordId);
    return !!(profile && profile.banned === true);
  } catch (err) {
    console.warn("[serverv2] isDiscordUserBanned error:", err);
    return false;
  }
}

function makeDiscordAvatarUrl(profile) {
  if (!profile) return null;
  const id = profile.id || profile.discordId;
  const avatar = profile.avatar;
  if (id && avatar) {
    return `https://cdn.discordapp.com/avatars/${id}/${avatar}.png?size=128`;
  }
  if (id) {
    const idx = Number(id) % 5;
    return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
  }
  return null;
}

function makeDiscordBannerUrl(profile) {
  if (!profile) return null;
  const id = profile.id || profile.discordId;
  const banner = profile.banner;
  if (id && banner) {
    return `https://cdn.discordapp.com/banners/${id}/${banner}.png?size=512`;
  }
  return null;
}

// Normalisasi Paid key untuk admin-dashboarddiscord
function normalizePaidKeyForAdmin(k, fallbackDiscordId) {
  if (!k) return null;
  const token = String(k.token || k.key || "");
  if (!token) return null;

  const createdAtMs =
    typeof k.createdAt === "number" && k.createdAt > 0
      ? k.createdAt
      : null;
  const expiresAtMs =
    typeof k.expiresAfter === "number" && k.expiresAfter > 0
      ? k.expiresAfter
      : typeof k.expiresAtMs === "number" && k.expiresAtMs > 0
      ? k.expiresAtMs
      : null;

  const createdLabelObj = createdAtMs
    ? formatDualTimeLabelMs(createdAtMs)
    : { label: null };
  const expiresLabelObj = expiresAtMs
    ? formatDualTimeLabelMs(expiresAtMs)
    : { label: null };

  const deleted = !!k.deleted;
  const expired =
    typeof k.expired === "boolean"
      ? k.expired
      : expiresAtMs
      ? nowMs() > expiresAtMs
      : false;
  const valid =
    typeof k.valid === "boolean"
      ? k.valid
      : !deleted && !expired;

  let status = k.status;
  if (!status) {
    if (deleted) status = "Deleted";
    else if (expired) status = "Expired";
    else if (valid) status = "Active";
    else status = "Pending";
  }

  const tier = k.tier || "Paid";
  const type = k.type || tier || "paid";
  const timeLeftLabel = expiresAtMs
    ? formatTimeLeftLabelFromMs(expiresAtMs)
    : "-";

  const provider = k.provider || "ExHub Paid";

  return {
    token,
    key: token,
    provider,
    source: provider,
    tier,
    type,
    createdAt: createdAtMs,
    createdAtLabel: createdLabelObj.label,
    expiresAtLabel: expiresLabelObj.label,
    expiresAtMs,
    timeLeftLabel,
    status,
    deleted,
    expired,
    valid,
    free: false,
    ownerDiscordId: k.ownerDiscordId || fallbackDiscordId || null,
  };
}

// Normalisasi Free key untuk admin-dashboarddiscord
function normalizeFreeKeyForAdmin(fk, discordId) {
  if (!fk) return null;
  const token = fk.token;
  if (!token) return null;

  const expiresAtMs =
    typeof fk.expiresAfter === "number" && fk.expiresAfter > 0
      ? fk.expiresAfter
      : null;
  const expiresLabelObj = expiresAtMs
    ? formatDualTimeLabelMs(expiresAtMs)
    : { label: null };

  const statusStr = (fk.status || "").toLowerCase();
  const expired =
    expiresAtMs && typeof expiresAtMs === "number"
      ? nowMs() > expiresAtMs
      : statusStr === "expired";
  const valid = statusStr === "active" && !expired;

  const providerLabel = String(fk.provider || "ExHub Free").toLowerCase();
  let provider = "ExHub Free";
  if (providerLabel === "work.ink" || providerLabel === "workink") {
    provider = "Work.ink";
  } else if (providerLabel.indexOf("linkvertise") !== -1) {
    provider = "Linkvertise";
  }

  const timeLeftLabel = expiresAtMs
    ? formatTimeLeftLabelFromMs(expiresAtMs)
    : fk.timeLeftLabel || "-";

  const status = expired
    ? "Expired"
    : valid
    ? "Active"
    : fk.status || "Pending";

  return {
    token,
    key: token,
    provider,
    source: provider,
    tier: "Free",
    type: "free",
    createdAt: null,
    createdAtLabel: null,
    expiresAtLabel: expiresLabelObj.label,
    expiresAtMs,
    timeLeftLabel,
    status,
    deleted: false,
    expired,
    valid,
    free: true,
    ownerDiscordId: discordId,
  };
}

// ---------------------------------------------------------
// Helper: Ads / checkpoint state di session (per provider)
// ---------------------------------------------------------

function canonicalAdsProvider(raw) {
  const v = String(raw || "").toLowerCase();
  if (v === "linkvertise" || v === "linkvertise.com") return "linkvertise";
  return "workink";
}

function getAdsState(req, provider) {
  if (!req.session || !req.session.freeKeyAdsState) return null;
  const state = req.session.freeKeyAdsState[provider];
  if (!state) return null;
  return {
    ts: state.ts || 0,
    used: !!state.used,
  };
}

function setAdsCheckpoint(req, provider) {
  if (!req.session) return;
  if (!req.session.freeKeyAdsState) req.session.freeKeyAdsState = {};
  req.session.freeKeyAdsState[provider] = {
    ts: nowMs(),
    used: false,
  };
}

function markAdsUsed(req, provider) {
  if (!req.session) return;
  if (!req.session.freeKeyAdsState) req.session.freeKeyAdsState = {};
  const prev = req.session.freeKeyAdsState[provider] || {
    ts: nowMs(),
    used: false,
  };
  prev.used = true;
  req.session.freeKeyAdsState[provider] = prev;
}

// ---------------------------------------------------------
// Modul utama: mount ke Express app
// ---------------------------------------------------------
module.exports = function mountDiscordOAuth(app) {
  // =========================
  // ENV
  // =========================
  const DISCORD_CLIENT_ID =
    process.env.DISCORD_CLIENT_ID || process.env.CLIENT_ID;
  const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
  const DISCORD_REDIRECT_URI =
    process.env.DISCORD_REDIRECT_URI ||
    "http://localhost:3000/auth/discord/callback";

  // EXHUB_API_BASE: saat ini tidak kita pakai untuk user-info HTTP
  const EXHUB_API_BASE = resolveExHubApiBase();

  const WORKINK_ADS_URL =
    process.env.WORKINK_ADS_URL || "https://work.ink/23P2/exhubfreekey";
  const LINKVERTISE_ADS_URL =
    process.env.LINKVERTISE_ADS_URL ||
    "https://link-target.net/2995260/uaE3u7P8CG5D";

  // OWNER IDs masih boleh diisi untuk "badge" saja, TIDAK untuk login admin
  const RAW_OWNER_IDS =
    process.env.OWNER_IDS ||
    process.env.OWNER_ID ||
    "";
  const OWNER_IDS = RAW_OWNER_IDS.split(/[,\s]+/).filter(Boolean);

  function isOwnerId(id) {
    return OWNER_IDS.includes(String(id));
  }

  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    console.warn(
      "[serverv2] DISCORD_CLIENT_ID atau DISCORD_CLIENT_SECRET belum diset. " +
        "Fitur Discord Login tidak akan bekerja dengan benar."
    );
  }

  if (!hasFreeKeyKV) {
    console.warn(
      "[serverv2] PERINGATAN: KV_REST_API_URL / KV_REST_API_TOKEN tidak diset – Free Key / Paid Key TIDAK akan persisten."
    );
  }

  // =========================
  // HELPER SESSION ADMIN
  // =========================
  function isAdminSession(req) {
    return !!(
      req.session &&
      (req.session.isAdmin === true || req.session.adminLoggedIn === true)
    );
  }

  // =========================
  // MIDDLEWARE: res.locals.user & res.locals.isAdmin
  // =========================
  app.use((req, res, next) => {
    const user = (req.session && req.session.discordUser) || null;
    res.locals.user = user;
    res.locals.isOwner = user ? isOwnerId(user.id) : false;
    res.locals.ownerIds = OWNER_IDS;
    res.locals.isAdmin = isAdminSession(req);
    next();
  });

  // =========================
  // HELPER AUTH & ADS PROVIDER RESOLVER
  // =========================

  function makeDiscordAuthUrl(state) {
    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      response_type: "code",
      scope: "identify guilds email",
      redirect_uri: DISCORD_REDIRECT_URI,
      state,
      prompt: "consent",
    });

    return `https://discord.com/oauth2/authorize?${params.toString()}`;
  }

  // Resolver ads provider (dipakai GET /getfreekey, POST generate, POST extend)
  function resolveAdsProviderForRequest(req) {
    const rawAdsParam =
      typeof req.query.ads === "string" ? req.query.ads : "";

    let adsProvider;
    if (rawAdsParam) {
      // Ada ?ads → pakai & simpan ke session
      adsProvider = canonicalAdsProvider(rawAdsParam);
      if (req.session) {
        req.session.lastFreeKeyAdsProvider = adsProvider;
      }
    } else if (req.session && req.session.lastFreeKeyAdsProvider) {
      // Tidak ada ?ads, pakai provider terakhir dari session
      adsProvider = canonicalAdsProvider(req.session.lastFreeKeyAdsProvider);
    } else {
      // Default awal kalau belum ada riwayat
      adsProvider = "workink";
    }
    return adsProvider;
  }

  // Wajib login Discord untuk fitur user (dashboard, get key, dll)
  function requireAuth(req, res, next) {
    if (!req.session || !req.session.discordUser) {
      return res.redirect("/login-required");
    }
    next();
  }

  // Wajib session admin (ADMIN_USER / ADMIN_PASS) untuk fitur admin
  function requireAdmin(req, res, next) {
    if (!isAdminSession(req)) {
      return res.status(403).send("Forbidden: Admin only");
    }
    next();
  }

  // Ambil data key user untuk Dashboard (web) → langsung dari KV
  async function getUserKeys(discordUser) {
    const result = {
      total: 0,
      active: 0,
      premium: 0,
      keys: [],
      banned: false,
    };

    if (!discordUser) return result;

    let bannedFlag = false;

    try {
      const profile = await kvGetJson(discordUserProfileKey(discordUser.id));
      if (profile && profile.banned === true) bannedFlag = true;
    } catch (err) {
      console.warn("[serverv2] read discord profile for banned error:", err);
    }

    let paidKeys = [];
    try {
      paidKeys = await getPaidKeysForUserPersistent(discordUser.id);
    } catch (err) {
      console.error("[serverv2] getPaidKeysForUserPersistent error:", err);
    }

    let freeKeys = [];
    try {
      freeKeys = await getFreeKeysForUserPersistent(discordUser.id);
    } catch (err) {
      console.error("[serverv2] getFreeKeysForUserPersistent error:", err);
    }

    const normalizedFree = freeKeys.map((fk) => ({
      key: fk.token,
      token: fk.token,
      provider: fk.provider || "ExHub Free",
      timeLeft: fk.timeLeftLabel || "-",
      status: fk.status || "Active",
      tier: fk.tier || "Free",
      expiresAtMs: fk.expiresAfter || null,
      expiresAfter: fk.expiresAfter || null,
      free: true,
    }));

    const allKeys = paidKeys.concat(normalizedFree);

    result.keys = allKeys;
    result.total = allKeys.length;
    result.active = allKeys.filter(
      (k) => (k.status || "").toLowerCase() === "active"
    ).length;
    result.premium = allKeys.filter((k) => {
      const tier = String(k.tier || "").toLowerCase();
      return tier && tier.indexOf("free") === -1;
    }).length;
    result.banned = bannedFlag;

    return result;
  }

  // =========================
  // ROUTES – PUBLIC PAGES
  // =========================

  app.get("/discord-login", (req, res) => {
    const already = req.session && req.session.discordUser;
    if (already) {
      return res.redirect("/dashboard");
    }

    res.render("discord-login", {
      error: req.query.error || null,
    });
  });

  app.get("/login-required", (req, res) => {
    res.render("login-required");
  });

  // =========================
  // ROUTES – DASHBOARD & PAGE WAJIB LOGIN (USER DISCORD)
  // =========================

  app.get("/dashboard", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const keyData = await getUserKeys(discordUser);
    res.render("dashboard", { keyData });
  });

  app.get("/get-keyfree", requireAuth, (req, res) => {
    const ads = req.query.ads || "workink";
    res.redirect("/getfreekey?ads=" + encodeURIComponent(ads));
  });

  // --------------------------------------------------
  // GET /getfreekey – halaman utama get free key
  // --------------------------------------------------
  app.get("/getfreekey", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    const doneFlag = String(req.query.done || "") === "1";

    // Global config (UI + TTL)
    const { freeKeyUiConfig, freeKeyTtlHours } = await loadGlobalKeyConfig();

    // Cek banned
    const bannedFlag = await isDiscordUserBanned(userId);

    // Gunakan resolver umum (query.ads + session.lastFreeKeyAdsProvider)
    const adsProvider = resolveAdsProviderForRequest(req);

    if (doneFlag && req.session) {
      const existingState = getAdsState(req, adsProvider);
      const now = nowMs();

      if (
        existingState &&
        existingState.used &&
        existingState.ts &&
        now - existingState.ts < FREEKEY_ADS_COOLDOWN_MS
      ) {
        return res.redirect(
          "/getfreekey?ads=" + encodeURIComponent(adsProvider)
        );
      }

      setAdsCheckpoint(req, adsProvider);
      return res.redirect("/getfreekey?ads=" + encodeURIComponent(adsProvider));
    }

    const adsState = getAdsState(req, adsProvider);
    const adsProgressDone = !!adsState;
    const adsUsed = !!(adsState && adsState.used);

    const adsUrl =
      adsProvider === "linkvertise" ? LINKVERTISE_ADS_URL : WORKINK_ADS_URL;

    const freeKeys = await getFreeKeysForUserPersistent(userId);
    const maxKeys = FREE_KEY_MAX_PER_USER;
    const keys = freeKeys;

    const capacityOk = keys.length < maxKeys;

    let allowGenerate =
      capacityOk &&
      (!REQUIRE_FREEKEY_ADS_CHECKPOINT || (adsProgressDone && !adsUsed));
    let canRenew =
      keys.length > 0 &&
      (!REQUIRE_FREEKEY_ADS_CHECKPOINT || (adsProgressDone && !adsUsed));

    // Jika banned → tidak boleh generate / renew
    if (bannedFlag) {
      allowGenerate = false;
      canRenew = false;
    }

    const errorMessage = req.query.error || null;

    res.render("getfreekey", {
      title: "ExHub — Get Free Key",
      user: discordUser,
      adsProvider,
      adsUrl,
      keys,
      maxKeys,
      defaultKeyHours:
        typeof freeKeyTtlHours === "number" && freeKeyTtlHours > 0
          ? freeKeyTtlHours
          : FREE_KEY_TTL_HOURS,
      allowGenerate,
      canRenew,
      adsProgressDone,
      adsUsedFlag: adsUsed,
      currentUserId: userId,
      keyAction: "/getfreekey/generate",
      renewAction: "/getfreekey/extend",
      errorMessage,
      banned: bannedFlag,
      freeKeyUiConfig,
      freeKeyTtlHours,
    });
  });

  // --------------------------------------------------
  // POST /getfreekey/generate
  // --------------------------------------------------
  app.post("/getfreekey/generate", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    // Provider di-resolve sama seperti GET /getfreekey
    const adsProvider = resolveAdsProviderForRequest(req);
    const redirectBase = "/getfreekey?ads=" + encodeURIComponent(adsProvider);

    // Cek banned
    const bannedFlag = await isDiscordUserBanned(userId);
    if (bannedFlag) {
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent(
            "Akun ini telah diblokir. Free key tidak tersedia."
          )
      );
    }

    try {
      const existing = await getFreeKeysForUserPersistent(userId);
      if (existing.length >= FREE_KEY_MAX_PER_USER) {
        return res.redirect(
          redirectBase +
            "&error=" +
            encodeURIComponent(
              "Key slot penuh. Biarkan beberapa key expired dulu."
            )
        );
      }

      if (REQUIRE_FREEKEY_ADS_CHECKPOINT) {
        const adsState = getAdsState(req, adsProvider);
        if (!adsState || adsState.used) {
          return res.redirect(
            redirectBase +
              "&error=" +
              encodeURIComponent(
                "Selesaikan iklan terlebih dahulu sebelum generate key."
              )
          );
        }
      }

      const ipHeader = req.headers["x-forwarded-for"] || req.ip || "";
      const ip = String(ipHeader).split(",")[0].trim();
      await createFreeKeyRecordPersistent({
        userId,
        provider: adsProvider, // 'workink' atau 'linkvertise'
        ip,
      });

      markAdsUsed(req, adsProvider);

      return res.redirect(redirectBase);
    } catch (err) {
      console.error("[serverv2] generate free key error:", err);
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent("Failed to generate key.")
      );
    }
  });

  // --------------------------------------------------
  // POST /getfreekey/extend – Renew free key
  // --------------------------------------------------
  app.post("/getfreekey/extend", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    const adsProvider = resolveAdsProviderForRequest(req);
    const redirectBase = "/getfreekey?ads=" + encodeURIComponent(adsProvider);

    const token = req.body && req.body.token;

    if (!token) {
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent("Token tidak ditemukan.")
      );
    }

    // Cek banned
    const bannedFlag = await isDiscordUserBanned(userId);
    if (bannedFlag) {
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent(
            "Akun ini telah diblokir. Free key tidak dapat diperpanjang."
          )
      );
    }

    try {
      const rec = await kvGetJson(tokenKey(token));
      if (!rec || String(rec.userId) !== String(userId)) {
        return res.redirect(
          redirectBase +
            "&error=" +
            encodeURIComponent("Key tidak valid untuk akun ini.")
        );
      }

      if (REQUIRE_FREEKEY_ADS_CHECKPOINT) {
        const adsState = getAdsState(req, adsProvider);
        if (!adsState || adsState.used) {
          return res.redirect(
            redirectBase +
              "&error=" +
              encodeURIComponent(
                "Selesaikan iklan terlebih dahulu sebelum renew key."
              )
          );
        }
      }

      await extendFreeKeyPersistent(token);
      markAdsUsed(req, adsProvider);

      return res.redirect(redirectBase);
    } catch (err) {
      console.error("[serverv2] extend free key error:", err);
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent("Failed to renew key.")
      );
    }
  });

  // --------------------------------------------------
  // API: GET /api/freekey/isValidate/:key
  // --------------------------------------------------
  app.get("/api/freekey/isValidate/:key", async (req, res) => {
    const token = (req.params.key || "").trim();
    const now = nowMs();

    if (!token) {
      return res.json({
        valid: false,
        deleted: false,
        expired: false,
        info: null,
      });
    }

    const rec = await kvGetJson(tokenKey(token));

    if (!rec) {
      return res.json({
        valid: false,
        deleted: false,
        expired: false,
        info: null,
      });
    }

    const expired = rec.expiresAfter <= now;
    const deleted = !!rec.deleted;
    const valid = !!rec.valid && !deleted && !expired;

    return res.json({
      valid,
      deleted,
      expired,
      info: {
        token: rec.token,
        createdAt: rec.createdAt,
        byIp: rec.byIp,
        linkId: rec.linkId,
        userId: rec.userId,
        expiresAfter: rec.expiresAfter,
      },
    });
  });

  // --------------------------------------------------
  // API: POST /api/freekey/delete/:key
  // --------------------------------------------------
  app.post("/api/freekey/delete/:key", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;
    const token = (req.params.key || "").trim();

    if (!token) {
      return res.status(400).json({ ok: false, error: "TOKEN_REQUIRED" });
    }

    try {
      const result = await deleteFreeKeyPersistent(token, userId);
      if (!result.ok && result.reason === "USER_MISMATCH") {
        return res
          .status(403)
          .json({ ok: false, error: "NOT_OWNER_OF_KEY" });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("[serverv2] delete free key error:", err);
      return res.status(500).json({ ok: false, error: "INTERNAL_ERROR" });
    }
  });

  // --------------------------------------------------
  // API: POST /api/paidkey/createOrUpdate
  // --------------------------------------------------
  app.post("/api/paidkey/createOrUpdate", async (req, res) => {
    if (!hasFreeKeyKV) {
      return res.status(500).json({ ok: false, error: "KV_NOT_CONFIGURED" });
    }

    const body = req.body || {};
    const info = body.info || {};
    const token = (info.token || "").trim();

    if (!token) {
      return res.status(400).json({
        ok: false,
        error: "TOKEN_REQUIRED",
      });
    }

    const ownerDiscordId =
      body.ownerDiscordId ||
      info.ownerDiscordId ||
      info.discordId ||
      null;

    try {
      const rec = await setPaidKeyRecord({
        token,
        createdAt: info.createdAt,
        byIp: info.byIp,
        expiresAfter: info.expiresAfter,
        type: info.type,
        valid: !!body.valid,
        deleted: !!body.deleted,
        ownerDiscordId,
      });

      return res.json({
        ok: true,
        record: rec,
      });
    } catch (err) {
      console.error("[serverv2] /api/paidkey/createOrUpdate error:", err);
      return res
        .status(500)
        .json({ ok: false, error: "INTERNAL_ERROR" });
    }
  });

  // --------------------------------------------------
  // API: GET /api/paidkey/isValidate/:key
  // --------------------------------------------------
  app.get("/api/paidkey/isValidate/:key", async (req, res) => {
    const token = (req.params.key || "").trim();
    const now = nowMs();

    if (!token) {
      return res.json({
        valid: false,
        deleted: false,
        expired: false,
        info: null,
      });
    }

    try {
      const rec = await getPaidKeyRecord(token);

      if (!rec) {
        return res.json({
          valid: false,
          deleted: false,
          expired: false,
          info: null,
        });
      }

      const expired =
        rec.expiresAfter && typeof rec.expiresAfter === "number"
          ? now > rec.expiresAfter
          : false;
      const deleted = !!rec.deleted;
      const valid = !!rec.valid && !deleted && !expired;

      return res.json({
        valid,
        deleted,
        expired,
        info: {
          token: rec.token,
          createdAt: rec.createdAt,
          byIp: rec.byIp,
          expiresAfter: rec.expiresAfter,
          type: rec.type || null,
          ownerDiscordId: rec.ownerDiscordId || null,
        },
      });
    } catch (err) {
      console.error("[serverv2] /api/paidkey/isValidate error:", err);
      return res.status(500).json({
        valid: false,
        deleted: false,
        expired: false,
        info: null,
        error: "INTERNAL_ERROR",
      });
    }
  });

  // --------------------------------------------------
  // API: POST /api/paidfree/user-info
  //
  // INI yang akan dipanggil bot (EXHUB_USERINFO_URL).
  // --------------------------------------------------
  app.post("/api/paidfree/user-info", async (req, res) => {
    const body = req.body || {};
    const rawId =
      body.discordId ||
      (body.user && body.user.id) ||
      (body.profile && body.profile.id);
    const discordId = rawId ? String(rawId) : null;
    const discordTag = body.discordTag || null;

    if (!discordId) {
      return res.status(400).json({
        ok: false,
        error: "DISCORD_ID_REQUIRED",
      });
    }

    let profile = null;
    if (hasFreeKeyKV) {
      try {
        profile = await kvGetJson(discordUserProfileKey(discordId));
      } catch (err) {
        console.warn("[serverv2] read discord profile KV error:", err);
      }
    }

    let paidKeysRaw = [];
    let freeKeysRaw = [];
    try {
      paidKeysRaw = await getPaidKeysForUserPersistent(discordId);
    } catch (err) {
      console.error(
        "[serverv2] getPaidKeysForUserPersistent (/api/paidfree/user-info) error:",
        err
      );
    }

    try {
      freeKeysRaw = await getFreeKeysForUserPersistent(discordId);
    } catch (err) {
      console.error(
        "[serverv2] getFreeKeysForUserPersistent (/api/paidfree/user-info) error:",
        err
      );
    }

    const now = nowMs();

    const paidKeys = paidKeysRaw
      .map((k) => {
        if (!k) return null;
        const token = String(k.token || k.key || "");
        if (!token) return null;

        const provider = k.provider || "exhub-paid";
        const typeRaw = (k.type || "").toString().toLowerCase();
        const type =
          typeRaw === "month" || typeRaw === "lifetime" ? typeRaw : typeRaw || "paid";
        const tier = k.tier || "Paid";

        const statusStr = (k.status || "").toLowerCase();
        const valid =
          typeof k.valid === "boolean"
            ? k.valid
            : statusStr === "active";
        const deleted =
          typeof k.deleted === "boolean"
            ? k.deleted
            : statusStr === "deleted";
        const expiresAfter =
          typeof k.expiresAfter === "number"
            ? k.expiresAfter
            : typeof k.expiresAtMs === "number"
            ? k.expiresAtMs
            : null;
        const expired =
          typeof k.expired === "boolean"
            ? k.expired
            : expiresAfter
            ? now > expiresAfter
            : false;

        return {
          token,
          key: token,
          provider,
          source: provider,
          tier,
          type,
          createdAt: k.createdAt || null,
          expiresAfter,
          expiresAtMs: expiresAfter,
          valid,
          deleted,
          expired,
          ownerDiscordId: k.ownerDiscordId || discordId,
        };
      })
      .filter(Boolean);

    const freeKeys = freeKeysRaw.map((fk) => {
      const token = fk.token;
      const statusStr = (fk.status || "").toLowerCase();
      const expiresAfter =
        typeof fk.expiresAfter === "number" ? fk.expiresAfter : null;

      const providerLabel = String(fk.provider || "ExHub Free").toLowerCase();
      let provider = "exhub-free";
      if (providerLabel === "work.ink" || providerLabel === "workink") {
        provider = "work.ink";
      } else if (providerLabel.indexOf("linkvertise") !== -1) {
        provider = "linkvertise";
      }

      const expired =
        expiresAfter && typeof expiresAfter === "number"
          ? now > expiresAfter
          : statusStr === "expired";
      const valid = statusStr === "active" && !expired;

      return {
        token,
        key: token,
        provider,
        source: provider,
        tier: "free",
        type: "free",
        createdAt: null,
        expiresAfter,
        expiresAtMs: expiresAfter,
        valid,
        deleted: false,
        expired,
        free: true,
        ownerDiscordId: discordId,
      };
    });

    const allKeys = paidKeys.concat(freeKeys);

    const activeCount = allKeys.filter(
      (k) => k.valid && !k.deleted && !k.expired
    ).length;

    const summary = {
      total: allKeys.length,
      paid: paidKeys.length,
      free: freeKeys.length,
      active: activeCount,
    };

    const banned =
      (profile && profile.banned === true) ||
      (typeof body.banned === "boolean" && body.banned === true)
        ? true
        : false;

    return res.json({
      ok: true,
      discordId,
      discordTag,
      banned,
      profile: profile || null,
      paidKeys,
      freeKeys,
      keys: allKeys, // <-- dicek bot
      summary,
    });
  });

  // --------------------------------------------------
  // API kecil: GET /api/discord/owners
  // (hanya info, tidak dipakai untuk login admin)
  // --------------------------------------------------
  app.get("/api/discord/owners", (req, res) => {
    res.json({ ownerIds: OWNER_IDS });
  });

  // =========================
  // ROUTES – ADMIN DISCORD DASHBOARD & MANAGEMENT
  // =========================
  app.get("/admin/discord", requireAdmin, async (req, res) => {
    const query = (req.query.q || "").trim();
    const filter = req.query.filter || "all";
    const selectedUserParam = req.query.user
      ? String(req.query.user)
      : null;

    const {
      freeKeyUiConfig,
      freeKeyTtlHours,
      paidPlanConfig,
    } = await loadGlobalKeyConfig();

    if (!hasFreeKeyKV) {
      return res.render("admin-dashboarddiscord", {
        title: "Admin – Discord Key Manager",
        totalDiscordUsers: 0,
        totalKeysCount: 0,
        totalPaidKeysCount: 0,
        totalFreeKeysCount: 0,
        activeKeysCount: 0,
        bannedUsersCount: 0,
        query,
        filter,
        userStats: [],
        selectedUser: null,
        selectedUserSummary: null,
        selectedUserKeys: [],
        freeKeyUiConfig,
        freeKeyTtlHours,
        paidPlanConfig,
      });
    }

    let discordIds = [];
    try {
      discordIds = await getAllDiscordUserIds();
    } catch (err) {
      console.error("[serverv2] getAllDiscordUserIds error:", err);
      discordIds = [];
    }

    const perUserData = [];
    let totalKeysCount = 0;
    let totalPaidKeysCount = 0;
    let totalFreeKeysCount = 0;
    let activeKeysCount = 0;
    let bannedUsersCount = 0;

    for (const discordId of discordIds) {
      try {
        const [profileRaw, paidKeysRaw, freeKeysRaw] = await Promise.all([
          getDiscordUserProfile(discordId),
          getPaidKeysForUserPersistent(discordId),
          getFreeKeysForUserPersistent(discordId),
        ]);

        if (
          !profileRaw &&
          (!paidKeysRaw || paidKeysRaw.length === 0) &&
          (!freeKeysRaw || freeKeysRaw.length === 0)
        ) {
          continue;
        }

        const profile = profileRaw || { id: discordId };
        const normalizedPaid = (paidKeysRaw || [])
          .map((k) => normalizePaidKeyForAdmin(k, discordId))
          .filter(Boolean);
        const normalizedFree = (freeKeysRaw || [])
          .map((fk) => normalizeFreeKeyForAdmin(fk, discordId))
          .filter(Boolean);

        const keysAll = normalizedPaid.concat(normalizedFree);

        const summary = {
          total: keysAll.length,
          paid: normalizedPaid.length,
          free: normalizedFree.length,
          active: keysAll.filter((k) => k.status === "Active").length,
        };

        const lastLoginAtMs =
          typeof profile.lastLoginAt === "number"
            ? profile.lastLoginAt
            : null;
        const loginLabels = lastLoginAtMs
          ? formatDualTimeLabelMs(lastLoginAtMs)
          : { wita: null, wib: null, label: null };

        const latestExpireMs = keysAll.reduce((max, k) => {
          if (!k.expiresAtMs || typeof k.expiresAtMs !== "number")
            return max;
          return k.expiresAtMs > max ? k.expiresAtMs : max;
        }, 0);

        const expireLabels = latestExpireMs
          ? formatDualTimeLabelMs(latestExpireMs)
          : { wita: null, wib: null, label: null };

        const banned = !!profile.banned;

        if (banned) bannedUsersCount++;
        totalKeysCount += summary.total;
        totalPaidKeysCount += summary.paid;
        totalFreeKeysCount += summary.free;
        activeKeysCount += summary.active;

        const username = profile.username || "Unknown";
        const globalName = profile.global_name || username;
        const discriminator = profile.discriminator || "0000";
        const tag = `${username}#${discriminator}`;
        const avatarUrl = makeDiscordAvatarUrl(profile);
        const bannerUrl = makeDiscordBannerUrl(profile);
        const email = profile.email || null;

        perUserData.push({
          discordId,
          username,
          globalName,
          discriminator,
          tag,
          avatarUrl,
          bannerUrl,
          email,
          guildCount: profile.guildCount || 0,
          banned,
          lastLoginAtMs,
          lastLoginAtWITA: loginLabels.wita,
          lastLoginAtWIB: loginLabels.wib,
          lastLoginAtLabel: loginLabels.label,
          lastKeyExpiresAtMs: latestExpireMs || null,
          lastKeyExpiresAtWITA: expireLabels.wita,
          lastKeyExpiresAtWIB: expireLabels.wib,
          lastKeyExpiresAtLabel: expireLabels.label,
          summary,
          keysAll,
        });
      } catch (err) {
        console.error(
          "[serverv2] build perUserData error for id=",
          discordId,
          err
        );
      }
    }

    const totalDiscordUsers = perUserData.length;

    // Build userStats untuk tabel overview
    let userStats = perUserData.map((d) => ({
      discordId: d.discordId,
      username: d.username,
      globalName: d.globalName,
      discriminator: d.discriminator,
      tag: d.tag,
      avatarUrl: d.avatarUrl,
      guildCount: d.guildCount,
      totalKeys: d.summary.total,
      paidKeys: d.summary.paid,
      freeKeys: d.summary.free,
      activeKeys: d.summary.active,
      lastLoginAtWITA: d.lastLoginAtWITA,
      lastLoginAtWIB: d.lastLoginAtWIB,
      lastLoginAtLabel: d.lastLoginAtLabel,
      lastKeyExpiresAtWITA: d.lastKeyExpiresAtWITA,
      lastKeyExpiresAtWIB: d.lastKeyExpiresAtWIB,
      lastKeyExpiresAtLabel: d.lastKeyExpiresAtLabel,
      banned: d.banned,
    }));

    // Filter search
    if (query) {
      const qLower = query.toLowerCase();
      userStats = userStats.filter((row) => {
        if (
          row.discordId &&
          String(row.discordId).toLowerCase().includes(qLower)
        )
          return true;
        if (row.username && row.username.toLowerCase().includes(qLower))
          return true;
        if (row.globalName && row.globalName.toLowerCase().includes(qLower))
          return true;
        if (row.tag && row.tag.toLowerCase().includes(qLower)) return true;
        return false;
      });
    }

    // Filter status
    let filteredIds = userStats.map((u) => u.discordId);
    if (filter === "hasKeys") {
      userStats = userStats.filter((u) => (u.totalKeys || 0) > 0);
    } else if (filter === "noKeys") {
      userStats = userStats.filter((u) => (u.totalKeys || 0) === 0);
    } else if (filter === "banned") {
      userStats = userStats.filter((u) => !!u.banned);
    } else if (filter === "notBanned") {
      userStats = userStats.filter((u) => !u.banned);
    }
    filteredIds = userStats.map((u) => u.discordId);

    // Tentukan selectedUser
    let selectedUserId = null;
    if (selectedUserParam && filteredIds.includes(selectedUserParam)) {
      selectedUserId = selectedUserParam;
    } else if (!selectedUserParam && filteredIds.length > 0) {
      selectedUserId = filteredIds[0];
    }

    let selectedUser = null;
    let selectedUserSummary = null;
    let selectedUserKeys = [];

    if (selectedUserId) {
      const data = perUserData.find((d) => d.discordId === selectedUserId);
      if (data) {
        selectedUser = {
          discordId: data.discordId,
          username: data.username,
          globalName: data.globalName,
          discriminator: data.discriminator,
          tag: data.tag,
          avatarUrl: data.avatarUrl,
          bannerUrl: data.bannerUrl,
          email: data.email,
          guildCount: data.guildCount,
          banned: data.banned,
          lastLoginAtWITA: data.lastLoginAtWITA,
          lastLoginAtWIB: data.lastLoginAtWIB,
          lastLoginAtLabel: data.lastLoginAtLabel,
        };
        selectedUserSummary = data.summary;
        selectedUserKeys = data.keysAll;
      }
    }

    res.render("admin-dashboarddiscord", {
      title: "Admin – Discord Key Manager",
      totalDiscordUsers,
      totalKeysCount,
      totalPaidKeysCount,
      totalFreeKeysCount,
      activeKeysCount,
      bannedUsersCount,
      query,
      filter,
      userStats,
      selectedUser,
      selectedUserSummary,
      selectedUserKeys,
      freeKeyUiConfig,
      freeKeyTtlHours,
      paidPlanConfig,
    });
  });

  // Simpan global config (UI Get Free Key + TTL)
  app.post(
    "/admin/discord/save-global-key-config",
    requireAdmin,
    async (req, res) => {
      const body = req.body || {};

      const heroSubtext = (body.heroSubtext || "").trim();
      const bullet1 = (body.bullet1 || "").trim();
      const bullet2 = (body.bullet2 || "").trim();
      const validityLabel = (body.validityLabel || "").trim();
      const workinkDescription = (body.workinkDescription || "").trim();
      const linkvertiseDescription = (body.linkvertiseDescription || "").trim();

      let freeKeyTtlHours = parseInt(body.freeKeyTtlHours, 10);
      if (!Number.isFinite(freeKeyTtlHours) || freeKeyTtlHours <= 0) {
        freeKeyTtlHours = FREE_KEY_TTL_DEFAULT_HOURS;
      }
      if (freeKeyTtlHours > 72) freeKeyTtlHours = 72;

      let paidMonthDays = parseInt(body.paidMonthDays, 10);
      if (!Number.isFinite(paidMonthDays) || paidMonthDays <= 0) {
        paidMonthDays = PAID_MONTH_DEFAULT_DAYS;
      }
      if (paidMonthDays > 730) paidMonthDays = 730;

      let paidLifetimeDays = parseInt(body.paidLifetimeDays, 10);
      if (!Number.isFinite(paidLifetimeDays) || paidLifetimeDays <= 0) {
        paidLifetimeDays = PAID_LIFETIME_DEFAULT_DAYS;
      }
      if (paidLifetimeDays > 3650) paidLifetimeDays = 3650;

      const freeKeyUiConfig = {
        ttlHours: freeKeyTtlHours,
        freeKeyTtlHours,
        global: {
          dashboardCaption: heroSubtext,
          heroSubtext,
          bullet1,
          bullet2,
          validityLabel,
        },
        workink: {
          dashboardDescription: workinkDescription,
        },
        linkvertise: {
          dashboardDescription: linkvertiseDescription,
        },
      };

      const paidPlanConfig = {
        monthDays: paidMonthDays,
        lifetimeDays: paidLifetimeDays,
      };

      try {
        await Promise.all([
          kvSetJson(FREE_KEY_UI_CONFIG_KEY, freeKeyUiConfig),
          kvSetJson(PAID_PLAN_CONFIG_KEY, paidPlanConfig),
        ]);

        // update cache in-memory
        cachedFreeKeyUiConfig = freeKeyUiConfig;
        cachedPaidPlanConfig = paidPlanConfig;
        cachedGlobalConfigLoadedAt = nowMs();
      } catch (err) {
        console.error(
          "[serverv2] save-global-key-config error (masih pakai nilai lama jika gagal):",
          err
        );
      }

      res.redirect("/admin/discord");
    }
  );

  // Ban user
  app.post("/admin/discord/ban-user", requireAdmin, async (req, res) => {
    const discordId = (req.body.discordId || "").trim();
    if (!discordId) {
      return res.redirect("/admin/discord");
    }

    try {
      await setDiscordUserProfilePersistent(discordId, { banned: true });
    } catch (err) {
      console.error("[serverv2] ban-user error:", err);
    }

    res.redirect("/admin/discord?user=" + encodeURIComponent(discordId));
  });

  // Unban user
  app.post("/admin/discord/unban-user", requireAdmin, async (req, res) => {
    const discordId = (req.body.discordId || "").trim();
    if (!discordId) {
      return res.redirect("/admin/discord");
    }

    try {
      await setDiscordUserProfilePersistent(discordId, { banned: false });
    } catch (err) {
      console.error("[serverv2] unban-user error:", err);
    }

    res.redirect("/admin/discord?user=" + encodeURIComponent(discordId));
  });

  // Delete semua key user
  app.post(
    "/admin/discord/delete-user-keys",
    requireAdmin,
    async (req, res) => {
      const discordId = (req.body.discordId || "").trim();
      if (!discordId) {
        return res.redirect("/admin/discord");
      }

      try {
        // Free keys
        const freeIdxKey = userIndexKey(discordId);
        const freeTokens = await kvGetJson(freeIdxKey);
        if (Array.isArray(freeTokens)) {
          for (const t of freeTokens) {
            if (!t) continue;
            try {
              await deleteFreeKeyPersistent(t, discordId);
            } catch (err) {
              console.error(
                "[serverv2] delete-user-keys free token error:",
                t,
                err
              );
            }
          }
          // kosongkan index (walaupun deleteFreeKeyPersistent sudah bersihkan)
          await kvSetJson(freeIdxKey, []);
        }

        // Paid keys
        const paidIdxKey = paidUserIndexKey(discordId);
        const paidTokens = await kvGetJson(paidIdxKey);
        if (Array.isArray(paidTokens)) {
          for (const t of paidTokens) {
            if (!t) continue;
            try {
              const rec = await getPaidKeyRecord(t);
              if (!rec) continue;
              await setPaidKeyRecord({
                token: t,
                createdAt: rec.createdAt,
                byIp: rec.byIp,
                expiresAfter: rec.expiresAfter,
                type: rec.type,
                valid: false,
                deleted: true,
                ownerDiscordId: discordId,
              });
            } catch (err) {
              console.error(
                "[serverv2] delete-user-keys paid token error:",
                t,
                err
              );
            }
          }
          await kvSetJson(paidIdxKey, []);
        }
      } catch (err) {
        console.error("[serverv2] delete-user-keys error:", err);
      }

      res.redirect("/admin/discord?user=" + encodeURIComponent(discordId));
    }
  );

  // Update 1 key (createdAt + time left TTL)
  app.post("/admin/discord/update-key", requireAdmin, async (req, res) => {
    const discordId = (req.body.discordId || "").trim();
    const token = (req.body.token || "").trim();
    const createdAtRaw = req.body.createdAt;
    const expiresTTLRaw = req.body.expiresAt; // HH:MM:SS

    if (!discordId || !token) {
      return res.redirect("/admin/discord");
    }

    const redirectUrl =
      "/admin/discord?user=" + encodeURIComponent(discordId);

    try {
      const now = nowMs();
      const newCreatedMs = parseDateOrTimestamp(createdAtRaw);
      const ttlMs = parseHHMMSS(expiresTTLRaw);
      const newExpiresMs =
        ttlMs && ttlMs > 0 ? now + ttlMs : null;

      let paidRec = await getPaidKeyRecord(token);
      let freeRec = null;
      if (!paidRec) {
        freeRec = await kvGetJson(tokenKey(token));
      }

      if (!paidRec && !freeRec) {
        return res.redirect(redirectUrl);
      }

      if (paidRec) {
        const updated = {
          token,
          createdAt: newCreatedMs || paidRec.createdAt || now,
          byIp: paidRec.byIp,
          expiresAfter:
            newExpiresMs !== null
              ? newExpiresMs
              : paidRec.expiresAfter || 0,
          type: paidRec.type,
          valid: paidRec.valid,
          deleted: paidRec.deleted,
          ownerDiscordId: paidRec.ownerDiscordId || discordId,
        };
        await setPaidKeyRecord(updated);
      } else if (freeRec) {
        if (String(freeRec.userId) !== String(discordId)) {
          console.warn(
            "[serverv2] update-key: free key user mismatch, tetap update sebagai admin.",
            token,
            freeRec.userId,
            discordId
          );
        }
        if (newCreatedMs) {
          freeRec.createdAt = newCreatedMs;
        }
        if (newExpiresMs !== null) {
          freeRec.expiresAfter = newExpiresMs;
        }
        const expired = freeRec.expiresAfter <= now;
        freeRec.deleted = freeRec.deleted || false;
        freeRec.valid = !freeRec.deleted && !expired;
        await kvSetJson(tokenKey(token), freeRec);
      }
    } catch (err) {
      console.error("[serverv2] update-key error:", err);
    }

    res.redirect(redirectUrl);
  });

  // Renew 1 key (extend expiry)
  app.post("/admin/discord/renew-key", requireAdmin, async (req, res) => {
    const discordId = (req.body.discordId || "").trim();
    const token = (req.body.token || "").trim();

    if (!discordId || !token) {
      return res.redirect("/admin/discord");
    }

    const redirectUrl =
      "/admin/discord?user=" + encodeURIComponent(discordId);

    try {
      const now = nowMs();
      let paidRec = await getPaidKeyRecord(token);
      let freeRec = null;
      if (!paidRec) {
        freeRec = await kvGetJson(tokenKey(token));
      }

      if (!paidRec && !freeRec) {
        return res.redirect(redirectUrl);
      }

      if (paidRec) {
        const typeRaw = (paidRec.type || "").toLowerCase();
        const { monthMs, lifetimeMs } = await getPaidDurationsMs();

        let durationMs;
        if (typeRaw === "month") {
          durationMs = monthMs;
        } else if (typeRaw === "lifetime") {
          durationMs = lifetimeMs;
        } else {
          durationMs = monthMs;
        }

        const newExpires = now + durationMs;
        await setPaidKeyRecord({
          token,
          createdAt: paidRec.createdAt || now,
          byIp: paidRec.byIp,
          expiresAfter: newExpires,
          type: paidRec.type,
          valid: true,
          deleted: false,
          ownerDiscordId: paidRec.ownerDiscordId || discordId,
        });
      } else if (freeRec) {
        await extendFreeKeyPersistent(token);
      }
    } catch (err) {
      console.error("[serverv2] renew-key error:", err);
    }

    res.redirect(redirectUrl);
  });

  // Delete 1 key (paid / free) untuk 1 user di admin-dashboarddiscord
  app.post("/admin/discord/delete-key", requireAdmin, async (req, res) => {
    const discordId = (req.body.discordId || "").trim();
    const token = (req.body.token || "").trim();

    if (!discordId || !token) {
      return res.redirect("/admin/discord");
    }

    const redirectUrl =
      "/admin/discord?user=" + encodeURIComponent(discordId);

    try {
      // 1) Paid key: tandai deleted + invalid + bersihkan index paid
      let paidRec = await getPaidKeyRecord(token);
      if (paidRec) {
        await setPaidKeyRecord({
          token,
          createdAt: paidRec.createdAt,
          byIp: paidRec.byIp,
          expiresAfter: paidRec.expiresAfter,
          type: paidRec.type,
          valid: false,
          deleted: true,
          ownerDiscordId: paidRec.ownerDiscordId || discordId,
        });

        try {
          const paidIdxKey = paidUserIndexKey(discordId);
          const paidTokens = await kvGetJson(paidIdxKey);
          if (Array.isArray(paidTokens)) {
            const filteredPaid = paidTokens.filter((t) => t && t !== token);
            await kvSetJson(paidIdxKey, filteredPaid);
          }
        } catch (err2) {
          console.error(
            "[serverv2] delete-key: cleanup paid index error:",
            err2
          );
        }
      }

      // 2) Free key: delete + bersihkan index via deleteFreeKeyPersistent
      const freeRec = await kvGetJson(tokenKey(token));
      if (freeRec && String(freeRec.userId) === String(discordId)) {
        await deleteFreeKeyPersistent(token, discordId);
      }
    } catch (err) {
      console.error("[serverv2] delete-key error:", err);
    }

    res.redirect(redirectUrl);
  });

  // =========================
  // ROUTES – DISCORD OAUTH2
  // =========================

  app.get("/auth/discord", (req, res) => {
    const state = crypto.randomBytes(16).toString("hex");
    if (req.session) {
      req.session.oauthState = state;
    }
    const url = makeDiscordAuthUrl(state);
    res.redirect(url);
  });

  app.get("/auth/discord/callback", async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
      console.error("Discord OAuth error:", error);
      return res.redirect("/discord-login?error=oauth");
    }

    if (!code) {
      return res.redirect("/discord-login?error=nocode");
    }

    if (!req.session || !state || state !== req.session.oauthState) {
      console.warn("[serverv2] Invalid OAuth state.");
      return res.redirect("/discord-login?error=state");
    }

    req.session.oauthState = null;

    try {
      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_REDIRECT_URI,
        }),
      });

      const tokenText = await tokenRes.text();
      if (!tokenRes.ok) {
        console.error(
          "[serverv2] Token error:",
          tokenRes.status,
          tokenText.slice(0, 200)
        );
        return res.redirect("/discord-login?error=token");
      }

      let tokenData;
      try {
        tokenData = JSON.parse(tokenText);
      } catch {
        console.error("[serverv2] Token JSON parse error:", tokenText);
        return res.redirect("/discord-login?error=tokenjson");
      }

      const accessToken = tokenData.access_token;
      if (!accessToken) {
        console.error("[serverv2] access_token kosong.");
        return res.redirect("/discord-login?error=tokenempty");
      }

      const userRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const userText = await userRes.text();
      if (!userRes.ok) {
        console.error(
          "[serverv2] User error:",
          userRes.status,
          userText.slice(0, 200)
        );
        return res.redirect("/discord-login?error=user");
      }

      let user;
      try {
        user = JSON.parse(userText);
      } catch {
        console.error("[serverv2] User JSON parse error:", userText);
        return res.redirect("/discord-login?error=userjson");
      }

      let guildCount = 0;
      try {
        const guildRes = await fetch(
          "https://discord.com/api/users/@me/guilds",
          {
            headers: { Authorization: `Bearer ${accessToken}` },
          }
        );
        if (guildRes.ok) {
          const guilds = await guildRes.json();
          if (Array.isArray(guilds)) guildCount = guilds.length;
        }
      } catch {
        // tidak fatal
      }

      const isOwner = isOwnerId(user.id); // hanya untuk badge, bukan login admin

      req.session.discordUser = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || user.username,
        discriminator: user.discriminator,
        avatar: user.avatar,
        email: user.email,
        guildCount,
        banner: user.banner || null,
        isOwner,
      };

      if (hasFreeKeyKV) {
        try {
          await setDiscordUserProfilePersistent(user.id, {
            id: user.id,
            username: user.username,
            global_name: user.global_name || user.username,
            discriminator: user.discriminator,
            avatar: user.avatar,
            banner: user.banner || null,
            email: user.email || null,
            guildCount,
            lastLoginAt: nowMs(),
            isOwner,
          });
        } catch (e) {
          console.warn("[serverv2] gagal simpan profil discord ke KV:", e);
        }
      }

      res.redirect("/dashboard");
    } catch (err) {
      console.error("[serverv2] OAuth callback exception:", err);
      res.redirect("/discord-login?error=exception");
    }
  });

  app.post("/logout", (req, res) => {
    if (req.session) {
      req.session.discordUser = null;
    }
    res.redirect("/");
  });

  app.get("/logout", (req, res) => {
    if (req.session) {
      req.session.discordUser = null;
    }
    res.redirect("/");
  });

  console.log(
    "[serverv2] Discord OAuth + Dashboard + GetFreeKey + FreeKey API + PaidKey API + PaidFree User-Info API + Admin Discord Dashboard routes mounted (admin via session)."
  );
};
