// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key + Paid Key API
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

// ---------------------------------------------------------
// Helper: base API ExHub (sama pola dengan index.js bot / server.js)
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
// Upstash KV khusus Free Key & Paid Key
// ---------------------------------------------------------
const KV_REST_API_URL = process.env.KV_REST_API_URL;
const KV_REST_API_TOKEN = process.env.KV_REST_API_TOKEN;
const hasFreeKeyKV = !!(KV_REST_API_URL && KV_REST_API_TOKEN);

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

// ---------------------------------------------------------
// Konfigurasi Free Key (persisten via Upstash)
// ---------------------------------------------------------

const FREE_KEY_PREFIX = "EXHUBFREE";
const FREE_KEY_TTL_HOURS = 3;
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
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;
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

  const now = nowMs();
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;

  rec.expiresAfter = now + ttlMs;
  rec.valid = true;
  rec.deleted = false;

  await kvSetJson(key, rec);
  return rec;
}

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

    const timeLeftLabel = isExpired
      ? "Expired"
      : msLeft < 1000
      ? "< 1s"
      : msLeft < 60 * 1000
      ? Math.floor(msLeft / 1000) + "s"
      : msLeft < 60 * 60 * 1000
      ? Math.floor(msLeft / 60000) + "m"
      : Math.floor(msLeft / 3600000) + "h";

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
//  - Record per token: exhub:paidkey:token:<KEY>
//  - Index per user:   exhub:paidkey:user:<discordId> -> [KEY, ...]
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

/**
 * Simpan record PaidKey:
 *  - token
 *  - expiresAfter
 *  - type: 'month' | 'lifetime'
 *  - valid: false (belum redeem) / true (sudah redeem)
 *  - deleted: soft delete
 *  - ownerDiscordId: pemilik (supaya bisa muncul di dashboard akun yang sama)
 */
async function setPaidKeyRecord(payload) {
  if (!payload || !payload.token) return null;

  const now = nowMs();
  const token = payload.token;
  const ownerDiscordId = payload.ownerDiscordId
    ? String(payload.ownerDiscordId)
    : null;

  // baca record lama kalau ada (untuk preserve createdAt / expiresAfter kalau tidak dikirim)
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

  // hapus token dari index owner lama jika pindah
  if (previousOwnerId && previousOwnerId !== newOwnerId) {
    const oldIdxKey = paidUserIndexKey(previousOwnerId);
    let oldIdx = await kvGetJson(oldIdxKey);
    if (Array.isArray(oldIdx)) {
      const filtered = oldIdx.filter((t) => t !== token);
      await kvSetJson(oldIdxKey, filtered);
    }
  }

  // tambahkan ke index owner baru
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

/**
 * Ambil semua PaidKey milik Discord ID tertentu (untuk dashboard & /api/bot/user-info).
 */
async function getPaidKeysForUserPersistent(discordId) {
  if (!hasFreeKeyKV) return [];

  const idxKey = paidUserIndexKey(discordId);
  const index = await kvGetJson(idxKey);
  const tokens = Array.isArray(index) ? index : [];
  const now = nowMs();
  const result = [];

  for (const token of tokens) {
    if (!token) continue;
    const raw = await kvGetJson(paidTokenKey(token));
    if (!raw) continue;
    const rec = normalizePaidKeyRecord(raw);
    if (!rec) continue;

    const expired =
      rec.expiresAfter && typeof rec.expiresAfter === "number"
        ? now > rec.expiresAfter
        : false;
    const deleted = !!rec.deleted;

    let providerLabel = "ExHub Paid";
    const t = (rec.type || "").toString().toLowerCase();
    if (t === "month") providerLabel = "PAID MONTH";
    else if (t === "lifetime") providerLabel = "PAID LIFETIME";

    let statusLabel;
    if (deleted) statusLabel = "Deleted";
    else if (expired) statusLabel = "Expired";
    else if (rec.valid) statusLabel = "Active";
    else statusLabel = "Pending";

    result.push({
      key: rec.token,
      provider: providerLabel,
      timeLeft: "",
      status: statusLabel,
      tier: "Paid",
      expiresAtMs: rec.expiresAfter || null,
      expiresAfter: rec.expiresAfter || null,
      valid: rec.valid,
      expired,
      deleted,
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

  const EXHUB_API_BASE = resolveExHubApiBase();

  const WORKINK_ADS_URL =
    process.env.WORKINK_ADS_URL || "https://work.ink/23P2/exhubfreekey";
  const LINKVERTISE_ADS_URL =
    process.env.LINKVERTISE_ADS_URL ||
    "https://link-target.net/2995260/uaE3u7P8CG5D";

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
  // MIDDLEWARE: res.locals.user
  // =========================
  app.use((req, res, next) => {
    const user = (req.session && req.session.discordUser) || null;
    res.locals.user = user;
    res.locals.isOwner = user ? isOwnerId(user.id) : false;
    res.locals.ownerIds = OWNER_IDS;
    next();
  });

  // =========================
  // HELPER
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

  function requireAuth(req, res, next) {
    if (!req.session || !req.session.discordUser) {
      return res.redirect("/login-required");
    }
    next();
  }

  function requireOwner(req, res, next) {
    if (!req.session || !req.session.discordUser) {
      return res.redirect("/login-required");
    }
    if (!isOwnerId(req.session.discordUser.id)) {
      return res.status(403).send("Forbidden: Owner only");
    }
    next();
  }

  // Ambil data key user untuk Dashboard (web)
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

    // OPTIONAL: Ambil status banned dari API utama (jika ada)
    try {
      const url = new URL("bot/user-info", EXHUB_API_BASE);
      const payload = {
        discordId: discordUser.id,
        discordTag: discordUser.username,
      };

      const res = await fetch(url.toString(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const text = await res.text();
      if (!res.ok) {
        console.warn(
          "[serverv2] /api/bot/user-info gagal:",
          res.status,
          text.slice(0, 200)
        );
      } else {
        let data;
        try {
          data = JSON.parse(text);
        } catch {
          data = null;
        }
        if (data && typeof data.banned === "boolean") {
          bannedFlag = data.banned;
        }
      }
    } catch (err) {
      console.error("[serverv2] getUserKeys API error:", err);
    }

    // --- Paid keys dari KV PaidKey (integrasi langsung dengan bot) ---
    let paidKeys = [];
    try {
      paidKeys = await getPaidKeysForUserPersistent(discordUser.id);
    } catch (err) {
      console.error("[serverv2] getPaidKeysForUserPersistent error:", err);
    }

    // --- Free keys dari KV FreeKey ---
    let freeKeys = [];
    try {
      freeKeys = await getFreeKeysForUserPersistent(discordUser.id);
    } catch (err) {
      console.error("[serverv2] getFreeKeysForUserPersistent error:", err);
    }

    const normalizedFree = freeKeys.map((fk) => ({
      key: fk.token,
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
  // ROUTES – DASHBOARD & PAGE WAJIB LOGIN
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
    const queryAds = req.query.ads || "workink";
    let adsProvider = canonicalAdsProvider(queryAds);

    if (req.session) {
      if (queryAds) {
        req.session.lastFreeKeyAdsProvider = adsProvider;
      } else if (!queryAds && req.session.lastFreeKeyAdsProvider) {
        adsProvider = canonicalAdsProvider(req.session.lastFreeKeyAdsProvider);
      }
    }

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

    const allowGenerate =
      capacityOk &&
      (!REQUIRE_FREEKEY_ADS_CHECKPOINT || (adsProgressDone && !adsUsed));

    const canRenew =
      keys.length > 0 &&
      (!REQUIRE_FREEKEY_ADS_CHECKPOINT || (adsProgressDone && !adsUsed));

    const errorMessage = req.query.error || null;

    res.render("getfreekey", {
      title: "ExHub — Get Free Key",
      user: discordUser,
      adsProvider,
      adsUrl,
      keys,
      maxKeys,
      defaultKeyHours: FREE_KEY_TTL_HOURS,
      allowGenerate,
      canRenew,
      adsProgressDone,
      adsUsedFlag: adsUsed,
      currentUserId: userId,
      keyAction: "/getfreekey/generate",
      renewAction: "/getfreekey/extend",
      errorMessage,
    });
  });

  // --------------------------------------------------
  // POST /getfreekey/generate
  // --------------------------------------------------
  app.post("/getfreekey/generate", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;
    const adsProvider = canonicalAdsProvider(req.query.ads || "workink");

    const redirectBase = "/getfreekey?ads=" + encodeURIComponent(adsProvider);

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
        provider: adsProvider,
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
    const adsProvider = canonicalAdsProvider(req.query.ads || "workink");
    const redirectBase = "/getfreekey?ads=" + encodeURIComponent(adsProvider);

    const token = req.body && req.body.token;

    if (!token) {
      return res.redirect(
        redirectBase +
          "&error=" +
          encodeURIComponent("Token tidak ditemukan.")
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
  //
  // Dipanggil dari Discord Bot:
  // {
  //   "valid": false,
  //   "deleted": false,
  //   "expired": false,
  //   "ownerDiscordId": "1234567890",   // <- wajib diisi agar ter-link ke akun dashboard
  //   "info": {
  //     "token": "EXHUBPAID-XXXX",
  //     "createdAt": 1736930000000,
  //     "byIp": "discord-bot",
  //     "expiresAfter": 1739522000000,
  //     "type": "month" | "lifetime",
  //     "ownerDiscordId": "1234567890"  // optional mirror
  //   }
  // }
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
  // API: POST /api/bot/user-info
  //  Dipakai oleh:
  //   - Dashboard (opsional untuk banned / profil)
  //   - Discord Bot (/mykey, /checkmykey, fetchUserPaidKeys)
// --------------------------------------------------
  app.post("/api/bot/user-info", async (req, res) => {
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
      console.error("[serverv2] getPaidKeysForUserPersistent (user-info) error:", err);
    }

    try {
      freeKeysRaw = await getFreeKeysForUserPersistent(discordId);
    } catch (err) {
      console.error("[serverv2] getFreeKeysForUserPersistent (user-info) error:", err);
    }

    const now = nowMs();

    // Normalisasi paid keys → bentuk flat yang mudah dibaca bot
    const paidKeys = paidKeysRaw
      .map((k) => {
        if (!k) return null;
        const token = String(k.token || k.key || "");
        if (!token) return null;

        const provider = k.provider || "exhub-paid";
        const typeRaw = (k.type || "").toString().toLowerCase();
        const type =
          typeRaw === "month" || typeRaw === "lifetime" ? typeRaw : typeRaw || "paid";
        const tier = k.tier || (type === "month" || type === "lifetime" ? "Paid" : "Paid");

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

    // Normalisasi free keys → diberi type/tier "free" & provider work.ink / linkvertise
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
      keys: allKeys,
      summary,
    });
  });

  // --------------------------------------------------
  // API kecil: GET /api/discord/owners
  // --------------------------------------------------
  app.get("/api/discord/owners", (req, res) => {
    res.json({ ownerIds: OWNER_IDS });
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

      const isOwner = isOwnerId(user.id);

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
          await kvSetJson(discordUserProfileKey(user.id), {
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
    "[serverv2] Discord OAuth + Dashboard + GetFreeKey + FreeKey API + PaidKey API + Bot User-Info API routes mounted."
  );
};
