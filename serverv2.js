// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key
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
// Upstash KV khusus Free Key
// Pola DISESUAIKAN dengan server.js:
// - KV_REST_API_URL = base URL
// - GET:  {KV_REST_API_URL}/GET/<key>
// - SET:  {KV_REST_API_URL}/SET/<key>/<value>
// Header Authorization: Bearer KV_REST_API_TOKEN
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
// Konfigurasi Free Key (persisten via Upstash, mirip pola server.js)
// ---------------------------------------------------------

const FREE_KEY_PREFIX = "EXHUBFREE";
// TTL default free key (jam) – terpisah dari defaultKeyHours generate key biasa
const FREE_KEY_TTL_HOURS = 3;
const FREE_KEY_MAX_PER_USER = 5;

// REQUIREFREEKEY_ADS_CHECKPOINT = "1" (default) → wajib iklan dulu
const REQUIRE_FREEKEY_ADS_CHECKPOINT =
  String(process.env.REQUIREFREEKEY_ADS_CHECKPOINT || "1") === "1";

// Cooldown anti spam "Open" dari provider (ms). Default 5 menit.
const FREEKEY_ADS_COOLDOWN_MS = Number(
  process.env.FREEKEY_ADS_COOLDOWN_MS || 5 * 60 * 1000
);

function nowMs() {
  return Date.now();
}

// Prefix key di Upstash (disamakan pola "exhub:*" seperti server.js)
function userIndexKey(userId) {
  return `exhub:freekey:user:${userId}`;
}

function tokenKey(token) {
  return `exhub:freekey:token:${token}`;
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

// Buat record baru di KV (token unik)
async function createFreeKeyRecordPersistent({ userId, provider, ip }) {
  const createdAt = nowMs();
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;
  const expiresAfter = createdAt + ttlMs;

  let token;
  // pastikan unik di KV (kemungkinan tabrakan kecil, tapi aman)
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

  // Simpan record token
  await kvSetJson(tokenKey(token), rec);

  // Update index per-user (array token)
  const idxKey = userIndexKey(userId);
  let index = await kvGetJson(idxKey);
  if (!Array.isArray(index)) index = [];
  if (!index.includes(token)) {
    index.push(token);
    await kvSetJson(idxKey, index);
  }

  return rec;
}

// Perpanjang TTL sebuah token
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

// Tandai free key sebagai deleted (untuk endpoint delete)
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

// Ambil semua free key milik user dari KV
// Return: [{ token, provider, timeLeftLabel, status, expiresAfter, tier }]
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

    // Skip jika sudah dihapus
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

    // Normalisasi provider untuk tampilan
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

  // Sort: Active dulu, lalu yang paling dekat expired
  result.sort((a, b) => {
    const sa = a.status === "Active" ? 0 : 1;
    const sb = b.status === "Active" ? 0 : 1;
    if (sa !== sb) return sa - sb;
    return a.expiresAfter - b.expiresAfter;
  });

  return result;
}

// ---------------------------------------------------------
// Helper: Ads / checkpoint state di session (per provider)
// Struktur: req.session.freeKeyAdsState = {
//   workink:    { ts: <number>, used: <bool> },
//   linkvertise:{ ts: <number>, used: <bool> }
// }
// 1 checkpoint = 1 aksi (Generate ATAU Renew)
// ts: waktu terakhir checkpoint dibuat
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
  // Tidak ubah ts di sini, supaya ts tetap waktu checkpoint terakhir
  prev.used = true;
  req.session.freeKeyAdsState[provider] = prev;
}

// ---------------------------------------------------------
// Modul utama: mount ke Express app (dipanggil dari server.js)
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

  // URL iklan Work.ink & Linkvertise (untuk tombol START)
  const WORKINK_ADS_URL =
    process.env.WORKINK_ADS_URL || "https://work.ink/23P2/exhubfreekey";
  const LINKVERTISE_ADS_URL =
    process.env.LINKVERTISE_ADS_URL ||
    "https://link-target.net/2995260/uaE3u7P8CG5D";

  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    console.warn(
      "[serverv2] DISCORD_CLIENT_ID atau DISCORD_CLIENT_SECRET belum diset. " +
        "Fitur Discord Login tidak akan bekerja dengan benar."
    );
  }

  if (!hasFreeKeyKV) {
    console.warn(
      "[serverv2] PERINGATAN: KV_REST_API_URL / KV_REST_API_TOKEN tidak diset – Free Key TIDAK akan persisten."
    );
  }

  // =========================
  // MIDDLEWARE: res.locals.user (untuk header EJS, dll)
  // =========================
  app.use((req, res, next) => {
    res.locals.user = (req.session && req.session.discordUser) || null;
    next();
  });

  // =========================
  // HELPER
  // =========================

  function makeDiscordAuthUrl(state) {
    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      response_type: "code",
      scope: "identify email guilds",
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

  // Ambil data key user dari ExHub API + Free Key KV (untuk dashboard)
  async function getUserKeys(discordUser) {
    const result = {
      total: 0,
      active: 0,
      premium: 0,
      keys: [],
      banned: false,
    };

    if (!discordUser) return result;

    let apiKeysRaw = [];
    let bannedFlag = false;

    // --- Paid / main keys dari API ExHub ---
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
          console.warn("[serverv2] user-info bukan JSON valid.");
          data = null;
        }

        if (data) {
          if (Array.isArray(data.keys)) {
            apiKeysRaw = data.keys;
          }
          if (typeof data.banned === "boolean") {
            bannedFlag = data.banned;
          }
        }
      }
    } catch (err) {
      console.error("[serverv2] getUserKeys API error:", err);
    }

    // --- Normalisasi paid keys ---
    const normalizedPaid = apiKeysRaw.map((k) => {
      const label =
        k.key ||
        k.token ||
        k.keyToken ||
        k.id ||
        (typeof k === "string" ? k : JSON.stringify(k));

      const providerRaw = k.provider || k.source || "ExHub";
      let providerLabel = providerRaw;
      const p = String(providerLabel).toLowerCase();
      if (p === "workink" || p === "work.ink") providerLabel = "Work.ink";
      else if (p.indexOf("linkvertise") !== -1) providerLabel = "Linkvertise";

      const tierRaw = k.tier || k.type || "Paid";
      const tierLabel = tierRaw;

      const statusLabel =
        k.deleted || k.revoked
          ? "Deleted"
          : k.valid === false
          ? "Invalid"
          : "Active";

      // cari timestamp expired (jika ada)
      let expiresAtMs = null;
      if (typeof k.expiresAtMs !== "undefined" && k.expiresAtMs != null) {
        const tmp = parseInt(k.expiresAtMs, 10);
        if (!isNaN(tmp)) expiresAtMs = tmp;
      } else if (
        typeof k.expiresAfter !== "undefined" &&
        k.expiresAfter != null
      ) {
        const tmp = parseInt(k.expiresAfter, 10);
        if (!isNaN(tmp)) expiresAtMs = tmp;
      } else if (typeof k.expiresAt !== "undefined" && k.expiresAt != null) {
        const tmp = parseInt(k.expiresAt, 10);
        if (!isNaN(tmp)) expiresAtMs = tmp;
      }

      return {
        key: String(label),
        provider: providerLabel,
        timeLeft: k.timeLeft || "-",
        status: statusLabel,
        tier: tierLabel,
        expiresAtMs: expiresAtMs || null,
        expiresAfter: expiresAtMs || null,
        free: false,
      };
    });

    // --- Free keys dari KV Upstash ---
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

    // --- Gabungkan semua ---
    const allKeys = normalizedPaid.concat(normalizedFree);

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

  // Alias lama → baru (kalau ada link /get-keyfree lama)
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
    const queryAds = req.query.ads;
    let adsProvider = canonicalAdsProvider(queryAds);

    // Simpan/ambil provider terakhir di session
    if (req.session) {
      if (queryAds) {
        req.session.lastFreeKeyAdsProvider = adsProvider;
      } else if (!queryAds && req.session.lastFreeKeyAdsProvider) {
        adsProvider = canonicalAdsProvider(req.session.lastFreeKeyAdsProvider);
      }
    }

    // Jika selesai iklan (?done=1), tandai checkpoint & redirect ke URL bersih (?ads=...)
    if (doneFlag && req.session) {
      const existingState = getAdsState(req, adsProvider);
      const now = nowMs();

      // Anti-spam server-side:
      // Kalau checkpoint terakhir SUDAH dipakai (used === true)
      // dan masih dalam window FREEKEY_ADS_COOLDOWN_MS,
      // jangan bikin checkpoint baru (anggap spam "Open" dari ads).
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

    // State ads dari session
    const adsState = getAdsState(req, adsProvider);
    const adsProgressDone = !!adsState; // sudah punya checkpoint
    const adsUsed = !!(adsState && adsState.used); // checkpoint sudah dipakai?

    const adsUrl =
      adsProvider === "linkvertise" ? LINKVERTISE_ADS_URL : WORKINK_ADS_URL;

    // Free key dari KV (persisten, key di bawah exhub:freekey:*)
    const freeKeys = await getFreeKeysForUserPersistent(userId);
    const maxKeys = FREE_KEY_MAX_PER_USER;
    const keys = freeKeys; // {token,provider,timeLeftLabel,status,expiresAfter}

    const capacityOk = keys.length < maxKeys;

    // Satu checkpoint -> tepat 1 aksi (Generate ATAU Renew)
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
  // POST /getfreekey/generate – Generate Free Key baru
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

      // Satu checkpoint habis dipakai 1 aksi
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
  // POST /getfreekey/extend – Renew (perpanjang) free key
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
      // Satu checkpoint habis dipakai 1 aksi
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
  // { valid, deleted, expired, info: {...} }
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
  // Dipanggil dari dashboard ( tombol Delete ) untuk Free Key.
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

      // Banner juga disimpan supaya bisa dipakai di dashboard.ejs
      req.session.discordUser = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || user.username,
        discriminator: user.discriminator,
        avatar: user.avatar,
        email: user.email,
        guildCount,
        banner: user.banner || null,
      };

      res.redirect("/dashboard");
    } catch (err) {
      console.error("[serverv2] OAuth callback exception:", err);
      res.redirect("/discord-login?error=exception");
    }
  });

  // Logout Discord
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
    "[serverv2] Discord OAuth + Dashboard + GetFreeKey + FreeKey API routes mounted."
  );
};
