// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

// ========================================================
//  KONFIGURASI GLOBAL FREE KEY
// ========================================================

// TTL default free key (jam)
const FREE_KEY_TTL_HOURS = (() => {
  const v = parseInt(process.env.FREEKEY_TTL_HOURS || "3", 10);
  return Number.isFinite(v) && v > 0 ? v : 3;
})();

// Maksimal key per user (untuk halaman Get Free Key)
const FREE_KEY_MAX_PER_USER = (() => {
  const v = parseInt(process.env.FREEKEY_MAX_PER_USER || "5", 10);
  return Number.isFinite(v) && v > 0 ? v : 5;
})();

// Jika = "1" → user HARUS lewat checkpoint iklan (?done=1) sebelum bisa Generate Free Key
const REQUIRE_FREEKEY_ADS_CHECKPOINT =
  String(process.env.REQUIREFREEKEY_ADS_CHECKPOINT || "0") === "1";

// Helper: bangun base API ExHub (sama pola dengan index.js bot)
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

// ========================================================
//  PENYIMPANAN FREE KEY (IN MEMORY)
//  - Untuk produksi, ganti bagian ini ke Upstash / DB yang kamu pakai.
// ========================================================

// token -> record
const freeKeyStore = new Map();
// userId (Discord) -> Set(token)
const userFreeKeys = new Map();

/**
 * Generate token random dengan pola:
 * EXHUBFREE-XXX-XXXX-XXXXX
 * (huruf besar, kecil, angka)
 */
function generateFreeKeyToken() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  function randSegment(len) {
    let out = "";
    for (let i = 0; i < len; i++) {
      out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
  }

  return `EXHUBFREE-${randSegment(3)}-${randSegment(4)}-${randSegment(5)}`;
}

/**
 * Format sisa waktu (ms) menjadi HH:MM:SS atau "Expired".
 */
function formatTimeLeft(ms) {
  if (ms == null) return "-";
  if (ms <= 0) return "Expired";
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

/**
 * Buat record free key baru untuk user tertentu.
 */
function createFreeKeyRecord({ token, userId, byIp, provider }) {
  const createdAt = Date.now();
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;
  const expiresAfter = createdAt + ttlMs;

  const record = {
    token,
    createdAt,
    byIp: byIp || null,
    linkId: provider || null, // bisa diisi "workink" / "linkvertise"
    userId,
    expiresAfter,
    deleted: false,
  };

  freeKeyStore.set(token, record);

  if (!userFreeKeys.has(userId)) {
    userFreeKeys.set(userId, new Set());
  }
  userFreeKeys.get(userId).add(token);

  return record;
}

/**
 * Ambil list key milik user (untuk tabel di getfreekey.ejs).
 */
function getFreeKeysForUser(userId) {
  const set = userFreeKeys.get(userId);
  if (!set) return [];

  const now = Date.now();
  const result = [];

  for (const token of set) {
    const rec = freeKeyStore.get(token);
    if (!rec) continue;

    const msLeft = rec.expiresAfter - now;
    const valid = !rec.deleted && msLeft > 0;

    result.push({
      token: rec.token,
      timeLeftLabel: formatTimeLeft(msLeft),
      status: rec.deleted ? "Deleted" : valid ? "Active" : "Expired",
      raw: rec,
    });
  }

  return result;
}

/**
 * Update expire key (extend).
 */
function extendFreeKey(token) {
  const rec = freeKeyStore.get(token);
  if (!rec || rec.deleted) return null;

  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;
  const now = Date.now();
  rec.expiresAfter = now + ttlMs;
  return rec;
}

/**
 * Validasi key untuk endpoint /api/freekey/isValidate/:token
 */
function validateFreeKeyToken(token) {
  const rec = freeKeyStore.get(token);
  if (!rec) {
    return {
      valid: false,
      deleted: false,
      info: null,
    };
  }

  const now = Date.now();
  const deleted = !!rec.deleted;
  const valid = !deleted && now < rec.expiresAfter;

  return {
    valid,
    deleted,
    info: {
      token: rec.token,
      createdAt: rec.createdAt,
      byIp: rec.byIp,
      linkId: rec.linkId,
      userId: rec.userId,
      expiresAfter: rec.expiresAfter,
    },
  };
}

// ========================================================
//  MODUL UTAMA
// ========================================================

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

  // URL iklan Work.ink & Linkvertise
  const WORKINK_ADS_URL =
    process.env.WORKINK_ADS_URL ||
    "https://work.ink/23P2/exhubfreekey";
  const LINKVERTISE_ADS_URL =
    process.env.LINKVERTISE_ADS_URL ||
    "https://linkvertise.com/access/2995260/uaE3u7P8CG5D";

  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    console.warn(
      "[serverv2] DISCORD_CLIENT_ID atau DISCORD_CLIENT_SECRET belum diset. " +
        "Fitur Discord Login tidak akan bekerja dengan benar."
    );
  }

  // =========================
  // MIDDLEWARE: res.locals.user
  // =========================
  // Asumsi: server.js utama SUDAH pakai cookie-session dan EJS.
  // Di sini kita hanya gunakan `req.session.discordUser` supaya tidak tabrakan
  // dengan session lain (misal admin panel).
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

  function canonicalAdsProvider(raw) {
    const v = String(raw || "").toLowerCase();
    if (v === "linkvertise" || v === "linkvertise.com") return "linkvertise";
    return "workink";
  }

  function getClientIp(req) {
    const xf = req.headers["x-forwarded-for"];
    if (typeof xf === "string" && xf.length > 0) {
      return xf.split(",")[0].trim();
    }
    return req.ip || null;
  }

  // Ambil data key user dari ExHub API (contoh: /api/bot/user-info)
  async function getUserKeys(discordUser) {
    const result = {
      total: 0,
      active: 0,
      premium: 0,
      linked: 0,
      keys: [],
    };

    if (!discordUser) return result;

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
        return result;
      }

      let data;
      try {
        data = JSON.parse(text);
      } catch {
        console.warn("[serverv2] user-info bukan JSON valid.");
        return result;
      }

      const keys = Array.isArray(data.keys) ? data.keys : [];
      result.total = keys.length;
      result.linked = keys.length;

      // heuristik: active = belum deleted && (valid !== false)
      const activeKeys = keys.filter(
        (k) => !k.deleted && k.valid !== false && k.revoked !== true
      );
      result.active = activeKeys.length;

      // premium = tier === "premium"
      const premiumKeys = keys.filter((k) => {
        const tier = String(k.tier || k.type || "").toLowerCase();
        return tier.includes("premium") || tier.includes("vip");
      });
      result.premium = premiumKeys.length;

      result.keys = keys.map((k) => {
        const label =
          k.key ||
          k.token ||
          k.keyToken ||
          k.id ||
          (typeof k === "string" ? k : JSON.stringify(k));
        return {
          key: String(label),
          provider: k.provider || k.source || "ExHub",
          timeLeft: k.timeLeft || "-", // kalau API punya field ini
          status:
            k.deleted || k.revoked
              ? "Deleted"
              : k.valid === false
              ? "Invalid"
              : "Active",
          tier: k.tier || "Free",
        };
      });

      return result;
    } catch (err) {
      console.error("[serverv2] getUserKeys error:", err);
      return result;
    }
  }

  // ======================================================
  // ROUTES – PUBLIC PAGES
  // ======================================================

  // popup Sign In (mirip gambar "Sign in with Discord")
  app.get("/discord-login", (req, res) => {
    res.render("discord-login", {
      error: req.query.error || null,
    });
  });

  // jika belum login tetapi akses halaman proteksi
  app.get("/login-required", (req, res) => {
    res.render("login-required");
  });

  // ======================================================
  // ROUTES – DASHBOARD & PAGE WAJIB LOGIN
  // ======================================================

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

  // Halaman baru: Get Free Key (Work.ink / Linkvertise)
  app.get("/getfreekey", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    const doneFlag = String(req.query.done || "") === "1";
    const queryAds = req.query.ads;

    // Tentukan provider
    let adsProvider = canonicalAdsProvider(queryAds);

    // Kalau tidak ada ?ads di query, pakai last provider dari session (kalau ada)
    if (!queryAds && req.session && req.session.lastFreeKeyAdsProvider) {
      adsProvider = req.session.lastFreeKeyAdsProvider;
    }

    if (req.session) {
      req.session.lastFreeKeyAdsProvider = adsProvider;

      // Kalau datang dengan ?done=1 → tandai checkpoint
      if (doneFlag) {
        if (!req.session.freeKeyAdsState) {
          req.session.freeKeyAdsState = {};
        }
        req.session.freeKeyAdsState[adsProvider] = Date.now();
      }
    }

    const adsUrl =
      adsProvider === "linkvertise" ? LINKVERTISE_ADS_URL : WORKINK_ADS_URL;

    // Ambil free key in-memory
    const keys = getFreeKeysForUser(userId);
    const maxKeys = FREE_KEY_MAX_PER_USER;

    const capacityOk = keys.length < maxKeys;

    let hasCheckpoint = true;
    if (REQUIRE_FREEKEY_ADS_CHECKPOINT) {
      const state = (req.session && req.session.freeKeyAdsState) || {};
      hasCheckpoint = !!state[adsProvider];
    }

    const allowGenerate =
      capacityOk && (!REQUIRE_FREEKEY_ADS_CHECKPOINT || hasCheckpoint);

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
      currentUserId: userId,
      keyAction: "/getfreekey/generate",
      renewAction: "/getfreekey/extend",
      errorMessage,
    });
  });

  // POST generate free key
  app.post("/getfreekey/generate", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    const adsRaw = req.query.ads || req.session.lastFreeKeyAdsProvider || "workink";
    const adsProvider = canonicalAdsProvider(adsRaw);

    const keys = getFreeKeysForUser(userId);
    const maxKeys = FREE_KEY_MAX_PER_USER;
    const capacityOk = keys.length < maxKeys;

    if (!capacityOk) {
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(adsProvider) +
          "&error=" +
          encodeURIComponent("Key limit reached for this account.")
      );
    }

    let hasCheckpoint = true;
    if (REQUIRE_FREEKEY_ADS_CHECKPOINT) {
      const state = (req.session && req.session.freeKeyAdsState) || {};
      hasCheckpoint = !!state[adsProvider];
      if (!hasCheckpoint) {
        return res.redirect(
          "/getfreekey?ads=" +
            encodeURIComponent(adsProvider) +
            "&error=" +
            encodeURIComponent("Please complete the verification task first.")
        );
      }
    }

    try {
      const token = generateFreeKeyToken();
      const ip = getClientIp(req);

      createFreeKeyRecord({
        token,
        userId,
        byIp: ip,
        provider: adsProvider,
      });

      // Setelah berhasil generate, checkpoint boleh di-reset
      if (REQUIRE_FREEKEY_ADS_CHECKPOINT && req.session?.freeKeyAdsState) {
        delete req.session.freeKeyAdsState[adsProvider];
      }

      return res.redirect("/getfreekey?ads=" + encodeURIComponent(adsProvider));
    } catch (err) {
      console.error("[serverv2] generate free key error:", err);
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(adsProvider) +
          "&error=" +
          encodeURIComponent("Failed to generate free key.")
      );
    }
  });

  // POST extend free key
  app.post("/getfreekey/extend", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const userId = discordUser.id;

    const adsRaw = req.query.ads || req.session.lastFreeKeyAdsProvider || "workink";
    const adsProvider = canonicalAdsProvider(adsRaw);

    const token = req.body && req.body.token;
    if (!token) {
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(adsProvider) +
          "&error=" +
          encodeURIComponent("Invalid token.")
      );
    }

    try {
      const rec = freeKeyStore.get(token);
      if (!rec || rec.userId !== userId) {
        return res.redirect(
          "/getfreekey?ads=" +
            encodeURIComponent(adsProvider) +
            "&error=" +
            encodeURIComponent("Key not found for this user.")
        );
      }

      extendFreeKey(token);

      return res.redirect("/getfreekey?ads=" + encodeURIComponent(adsProvider));
    } catch (err) {
      console.error("[serverv2] extend free key error:", err);
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(adsProvider) +
          "&error=" +
          encodeURIComponent("Failed to extend key.")
      );
    }
  });

  // ======================================================
  // ROUTES – API FREEKEY (untuk executor / eksternal)
  // ======================================================

  // Validate free key: /api/freekey/isValidate/{KEY}
  app.get("/api/freekey/isValidate/:token", (req, res) => {
    const rawToken = req.params.token || "";
    const token = String(rawToken).trim();

    const result = validateFreeKeyToken(token);
    res.json(result);
  });

  // ======================================================
  // ROUTES – DISCORD OAUTH2
  // ======================================================

  // Step 1: redirect ke Discord OAuth authorize
  app.get("/auth/discord", (req, res) => {
    const state = crypto.randomBytes(16).toString("hex");
    if (req.session) {
      req.session.oauthState = state;
    }
    const url = makeDiscordAuthUrl(state);
    res.redirect(url);
  });

  // Step 2: callback dari Discord
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

    // state hanya satu kali pakai
    req.session.oauthState = null;

    try {
      // Tukar "code" jadi access_token
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

      // Ambil data user @me
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

      // Ambil guilds untuk "Know what servers you're in"
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

      // Simpan data minimal ke session
      req.session.discordUser = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || user.username,
        discriminator: user.discriminator,
        avatar: user.avatar,
        email: user.email,
        guildCount,
      };

      res.redirect("/dashboard");
    } catch (err) {
      console.error("[serverv2] OAuth callback exception:", err);
      res.redirect("/discord-login?error=exception");
    }
  });

  // Logout Discord (hanya hapus data discordUser, session lain tetap boleh dipakai)
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
