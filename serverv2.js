// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

// ---------------------------------------------------------
// Helper: base API ExHub (sama pola dengan index.js bot)
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
// Konfigurasi Free Key (in-memory store)
// (Jika proses restart / multi-instance load balancing,
//  map ini tidak persisten – ini hanya untuk 1 instance proses.)
// ---------------------------------------------------------

const FREE_KEY_PREFIX = "EXHUBFREE";
const FREE_KEY_TTL_HOURS = 3;            // default 3 jam
const FREE_KEY_MAX_PER_USER = 5;

// REQUIREFREEKEY_ADS_CHECKPOINT = "1" (default) → wajib iklan dulu
const REQUIRE_FREEKEY_ADS_CHECKPOINT =
  String(process.env.REQUIREFREEKEY_ADS_CHECKPOINT || "1") === "1";

// Store in-memory
// token -> { token, userId, provider, createdAt, byIp, linkId, expiresAfter, deleted, valid }
const freeKeyStore = new Map();

function nowMs() {
  return Date.now();
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

function createFreeKeyRecord({ userId, provider, ip }) {
  const createdAt = nowMs();
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;
  const expiresAfter = createdAt + ttlMs;

  let token;
  do {
    token = generateFreeKeyToken();
  } while (freeKeyStore.has(token));

  const rec = {
    token,
    userId: String(userId),
    provider,
    createdAt,
    byIp: ip || null,
    linkId: null,
    expiresAfter,
    deleted: false,
    valid: true,
  };

  freeKeyStore.set(token, rec);
  return rec;
}

function extendFreeKey(token) {
  const rec = freeKeyStore.get(token);
  if (!rec) return null;

  const now = nowMs();
  const ttlMs = FREE_KEY_TTL_HOURS * 60 * 60 * 1000;

  rec.expiresAfter = now + ttlMs;
  rec.valid = true;
  rec.deleted = false;

  freeKeyStore.set(token, rec);
  return rec;
}

// Ambil semua free key milik user dari store
// Return: [{ token, timeLeftLabel, status, expiresAfter }]
function getFreeKeysForUser(userId) {
  const result = [];
  const now = nowMs();
  const uid = String(userId);

  for (const rec of freeKeyStore.values()) {
    if (String(rec.userId) !== uid) continue;

    const msLeft = rec.expiresAfter - now;
    const isExpired = msLeft <= 0 || rec.deleted;

    const timeLeftLabel = isExpired
      ? "Expired"
      : msLeft < 1000
      ? "< 1s"
      : msLeft < 60 * 1000
      ? Math.floor(msLeft / 1000) + "s"
      : msLeft < 60 * 60 * 1000
      ? Math.floor(msLeft / 60000) + "m"
      : Math.floor(msLeft / 3600000) + "h";

    result.push({
      token: rec.token,
      timeLeftLabel,
      status: isExpired ? "Expired" : "Active",
      expiresAfter: rec.expiresAfter,
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
// Helper: Ads / checkpoint state di session
// Struktur: req.session.freeKeyAdsState = {
//   workink:    { ts: <number>, used: <bool> },
//   linkvertise: { ts: <number>, used: <bool> }
// }
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
// Modul utama
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

  // Ambil data key user dari ExHub API (untuk dashboard utama)
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

      const activeKeys = keys.filter(
        (k) => !k.deleted && k.valid !== false && k.revoked !== true
      );
      result.active = activeKeys.length;

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
          timeLeft: k.timeLeft || "-",
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
      setAdsCheckpoint(req, adsProvider);
      return res.redirect("/getfreekey?ads=" + encodeURIComponent(adsProvider));
    }

    // State ads dari session
    const adsState = getAdsState(req, adsProvider);
    const adsProgressDone = !!adsState; // sudah punya checkpoint
    const adsUsed = !!(adsState && adsState.used); // checkpoint sudah dipakai?

    const adsUrl =
      adsProvider === "linkvertise" ? LINKVERTISE_ADS_URL : WORKINK_ADS_URL;

    // Free key dari in-memory store
    const freeKeys = getFreeKeysForUser(userId);
    const maxKeys = FREE_KEY_MAX_PER_USER;
    const keys = freeKeys; // sudah berbentuk {token,timeLeftLabel,status,expiresAfter}

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
      const existing = getFreeKeysForUser(userId);
      if (existing.length >= FREE_KEY_MAX_PER_USER) {
        return res.redirect(
          redirectBase +
            "&error=" +
            encodeURIComponent("Key slot penuh. Biarkan beberapa key expired dulu.")
        );
      }

      if (REQUIRE_FREEKEY_ADS_CHECKPOINT) {
        const adsState = getAdsState(req, adsProvider);
        if (!adsState || adsState.used) {
          return res.redirect(
            redirectBase +
              "&error=" +
              encodeURIComponent("Selesaikan iklan terlebih dahulu sebelum generate key.")
          );
        }
      }

      const ipHeader = req.headers["x-forwarded-for"] || req.ip || "";
      const ip = String(ipHeader).split(",")[0].trim();
      createFreeKeyRecord({ userId, provider: adsProvider, ip });

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
      const rec = freeKeyStore.get(token);
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
              encodeURIComponent("Selesaikan iklan terlebih dahulu sebelum renew key.")
          );
        }
      }

      extendFreeKey(token);
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
  // --------------------------------------------------
  app.get("/api/freekey/isValidate/:key", (req, res) => {
    const token = req.params.key;
    const rec = freeKeyStore.get(token);
    const now = nowMs();

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
