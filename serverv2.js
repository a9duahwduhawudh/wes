// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub + Get Free Key
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

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

  // Optional: URL iklan Work.ink & Linkvertise
  const WORKINK_ADS_URL =
    process.env.WORKINK_ADS_URL ||
    "https://link-hub.net/2995260/0xLAgWUZzCns";
  const LINKVERTISE_ADS_URL =
    process.env.LINKVERTISE_ADS_URL ||
    "https://linkvertise.com/";

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

  // =========================
  // ROUTES – PUBLIC PAGES
  // =========================

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

  // Halaman baru: Get Free Key (Work.ink / Linkvertise)
  app.get("/getfreekey", requireAuth, async (req, res) => {
    const discordUser = req.session.discordUser;
    const rawAds = (req.query.ads || "workink").toLowerCase();

    const adsProvider =
      rawAds === "linkvertise" || rawAds === "linkvertise.com"
        ? "linkvertise"
        : "workink";

    const adsUrl =
      adsProvider === "linkvertise" ? LINKVERTISE_ADS_URL : WORKINK_ADS_URL;

    // Ambil key yang sama seperti di dashboard, lalu mapping ke bentuk sederhana
    const keyData = await getUserKeys(discordUser);
    const maxKeys = 5;
    const keys =
      (keyData.keys || []).map((k) => ({
        token: k.key,
        timeLeftLabel: k.timeLeft || "-",
        status: k.status || "Active",
      })) || [];

    const allowGenerate = keys.length < maxKeys;
    const errorMessage = req.query.error || null;

    res.render("getfreekey", {
      title: "ExHub — Get Free Key",
      user: discordUser,
      adsProvider,
      adsUrl,
      keys,
      maxKeys,
      defaultKeyHours: 8,
      allowGenerate,
      currentUserId: discordUser.id,
      keyAction: "/getfreekey/generate",
      renewAction: "/getfreekey/extend",
      errorMessage,
    });
  });

  // POST generate key (stub, nanti bisa disambungkan ke ExHub API internal)
  app.post("/getfreekey/generate", requireAuth, async (req, res) => {
    const ads = (req.query.ads || "workink").toLowerCase();

    try {
      // TODO: panggil API internal ExHub untuk generate key di sini,
      // misal: await fetch(EXHUB_API_BASE + "keys/generate", {...})

      // Untuk sementara hanya redirect balik tanpa error
      return res.redirect("/getfreekey?ads=" + encodeURIComponent(ads));
    } catch (err) {
      console.error("[serverv2] generate free key error:", err);
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(ads) +
          "&error=" +
          encodeURIComponent("Failed to generate key.")
      );
    }
  });

  // POST extend key (stub, nanti sambungkan ke API internal kalau ada)
  app.post("/getfreekey/extend", requireAuth, async (req, res) => {
    const ads = (req.query.ads || "workink").toLowerCase();
    const token = req.body && req.body.token;

    try {
      if (token) {
        // TODO: panggil API internal ExHub untuk extend key,
        // misal: await fetch(EXHUB_API_BASE + "keys/extend", {...})
      }

      return res.redirect("/getfreekey?ads=" + encodeURIComponent(ads));
    } catch (err) {
      console.error("[serverv2] extend free key error:", err);
      return res.redirect(
        "/getfreekey?ads=" +
          encodeURIComponent(ads) +
          "&error=" +
          encodeURIComponent("Failed to extend key.")
      );
    }
  });

  // =========================
  // ROUTES – DISCORD OAUTH2
  // =========================

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

  console.log("[serverv2] Discord OAuth + Dashboard + GetFreeKey routes mounted.");
};
