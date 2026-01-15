// serverv2.js
// Modul fitur: Discord OAuth Login + Dashboard ExHub
// DIPANGGIL dari server.js utama dengan: require("./serverv2")(app);

const crypto = require("crypto");

// =========================
// Helper: bangun base API ExHub
// =========================
//
// Konvensi ENV yang dipakai:
// - EXHUB_API_BASE   → biasanya kamu isi "https://exc-webs.vercel.app"
//                       (BASE SITE, tanpa /api) di Vercel sekarang.
// - EXHUB_SITE_BASE  → opsional, kalau mau pisah jelas base site.
//
// Fungsi ini akan memastikan hasil akhirnya SELALU:
//   https://exc-webs.vercel.app/api/
// sehingga ketika dipakai:
//   new URL("bot/user-info", EXHUB_API_BASE)
// akan menjadi:
//   https://exc-webs.vercel.app/api/bot/user-info
//
function resolveExHubApiBase() {
  let base = process.env.EXHUB_API_BASE;

  if (!base) {
    const site = process.env.EXHUB_SITE_BASE || "https://exc-webs.vercel.app";
    base = new URL("/api/", site).toString(); // site -> site/api/
  } else {
    // Kalau EXHUB_API_BASE tidak mengandung "/api", tambahkan otomatis
    // contoh: "https://exc-webs.vercel.app" -> "https://exc-webs.vercel.app/api/"
    if (!/\/api\/?$/i.test(base)) {
      base = new URL("/api/", base).toString();
    }
  }

  if (!base.endsWith("/")) base += "/";
  return base;
}

module.exports = function mountDiscordOAuth(app) {
  // =========================
  // ENV
  // =========================
  //
  // PENTING:
  // - DISCORD_CLIENT_ID       → Client ID APLIKASI OAUTH WEBSITE
  // - DISCORD_CLIENT_SECRET   → Client Secret OAUTH
  // - DISCORD_REDIRECT_URI    → HARUS sama dengan redirect di Discord Dev Portal,
  //                             contoh: "https://exc-webs.vercel.app/auth/discord/callback"
  //
  // Bot Discord (index.js) tetap pakai:
  // - DISCORD_TOKEN
  // - CLIENT_ID (untuk bot)
  //
  const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
  const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
  const DISCORD_REDIRECT_URI =
    process.env.DISCORD_REDIRECT_URI ||
    "http://localhost:3000/auth/discord/callback";

  const EXHUB_API_BASE = resolveExHubApiBase();

  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    console.warn(
      "[serverv2] DISCORD_CLIENT_ID atau DISCORD_CLIENT_SECRET belum diset. " +
        "Fitur Discord Login tidak akan bekerja dengan benar."
    );
  } else {
    console.log(
      `[serverv2] OAuth config OK. CLIENT_ID=${DISCORD_CLIENT_ID}, REDIRECT_URI=${DISCORD_REDIRECT_URI}`
    );
  }

  console.log("[serverv2] EXHUB_API_BASE (for /api/*):", EXHUB_API_BASE);

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
        // Tag boleh apa saja, di server.js kita cuma pakai discordId sebagai kunci utama
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

      // premium = tier mengandung premium/VIP
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

  // Contoh route yang wajib login (get-keyfree)
  app.get("/get-keyfree", requireAuth, (req, res) => {
    // Untuk sementara bisa pakai view sederhana.
    // Nanti kamu bisa ganti isinya dengan desain seperti get-key.ejs Work.ink.
    res.render("get-keyfree", {});
  });

  // =========================
  // ROUTES – DISCORD OAUTH2
  // =========================

  // Step 1: redirect ke Discord OAuth authorize
  app.get("/auth/discord", (req, res) => {
    // Kalau config belum benar, jangan terusin supaya tidak bingung
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
      console.error(
        "[serverv2] /auth/discord dipanggil tapi ENV OAuth belum lengkap."
      );
      return res.redirect("/discord-login?error=config");
    }

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

  console.log("[serverv2] Discord OAuth + Dashboard routes mounted.");
};
