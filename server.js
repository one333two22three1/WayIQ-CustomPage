import express from "express";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());

// ---------- Config (Render > Environment) ----------
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;          // signs the 60-second login token
const SESSION_SECRET = process.env.SESSION_SECRET;  // signs the WayIQ session (use a different value)
const ISSUER = "wayhub.io";

const ALLOWED_ORIGINS = [
    "https://wayhub.io",
    "https://www.wayhub.io",
    "https://purplescape.com",
    "https://www.purplescape.com",
];

// ---------- CORS ----------
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
});

// ---------- Helpers ----------
const usedJti = new Map();                         // single-use tokens (Redis in production)
setInterval(() => {
    const now = Date.now();
    for (const [id, exp] of usedJti) if (exp < now) usedJti.delete(id);
}, 60_000);

const users = new Map();                           // test user store (database in production)
function findOrCreateUser({ ghlUserId, email, name, role, locationId }) {
    let u = users.get(ghlUserId);
    if (!u) {
        u = { id: "wq_" + ghlUserId, ghlUserId, email, name, role, locationId };
        users.set(ghlUserId, u);
    } else {
        Object.assign(u, { email, name, role, locationId });
    }
    return u;
}

function getBearer(req) {
    const h = req.headers.authorization || "";
    return h.startsWith("Bearer ") ? h.slice(7) : null;
}

// =====================================================
// TOKEN SERVICE: decrypt the GHL payload, issue a 60-second token
// =====================================================
app.post("/api/ghl/sso", (req, res) => {
    try {
        const bytes = CryptoJS.AES.decrypt(req.body.encrypted, GHL_SHARED_SECRET);
        const user = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        if (!user.userId) throw new Error("bad payload");

        console.log("GHL user:", { userId: user.userId, email: user.email, name: user.userName, loc: user.activeLocation });

        const token = jwt.sign(
            {
                sub: user.userId,
                email: user.email,
                name: user.userName,
                role: user.role,
                companyId: user.companyId,
                locationId: user.activeLocation,
                jti: crypto.randomUUID(),
            },
            JWT_SECRET,
            { expiresIn: "60s", issuer: ISSUER, audience: "login" }
        );
        res.json({ token });
    } catch (err) {
        console.error("SSO error:", err.message);
        res.status(400).json({ error: "Failed to decrypt user data" });
    }
});

// =====================================================
// WAYIQ (test): receives the token in the Authorization header
// POST /wayiq/auth/ghl-login
// =====================================================
app.post("/wayiq/auth/ghl-login", (req, res) => {
    const token = getBearer(req);
    console.log("ghl-login: has Authorization header?", !!req.headers.authorization);
    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const p = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });

        if (usedJti.has(p.jti)) return res.status(401).json({ error: "Token already used" });
        usedJti.set(p.jti, Date.now() + 5 * 60_000);

        const user = findOrCreateUser({
            ghlUserId: p.sub, email: p.email, name: p.name, role: p.role, locationId: p.locationId,
        });

        const session = jwt.sign(
            { uid: user.id },
            SESSION_SECRET,
            { expiresIn: "8h", issuer: "wayiq", audience: "wayiq-session" }
        );

        res.json({
            session,
            user: { id: user.id, name: user.name, email: user.email, role: user.role, locationId: user.locationId },
        });
    } catch (err) {
        console.error("ghl-login failed:", err.name, err.message);
        res.status(401).json({ error: "Invalid or expired token", reason: err.message });
    }
});

function requireSession(req, res, next) {
    const token = getBearer(req);
    console.log("ghl-login: has Authorization header?", !!req.headers.authorization);
    if (!token) return res.status(401).json({ error: "Missing session" });
    try {
        const p = jwt.verify(token, SESSION_SECRET, { issuer: "wayiq", audience: "wayiq-session" });
        const user = [...users.values()].find((u) => u.id === p.uid);
        if (!user) return res.status(401).json({ error: "Unknown user" });
        req.user = user;
        next();
    } catch {
        res.status(401).json({ error: "Invalid or expired session" });
    }
}

// WayIQ (test): protected endpoint, returns the signed-in user's data
app.get("/wayiq/api/me", requireSession, (req, res) => {
    const { id, name, email, role, locationId } = req.user;
    res.json({ id, name, email, role, locationId });
});

// ---------- HTML escaping for server-rendered pages ----------
function esc(s) {
    return String(s ?? "-").replace(/[&<>"']/g, (c) =>
        ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// =====================================================
// WAYIQ (test): the UI page. Requires the session in the Authorization header.
// GET /wayiq/app
// =====================================================
app.get("/wayiq/app", requireSession, (req, res) => {
    const u = req.user;
    const apiBase = JSON.stringify(`https://${req.get("host")}`).replace(/</g, "\\u003c");

    res.set("Cache-Control", "no-store");
    res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WayIQ</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, sans-serif; color: #1f2430; background: #f5f6fa; }
    header { background: #1f2a44; color: #fff; padding: 14px 24px; display: flex; justify-content: space-between; align-items: center; }
    header .logo { font-weight: 600; font-size: 18px; letter-spacing: .3px; }
    header .who { font-size: 13px; opacity: .85; }
    main { max-width: 860px; margin: 24px auto; padding: 0 16px; display: grid; gap: 16px; }
    .card { background: #fff; border: 1px solid #e3e6ee; border-radius: 12px; padding: 20px; }
    h2 { margin: 0 0 12px; font-size: 18px; }
    dl { display: grid; grid-template-columns: 130px 1fr; gap: 8px 12px; margin: 0; }
    dt { color: #7a8196; } dd { margin: 0; word-break: break-all; }
    button { background: #2d5bff; color: #fff; border: 0; border-radius: 8px; padding: 9px 16px; cursor: pointer; font-size: 14px; }
    pre { background: #f0f2f8; border-radius: 8px; padding: 12px; margin: 12px 0 0; white-space: pre-wrap; word-break: break-all; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <div class="logo">WayIQ</div>
    <div class="who">${esc(u.name)} &middot; ${esc(u.email)}</div>
  </header>
  <main>
    <section class="card">
      <h2>Welcome, ${esc(u.name)}</h2>
      <dl>
        <dt>Email</dt><dd>${esc(u.email)}</dd>
        <dt>Role</dt><dd>${esc(u.role)}</dd>
        <dt>GHL account</dt><dd>${esc(u.locationId)}</dd>
        <dt>WayIQ user ID</dt><dd>${esc(u.id)}</dd>
      </dl>
    </section>
    <section class="card">
      <h2>Live data check</h2>
      <p>Calls the WayIQ API with your session in the request header.</p>
      <button id="check">Load my profile</button>
      <pre id="out" hidden></pre>
    </section>
  </main>
  <script>
    var API = ${apiBase};
    var session = window.__WAYIQ_SESSION__ || (function () {
      try { return sessionStorage.getItem("wayiq_session"); } catch (e) { return null; }
    })();
    document.getElementById("check").onclick = async function () {
      var out = document.getElementById("out");
      out.hidden = false;
      try {
        var r = await fetch(API + "/wayiq/api/me", { headers: { Authorization: "Bearer " + session } });
        out.textContent = r.status + "\\n" + JSON.stringify(await r.json(), null, 2);
      } catch (err) {
        out.textContent = "Request failed: " + err.message;
      }
    };
  </script>
</body>
</html>`);
});

app.get("/", (_req, res) => res.send("Token service + WayIQ test API running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server on :" + PORT));