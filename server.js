import express from "express";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());

// ---------- Config (Render > Environment) ----------
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET;   // from the GHL Marketplace app
const JWT_SECRET = process.env.JWT_SECRET;                 // signs the 60-second login token
const SESSION_SECRET = process.env.SESSION_SECRET;         // signs the WayIQ session (different value)
const WAYIQ_APP_URL = process.env.WAYIQ_APP_URL || "https://wayhub.io";   // UI page to open
const ISSUER = "wayhub.io";

for (const [name, value] of Object.entries({ GHL_SHARED_SECRET, JWT_SECRET, SESSION_SECRET })) {
    if (!value) {
        console.error(`Missing environment variable: ${name}`);
        process.exit(1);
    }
}

// Origins allowed to call this API
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
// Single-use login tokens (use Redis in production, this resets on restart)
const usedJti = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [id, exp] of usedJti) if (exp < now) usedJti.delete(id);
}, 60_000);

// Test user store (use a database in production)
const users = new Map();
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

function requireSession(req, res, next) {
    const token = getBearer(req);
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

// =====================================================
// 1) TOKEN SERVICE
//    Decrypts the GHL payload and issues a 60-second login token
//    POST /api/ghl/sso
// =====================================================
app.post("/api/ghl/sso", (req, res) => {
    try {
        const bytes = CryptoJS.AES.decrypt(req.body.encrypted, GHL_SHARED_SECRET);
        const user = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        if (!user.userId) throw new Error("bad payload");

        console.log("GHL user:", {
            userId: user.userId,
            email: user.email,
            name: user.userName,
            loc: user.activeLocation,
        });

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
// 2) WAYIQ LOGIN
//    Receives the token in the Authorization header, validates it,
//    returns a WayIQ session and the UI page to open (wayhub.io)
//    POST /wayiq/auth/ghl-login
//    Header: Authorization: Bearer <login token>
// =====================================================
app.post("/wayiq/auth/ghl-login", (req, res) => {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const p = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });

        if (usedJti.has(p.jti)) return res.status(401).json({ error: "Token already used" });
        usedJti.set(p.jti, Date.now() + 5 * 60_000);

        const user = findOrCreateUser({
            ghlUserId: p.sub,
            email: p.email,
            name: p.name,
            role: p.role,
            locationId: p.locationId,
        });

        const session = jwt.sign(
            { uid: user.id },
            SESSION_SECRET,
            { expiresIn: "8h", issuer: "wayiq", audience: "wayiq-session" }
        );

        res.json({
            session,
            appUrl: WAYIQ_APP_URL,            // the UI page the entry page should open
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                locationId: user.locationId,
            },
        });
    } catch (err) {
        console.error("ghl-login failed:", err.name, err.message);
        const isTokenProblem = ["JsonWebTokenError", "TokenExpiredError", "NotBeforeError"].includes(err.name);
        res.status(isTokenProblem ? 401 : 500).json({
            error: isTokenProblem ? "Invalid or expired token" : "Server error",
            reason: err.message,
        });
    }
});

// =====================================================
// 3) WAYIQ API (protected by the session header)
//    The wayhub.io page calls these with Authorization: Bearer <session>
// =====================================================
app.get("/wayiq/api/me", requireSession, (req, res) => {
    const { id, name, email, role, locationId } = req.user;
    res.json({ id, name, email, role, locationId });
});

// Add more WayIQ endpoints here, for example:
// app.get("/wayiq/api/reports", requireSession, (req, res) => { ... });

app.get("/", (_req, res) => res.send("Token service + WayIQ API running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server on :" + PORT));