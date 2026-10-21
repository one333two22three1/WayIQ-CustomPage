import express from "express";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());

// ---------- Config (set these in Render > Environment) ----------
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const ISSUER = "wayhub.io";

// Origins allowed to call this API (the page that runs /entry)
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

// ---------- Single-use token tracking (use Redis in production) ----------
const usedJti = new Map(); // jti -> expiry time (ms)
setInterval(() => {
    const now = Date.now();
    for (const [jti, exp] of usedJti) if (exp < now) usedJti.delete(jti);
}, 60_000);

// ---------- Helpers ----------
function getBearer(req) {
    const h = req.headers.authorization || "";
    return h.startsWith("Bearer ") ? h.slice(7) : null;
}

// Protects routes that need a valid WayIQ session
function requireSession(req, res, next) {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Missing session" });
    try {
        req.user = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "session" });
        next();
    } catch {
        res.status(401).json({ error: "Invalid or expired session" });
    }
}

// ---------- 1) Decrypt GHL payload and issue a short-lived login token ----------
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

// ---------- 2) Validate the token from the Authorization header, start a session ----------
app.post("/api/session", (req, res) => {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const p = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });

        if (usedJti.has(p.jti)) {
            return res.status(401).json({ error: "Token already used" });
        }
        usedJti.set(p.jti, Date.now() + 5 * 60_000);

        const session = jwt.sign(
            {
                sub: p.sub,
                email: p.email,
                name: p.name,
                role: p.role,
                companyId: p.companyId,
                locationId: p.locationId,
            },
            JWT_SECRET,
            { expiresIn: "8h", issuer: ISSUER, audience: "session" }
        );

        res.json({
            session,
            user: {
                id: p.sub,
                name: p.name,
                email: p.email,
                role: p.role,
                locationId: p.locationId,
            },
        });
    } catch {
        res.status(401).json({ error: "Invalid or expired token" });
    }
});

// ---------- 3) Example protected endpoint (WayIQ data goes here) ----------
app.get("/api/me", requireSession, (req, res) => {
    const u = req.user;
    res.json({
        id: u.sub,
        name: u.name,
        email: u.email,
        role: u.role,
        locationId: u.locationId,
    });
});

app.get("/", (_req, res) => res.send("WayIQ SSO service is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("SSO server on :" + PORT));