import express from "express";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import {
    HttpError,
    getInstallUrl,
    initOAuth,
    getLocationToken,
    ghlRequest,
    handleInstallCallback,
    handleWebhook,
} from "./ghl-oauth.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();            // must come before any app.get / app.post / app.use
app.use(express.json());

// ---------- Config (Render > Environment) ----------
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET;   // from the GHL Marketplace app(s), comma-separated
// Each marketplace app that opens this page encrypts with its own shared secret
const GHL_SHARED_SECRETS = (GHL_SHARED_SECRET || "").split(",").map((s) => s.trim()).filter(Boolean);
const JWT_SECRET = process.env.JWT_SECRET;                 // signs the 60-second login token
const SESSION_SECRET = process.env.SESSION_SECRET;         // signs the WayIQ session (different value)
const ISSUER = "wayhub.io";

const WAYIQ_API_KEY = process.env.WAYIQ_API_KEY;
for (const [name, value] of Object.entries({ GHL_SHARED_SECRET, JWT_SECRET, SESSION_SECRET, WAYIQ_API_KEY })) {
    if (!value) {
        console.error(`Missing environment variable: ${name}`);
        process.exit(1);
    }
}
await initOAuth();   // OAuth is optional at startup: logs what is missing, creates the token table

// Origins allowed to call this API (the funnel page on wayhub.io)
const ALLOWED_ORIGINS = [
    "https://wayhub.io",
    "https://www.wayhub.io",
    "https://purplescape.com",
    "https://www.purplescape.com",
];

// frame-ancestors checks every ancestor: the funnel (wayhub.io) AND GHL above it
const FRAME_ANCESTORS =
    "frame-ancestors " +
    "https://wayhub.io https://*.wayhub.io " +
    "https://app.gohighlevel.com https://*.gohighlevel.com " +
    "https://*.leadconnectorhq.com https://*.msgsndr.com " +
    "https://*.myfunnels.com https://*.leadconnectorhq.com " +
    (process.env.EXTRA_FRAME_ANCESTORS || "");

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

// Decrypts the GHL SSO payload with whichever app's shared secret it was encrypted with
function decryptSsoPayload(encrypted) {
    for (const secret of GHL_SHARED_SECRETS) {
        try {
            const user = JSON.parse(CryptoJS.AES.decrypt(encrypted, secret).toString(CryptoJS.enc.Utf8));
            if (user?.userId) return user;
        } catch {
            // encrypted by another app: try the next secret
        }
    }
    throw new Error("no configured shared secret matches the payload");
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

// Verifies the login token (issued by /api/ghl/sso) and keeps its user and location on req.login
function requireLoginToken(req, res, next) {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
        req.login = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });
        next();
    } catch {
        res.status(401).json({ error: "Invalid or expired token" });
    }
}

function sendError(res, err) {
    if (err instanceof HttpError) return res.status(err.status).json(err.body);
    console.error("Unexpected error:", err);
    res.status(500).json({ error: "Server error" });
}

// ---------- Service-to-service auth for the WayIQ backend ----------
function requireApiKey(req, res, next) {
    const given = Buffer.from(String(req.headers["x-api-key"] || ""));
    const expected = Buffer.from(WAYIQ_API_KEY);
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
        return res.status(401).json({ valid: false, code: "UNAUTHORIZED_CLIENT" });
    }
    next();
}

const WAYIQ_AUTH_URL = "https://api-wayiq.dev.purplescape.com/api/purpl-home/auth/ghl";

app.post("/api/wayiq/auth", async (req, res) => {
    const accessToken = req.body?.accessToken;
    if (!accessToken) return res.status(400).json({ error: "Missing accessToken" });

    try {
        // Only forward tokens that this service issued
        jwt.verify(accessToken, JWT_SECRET, { issuer: ISSUER, audience: "login" });
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }

    try {
        const r = await fetch(WAYIQ_AUTH_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ accessToken }),
        });
        const body = await r.json().catch(() => ({}));
        res.status(r.status).json(body);
    } catch (err) {
        console.error("WayIQ call failed:", err.message);
        res.status(502).json({ error: "WayIQ unreachable", reason: err.message });
    }
});

app.post("/api/wayiq/auth", async (req, res) => {
    const accessToken = req.body?.accessToken;
    if (!accessToken) return res.status(400).json({ error: "Missing accessToken" });

    try {
        // Only forward tokens that this service really issued
        jwt.verify(accessToken, JWT_SECRET, { issuer: ISSUER, audience: "login" });
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }

    try {
        const r = await fetch(WAYIQ_AUTH_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json", "auth-token": process.env.WAYIQ_AUTH_TOKEN },
            body: JSON.stringify({ accessToken }),
        });
        const body = await r.json().catch(() => ({}));
        res.status(r.status).json(body);
    } catch (err) {
        console.error("WayIQ call failed:", err.message);
        res.status(502).json({ error: "WayIQ unreachable" });
    }
});

// =====================================================
// 5) TOKEN VALIDATION for the WayIQ team (server-to-server)
//    POST /api/token/validate
//    Headers: X-Api-Key: <WAYIQ_API_KEY>
//             Authorization: Bearer <login token>
//    Check-only: verifies signature/expiry but does NOT consume the token.
//    Token is consumed exclusively by /wayiq/auth/ghl-login.
// =====================================================
app.post("/api/token/validate", requireApiKey, (req, res) => {
    const token = getBearer(req);
    if (!token) return res.status(400).json({ valid: false, code: "MISSING_TOKEN" });

    try {
        // Checks signature, issuer, audience and expiry (exp)
        const p = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });

        const now = Math.floor(Date.now() / 1000);
        res.json({
            valid: true,
            user: {
                ghlUserId: p.sub,
                name: p.name,
                email: p.email,
                role: p.role,
                companyId: p.companyId,
                locationId: p.locationId,
            },
            issuedAt: new Date(p.iat * 1000).toISOString(),
            expiresAt: new Date(p.exp * 1000).toISOString(),
            secondsRemaining: Math.max(0, p.exp - now),
        });
    } catch (err) {
        const code =
            err.name === "TokenExpiredError" ? "TOKEN_EXPIRED" :
                err.name === "NotBeforeError" ? "TOKEN_NOT_ACTIVE" :
                    "TOKEN_INVALID";
        res.status(401).json({
            valid: false,
            code,
            ...(err.name === "TokenExpiredError" && { expiredAt: err.expiredAt }),
        });
    }
});

// =====================================================
// 1) TOKEN SERVICE
//    POST /api/ghl/sso
//    Decrypts the GHL payload and issues a 60-second login token
// =====================================================
app.post("/api/ghl/sso", (req, res) => {
    try {
        const user = decryptSsoPayload(req.body?.encrypted);

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
            { expiresIn: "60m", issuer: ISSUER, audience: "login" }
        );

        res.json({ token });
    } catch (err) {
        console.error("SSO error:", err.message);
        res.status(400).json({ error: "Failed to decrypt user data" });
    }
});

// =====================================================
// 2) WAYIQ LOGIN
//    POST /wayiq/auth/ghl-login
//    Header: Authorization: Bearer <login token>
//    Validates the token, returns the verified user (and a session)
// =====================================================
app.post("/wayiq/auth/ghl-login", (req, res) => {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const p = jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: "login" });

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
// =====================================================
app.get("/wayiq/api/me", requireSession, (req, res) => {
    const { id, name, email, role, locationId } = req.user;
    res.json({ id, name, email, role, locationId });
});

// Add more WayIQ endpoints here, for example:
// app.get("/wayiq/api/reports", requireSession, (req, res) => { ... });

// =====================================================
// 6) GHL MARKETPLACE OAUTH (see ghl-oauth.js)
//    One agency install gives tokens for every sub-account
// =====================================================
app.get("/oauth/install", (_req, res) => {
    try {
        res.redirect(getInstallUrl());
    } catch (err) {
        sendError(res, err);
    }
});

app.get("/oauth/callback", async (req, res) => {
    try {
        res.json({ installed: true, ...(await handleInstallCallback(req.query.code)) });
    } catch (err) {
        sendError(res, err);
    }
});

app.post("/oauth/webhook", async (req, res) => {
    try {
        res.json(await handleWebhook(req.query.key, req.body));
    } catch (err) {
        sendError(res, err);
    }
});

// =====================================================
// 7) GHL TASK API (test endpoints for the OAuth location token)
//    Header: Authorization: Bearer <login token>
//    The location and user come from the login token, never from the request.
// =====================================================

// GET /api/ghl/tasks?contactId=...  -> the contact's tasks
app.get("/api/ghl/tasks", requireLoginToken, async (req, res) => {
    const { contactId } = req.query;
    if (!contactId) return res.status(400).json({ error: "Missing contactId" });
    try {
        const accessToken = await getLocationToken(req.login.companyId, req.login.locationId);
        res.json(await ghlRequest(accessToken, "GET", `/contacts/${encodeURIComponent(contactId)}/tasks`));
    } catch (err) {
        sendError(res, err);
    }
});

// POST /api/ghl/tasks  { contactId, title, body?, dueDate, completed? }  -> creates a task assigned to the signed-in user
app.post("/api/ghl/tasks", requireLoginToken, async (req, res) => {
    const { contactId, title, body, dueDate, completed = false } = req.body ?? {};
    if (!contactId || !title || !dueDate) {
        return res.status(400).json({ error: "contactId, title and dueDate are required" });
    }
    try {
        const accessToken = await getLocationToken(req.login.companyId, req.login.locationId);
        const task = { title, body, dueDate, completed, assignedTo: req.login.sub };
        res.json(await ghlRequest(accessToken, "POST", `/contacts/${encodeURIComponent(contactId)}/tasks`, task));
    } catch (err) {
        sendError(res, err);
    }
});

// =====================================================
// 4) WAYIQ UI PAGE (shown inside the funnel's frame)
//    GET /wayiq/ui  ->  public/wayiq.html
// =====================================================
app.get("/wayiq/ui", (_req, res) => {
    res.removeHeader("X-Frame-Options");
    res.setHeader("Content-Security-Policy", FRAME_ANCESTORS);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Security-Policy", "frame-ancestors *");
    res.sendFile(path.join(__dirname, "public", "wayiq.html"));
});

app.get("/", (_req, res) => res.send("Token service + WayIQ API running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server on :" + PORT));