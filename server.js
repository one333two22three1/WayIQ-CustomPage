import express from "express";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());
const usedJti = new Set();   // use Redis with TTL in production

app.post("/api/ghl/sso", (req, res) => {
    try {
        const bytes = CryptoJS.AES.decrypt(req.body.encrypted, process.env.GHL_SHARED_SECRET);
        const user = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        if (!user.userId) throw new Error("bad payload");

        const token = jwt.sign(
            {
                sub: user.userId,
                email: user.email,
                name: user.userName,
                role: user.role,
                companyId: user.companyId,
                locationId: user.activeLocation,   // location context only
                jti: crypto.randomUUID(),
            },
            process.env.JWT_SECRET,
            { expiresIn: "60s", issuer: "wayhub.io" }
        );
        res.json({ token });
    } catch {
        res.status(400).json({ error: "Failed to decrypt user data" });
    }
});

// Exchange the URL token for a real session
app.post("/api/auth/exchange", (req, res) => {
    try {
        const p = jwt.verify(req.body.token, process.env.JWT_SECRET, { issuer: "wayhub.io" });
        if (usedJti.has(p.jti)) return res.status(401).end();
        usedJti.add(p.jti);
        const session = jwt.sign({ sub: p.sub, email: p.email, name: p.name, locationId: p.locationId },
            process.env.JWT_SECRET, { expiresIn: "8h" });
        res.json({ session });
    } catch { res.status(401).end(); }
});