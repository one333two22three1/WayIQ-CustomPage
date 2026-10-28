// GHL marketplace OAuth: one agency install -> location tokens for every sub-account.
//
//   GET  /oauth/install   -> GHL consent screen (agency admin picks the agency + sub-accounts)
//   GET  /oauth/callback  -> code exchanged for the Company (or Location) token, stored below
//   POST /oauth/webhook   -> INSTALL / UNINSTALL events
//
// Tokens are kept AES-encrypted in Postgres (DATABASE_URL, e.g. the Render database), in the
// same ghl_oauth_tokens table the ghl-wrapper-service uses. A refresh locks the row, so several
// instances can run without spending the single-use refresh token twice.
import pg from "pg";
import CryptoJS from "crypto-js";

export const GHL_API = "https://services.leadconnectorhq.com";
export const GHL_API_VERSION = "2021-07-28";
const INSTALL_URL = "https://marketplace.gohighlevel.com/oauth/chooselocation";
const TOKEN_URL = `${GHL_API}/oauth/token`;
const LOCATION_TOKEN_URL = `${GHL_API}/oauth/locationToken`;
const REFRESH_MARGIN_MS = 5 * 60 * 1000;      // refresh this long before expiry
const LOCATION_CACHE_MS = 60 * 60 * 1000;     // re-check a location's token at least hourly

const REQUIRED_ENV = ["DATABASE_URL", "GHL_OAUTH_CLIENT_ID", "GHL_OAUTH_CLIENT_SECRET", "GHL_OAUTH_REDIRECT_URI", "GHL_TOKEN_ENCRYPTION_KEY"];
const FORM_HEADERS = { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" };

const TABLE_SQL = `
CREATE TABLE IF NOT EXISTS ghl_oauth_tokens (
  resource_id   text        PRIMARY KEY,
  user_type     text        NOT NULL,
  company_id    text,
  access_token  text        NOT NULL,
  refresh_token text        NOT NULL,
  scope         text,
  expires_at    timestamptz NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
)`;

// Logs missing configuration and creates the token table. OAuth is optional at startup:
// the server keeps running without it and only the OAuth routes fail.
export async function initOAuth() {
    const missing = REQUIRED_ENV.filter((name) => !process.env[name]);
    if (missing.length) console.error(`GHL OAuth is missing environment variables: ${missing.join(", ")}`);
    if (!process.env.DATABASE_URL) return;
    try {
        await db().query(TABLE_SQL);
    } catch (err) {
        console.error("Could not prepare the ghl_oauth_tokens table:", err.message);
    }
}

// Error carrying the HTTP status and body to send back
export class HttpError extends Error {
    constructor(status, body = {}) {
        super(body.error || `HTTP error ${status}`);
        this.status = status;
        this.body = body;
    }
}

function env(name) {
    const value = process.env[name];
    if (!value) {
        console.error(`Missing environment variable: ${name}`);
        throw new HttpError(500, { error: "Server misconfigured" });
    }
    return value;
}

const encrypt = (value) => CryptoJS.AES.encrypt(value, env("GHL_TOKEN_ENCRYPTION_KEY")).toString();
const decrypt = (value) => CryptoJS.AES.decrypt(value, env("GHL_TOKEN_ENCRYPTION_KEY")).toString(CryptoJS.enc.Utf8);
const isFresh = (expiresAt) => expiresAt - REFRESH_MARGIN_MS > Date.now();

// ---------- Token store: one row per install, keyed by companyId (agency) or locationId (sub-account)
let pool = null;

// DATABASE_SSL: unset = verified SSL (Render external URL), "no-verify" = SSL without
// certificate check, "false" = no SSL (Render internal URL or a local database)
function db() {
    if (!pool) {
        const mode = process.env.DATABASE_SSL;
        pool = new pg.Pool({
            connectionString: env("DATABASE_URL"),
            ssl: mode === "false" ? false : mode === "no-verify" ? { rejectUnauthorized: false } : true,
            max: 5,
        });
        pool.on("error", (err) => console.error("Postgres pool error:", err.message));
    }
    return pool;
}

async function findToken(id) {
    const { rows } = await db().query("SELECT * FROM ghl_oauth_tokens WHERE resource_id = $1", [id]);
    return rows[0] ?? null;
}

async function saveToken(row, client = db()) {
    await client.query(
        `INSERT INTO ghl_oauth_tokens (resource_id, user_type, company_id, access_token, refresh_token, scope, expires_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (resource_id) DO UPDATE SET
           user_type = EXCLUDED.user_type, company_id = EXCLUDED.company_id,
           access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token,
           scope = EXCLUDED.scope, expires_at = EXCLUDED.expires_at, updated_at = now()`,
        [row.resource_id, row.user_type, row.company_id, row.access_token, row.refresh_token, row.scope, row.expires_at],
    );
}

async function deleteToken(id) {
    await db().query("DELETE FROM ghl_oauth_tokens WHERE resource_id = $1", [id]);
}

// Runs fn with the row locked (SELECT ... FOR UPDATE): other instances refreshing the same
// install wait here and then read the row the first one saved.
async function withLock(id, fn) {
    const client = await db().connect();
    try {
        await client.query("BEGIN");
        const { rows } = await client.query("SELECT * FROM ghl_oauth_tokens WHERE resource_id = $1 FOR UPDATE", [id]);
        const result = await fn(rows[0] ?? null, (row) => saveToken(row, client));
        await client.query("COMMIT");
        return result;
    } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

// ---------- GHL calls
async function postForm(url, params, headers = {}) {
    const r = await fetch(url, { method: "POST", headers: { ...FORM_HEADERS, ...headers }, body: new URLSearchParams(params) });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new HttpError(r.status, body);
    return body;
}

const requestToken = (params) => postForm(TOKEN_URL, {
    client_id: env("GHL_OAUTH_CLIENT_ID"),
    client_secret: env("GHL_OAUTH_CLIENT_SECRET"),
    ...params,
});

// Row to store from a token response; previous fills fields a refresh response may leave out
function toRow(data, previous) {
    const userType = data.userType ?? previous?.user_type;
    const companyId = data.companyId ?? previous?.company_id ?? null;
    const resourceId = previous?.resource_id ?? (userType === "Company" ? companyId : data.locationId);
    if (!userType || !resourceId || !data.access_token || !data.refresh_token) {
        throw new HttpError(502, { error: "Unexpected GHL token response" });
    }
    return {
        resource_id: resourceId,
        user_type: userType,
        company_id: companyId,
        access_token: encrypt(data.access_token),
        refresh_token: encrypt(data.refresh_token),
        scope: data.scope ?? null,
        expires_at: new Date(Date.now() + data.expires_in * 1000),
    };
}

const toAccessToken = (row) => ({ accessToken: decrypt(row.access_token), expiresAt: row.expires_at.getTime() });

// Access token of a stored install (companyId or locationId), refreshed when about to expire; null if none
async function getStoredAccessToken(id) {
    const row = await findToken(id);
    if (!row) return null;
    if (isFresh(row.expires_at.getTime())) return toAccessToken(row);

    return withLock(id, async (locked, save) => {
        if (!locked) return null;
        // Another instance may have refreshed it while this one waited for the lock
        if (isFresh(locked.expires_at.getTime())) return toAccessToken(locked);

        console.log(`Refreshing GHL ${locked.user_type} token for ${id}`);
        let data;
        try {
            data = await requestToken({
                grant_type: "refresh_token",
                refresh_token: decrypt(locked.refresh_token),
                user_type: locked.user_type,
            });
        } catch (err) {
            console.error(`GHL token refresh failed for ${locked.user_type} ${id}, the app must be reinstalled:`, err.status, JSON.stringify(err.body ?? err.message));
            throw new HttpError(401, { error: "GHL authorization expired, reinstall the app" });
        }
        const updated = toRow(data, locked);
        await save(updated);
        return { accessToken: data.access_token, expiresAt: updated.expires_at.getTime() };
    });
}

// Location token from the agency install; null when there is none or the app is not installed on the location
async function getTokenFromCompany(companyId, locationId) {
    if (!companyId) return null;
    const company = await getStoredAccessToken(companyId);
    if (!company) return null;
    try {
        const data = await postForm(LOCATION_TOKEN_URL, { companyId, locationId }, {
            Version: GHL_API_VERSION,
            Authorization: `Bearer ${company.accessToken}`,
        });
        return { accessToken: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
    } catch (err) {
        console.warn(`No location token for ${locationId} from company ${companyId} (is the app installed there?):`, err.status, JSON.stringify(err.body ?? err.message));
        return null;
    }
}

// ---------- Public API

export function getInstallUrl() {
    return `${INSTALL_URL}?${new URLSearchParams({
        response_type: "code",
        client_id: env("GHL_OAUTH_CLIENT_ID"),
        redirect_uri: env("GHL_OAUTH_REDIRECT_URI"),
        scope: process.env.GHL_OAUTH_SCOPES ?? "",
    })}`;
}

// Install callback: exchanges the code and stores the install's tokens
export async function handleInstallCallback(code) {
    if (!code) throw new HttpError(400, { error: "Missing code" });
    REQUIRED_ENV.forEach(env);   // fail before the single-use code is spent

    let data;
    try {
        data = await requestToken({
            grant_type: "authorization_code",
            code,
            redirect_uri: process.env.GHL_OAUTH_REDIRECT_URI,
            ...(process.env.GHL_OAUTH_USER_TYPE && { user_type: process.env.GHL_OAUTH_USER_TYPE }),
        });
    } catch (err) {
        console.error("GHL code exchange failed:", err.status, JSON.stringify(err.body ?? err.message));
        throw new HttpError(502, { error: "GHL code exchange failed" });
    }

    const row = toRow(data);
    await saveToken(row);
    if (data.locationId) locationCache.delete(data.locationId);
    console.log(`GHL app installed: ${row.user_type} ${row.resource_id}`);
    return { userType: data.userType, companyId: data.companyId ?? null, locationId: data.locationId ?? null };
}

const locationCache = new Map();   // locationId -> { accessToken, expiresAt, cachedAt }
const locationLoads = new Map();   // locationId -> in-flight load, so parallel requests share one call

// Access token for calling GHL APIs on a location: its own install first, then the agency install
export async function getLocationToken(companyId, locationId) {
    if (!locationId) throw new HttpError(400, { error: "Invalid Location Id" });

    const cached = locationCache.get(locationId);
    if (cached && isFresh(cached.expiresAt) && Date.now() - cached.cachedAt < LOCATION_CACHE_MS) {
        return cached.accessToken;
    }

    if (!locationLoads.has(locationId)) {
        locationLoads.set(locationId, (async () => {
            const token = await getStoredAccessToken(locationId)   // the sub-account installed the app itself
                ?? await getTokenFromCompany(companyId, locationId);
            if (!token) throw new HttpError(400, { error: "Invalid Location Id" });
            locationCache.set(locationId, { ...token, cachedAt: Date.now() });
            return token.accessToken;
        })().finally(() => locationLoads.delete(locationId)));
    }
    return locationLoads.get(locationId);
}

// Marketplace webhook (INSTALL / UNINSTALL); the URL carries ?key=GHL_OAUTH_WEBHOOK_KEY
export async function handleWebhook(webhookKey, body) {
    const expected = process.env.GHL_OAUTH_WEBHOOK_KEY;
    if (!expected || webhookKey !== expected) throw new HttpError(401, { error: "Unauthorized" });

    const { type, companyId, locationId } = body ?? {};
    if (type === "UNINSTALL") {
        if (locationId) {
            await deleteToken(locationId);
            locationCache.delete(locationId);
        } else if (companyId) {
            await deleteToken(companyId);
            locationCache.clear();
        }
        console.log(`GHL app uninstalled: company ${companyId ?? "-"}, location ${locationId ?? "-"}`);
    } else if (type === "INSTALL") {
        if (locationId) locationCache.delete(locationId);
        console.log(`GHL app installed: company ${companyId ?? "-"}, location ${locationId ?? "-"}`);
    }
    return { ok: true };
}

// Calls the GHL API on a location; GHL errors come back as HttpError with GHL's status and body
export async function ghlRequest(accessToken, method, apiPath, body) {
    const r = await fetch(`${GHL_API}${apiPath}`, {
        method,
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            Version: GHL_API_VERSION,
            Authorization: `Bearer ${accessToken}`,
        },
        ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new HttpError(r.status, data);
    return data;
}
