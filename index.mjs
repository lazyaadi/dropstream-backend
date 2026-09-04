import express  from "express";
import http     from "http";
import { Server } from "socket.io";
import cors     from "cors";
import dotenv   from "dotenv";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import { createHmac } from "crypto";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import {
  hashSecret,
  verifyUserPassword,                 
  verifyWorkspacePin,
  verifyProPinWithWorker,
  maybeUpgradeWorkspacePin,
  parseAllowedOrigins,
  isOriginAllowed,
} from "./security.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, ".env") });

const IS_DEV = process.env.NODE_ENV !== "production";
const ALLOWED_ORIGINS = parseAllowedOrigins();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_REDIRECT_TOKEN_SECRET = process.env.GOOGLE_REDIRECT_TOKEN_SECRET || process.env.ADMIN_SECRET || "";
const PRIMARY_CLIENT_URL = ALLOWED_ORIGINS[0] || "http://localhost:5173";
const devLog = (...args) => { if (IS_DEV) console.log(...args); };

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception thrown:", err);
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const corsOrigin = ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true;
const setHeaderValue = (target, key, value) => {
  if (target && typeof target.setHeader === "function") {
    target.setHeader(key, value);
    return;
  }
  if (target) {
    target[key] = value;
  }
};

const applyCorsHeaders = (headers, origin) => {
  const resolvedOrigin = origin || "*";
  setHeaderValue(headers, "Access-Control-Allow-Origin", resolvedOrigin);
  setHeaderValue(headers, "Access-Control-Allow-Credentials", "true");
  setHeaderValue(headers, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-Contact-Request-ID");
  setHeaderValue(headers, "Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  setHeaderValue(headers, "Vary", "Origin");
};

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || isOriginAllowed(origin, ALLOWED_ORIGINS)) {
    applyCorsHeaders(res, origin);
  }
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.use(cors({ origin: corsOrigin, credentials: true }));

const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e7,
  pingTimeout: 20000,
  pingInterval: 25000,
  cors: {
    origin: corsOrigin,
    methods: ["GET", "POST", "OPTIONS"],
    credentials: true,
  },
  transports: ["polling", "websocket"],
});

io.engine.on("initial_headers", (headers, req) => {
  const origin = req.headers.origin;
  if (!origin || isOriginAllowed(origin, ALLOWED_ORIGINS)) {
    applyCorsHeaders(headers, origin);
  }
});

io.engine.on("headers", (headers, req) => {
  const origin = req.headers.origin;
  if (!origin || isOriginAllowed(origin, ALLOWED_ORIGINS)) {
    applyCorsHeaders(headers, origin);
  }
});

const PUSHOVER_TOKEN = process.env.PUSHOVER_TOKEN || "";
const PUSHOVER_USER_KEY = process.env.PUSHOVER_USER_KEY || "";
const logNotificationError = (err, context = {}) => {
  const details = {
    message: err?.message,
    code: err?.code,
    response: err?.response,
    responseCode: err?.responseCode,
    errno: err?.errno,
    syscall: err?.syscall,
    address: err?.address,
    port: err?.port,
    host: err?.host,
    context,
  };
  console.error("[contact] notification error:", JSON.stringify(details, null, 2));
  if (err?.stack) console.error("[contact] notification stack:\n" + err.stack);
};

const sendViaPushover = async (payload) => {
  if (!PUSHOVER_TOKEN || !PUSHOVER_USER_KEY) {
    throw new Error("Pushover delivery not configured.");
  }

  const startedAt = Date.now();
  const timeoutMs = 10000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("Pushover request timed out.")), timeoutMs);
  const body = new URLSearchParams();
  body.set("token", PUSHOVER_TOKEN);
  body.set("user", PUSHOVER_USER_KEY);
  body.set("title", payload.title);
  body.set("message", payload.message);
  body.set("priority", "0");
  body.set("html", "1");

  try {
    const response = await fetch("https://api.pushover.net/1/messages.json", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: controller.signal,
    });

    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`Pushover HTTP ${response.status}: ${responseText.slice(0, 500)}`);
    }

    return responseText;
  } catch (err) {
    logNotificationError(err, { stage: "pushover-send", durationMs: Date.now() - startedAt });
    throw err;
  } finally {
    clearTimeout(timeout);
  }
};

const formatContactPushoverMessage = (entry) => {
  const clean = (value) => String(value || "").trim();
  const cleanSingleLine = (value) => clean(value).replace(/\s+/g, " ");

  const name = cleanSingleLine(entry.name);
  const email = cleanSingleLine(entry.email).toLowerCase();
  const subject = cleanSingleLine(entry.subject);
  const workspace = cleanSingleLine(entry.workspaceName);
  const role = cleanSingleLine(entry.role);
  const ip = cleanSingleLine(entry.ip);
  const userName = cleanSingleLine(entry.userName);
  const userEmail = cleanSingleLine(entry.userEmail).toLowerCase();

  const lines = [];
  lines.push(`<b>Name:</b> ${name || "Anonymous"}`);
  if (email) lines.push(`<b>Email:</b> ${email}`);
  if (subject) lines.push(`<b>Subject:</b> ${subject}`);
  if (workspace) lines.push(`<b>Workspace:</b> ${workspace}`);
  if (role) lines.push(`<b>Role:</b> ${role}`);
  if (ip) lines.push(`<b>IP:</b> ${ip}`);

  if (userName && userName.toLowerCase() !== (name || "").toLowerCase()) {
    lines.push(`<b>User Name:</b> ${userName}`);
  }
  if (userEmail && userEmail !== email) {
    lines.push(`<b>User Email:</b> ${userEmail}`);
  }

  const rawMessage = clean(entry.message)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join("\n");

  lines.push("");
  lines.push("<b>Message:</b>");
  lines.push(rawMessage || "(empty)");

  const maxLen = 1000;
  let text = lines.join("\n");
  if (text.length > maxLen) {
    text = `${text.slice(0, maxLen - 20)}\n... (truncated)`;
  }
  return text;
};

const normalizeText = (value) => String(value ?? "").trim();
const normalizeEmail = (value) => normalizeText(value).toLowerCase();

const emitWorkspaceError = (socket, message, eventName = "workspace_error") => {
  const safeMessage = String(message || "An unexpected workspace error occurred.");
  socket.emit("error_msg", safeMessage);
  socket.emit("error", { message: safeMessage, event: eventName });
};

const withSocketGuard = (socket, eventName, handler) => async (data = {}) => {
  try {
    return await handler(data || {});
  } catch (err) {
    console.error(`[${eventName}] Unhandled socket error:`, err);
    emitWorkspaceError(socket, "An unexpected workspace error occurred. Please try again.", eventName);
  }
};

app.post("/auth/google/callback", express.urlencoded({ extended: false }), async (req, res) => {
  const credential = String(req.body?.credential || req.body?.id_token || "").trim();
  const clientUrl = getClientRedirectUrl(req);
  const verified = await verifyGoogleToken(credential);

  if (!verified.ok) {
    return res.redirect(`${clientUrl}?google_auth_error=${encodeURIComponent("Google sign-in could not be verified. Please try again.")}`);
  }

  const token = signGoogleRedirectPayload({
    email: verified.email,
    name: verified.name,
    picture: verified.picture || null,
    sub: verified.sub || null,
    exp: Date.now() + (5 * 60 * 1000),
  });

  return res.redirect(`${clientUrl}?google_auth_token=${encodeURIComponent(token)}`);
});

app.post("/api/contact", async (req, res) => {
  const body = req.body || {};
  const requestId = String(req.headers["x-contact-request-id"] || body.requestId || "").trim();
  const name = String(body.name || "").trim().slice(0, 80);
  const email = String(body.email || "").trim().toLowerCase().slice(0, 120);
  const subject = String(body.subject || "").trim().slice(0, 120);
  const message = String(body.message || "").trim().slice(0, 2000);
  const website = String(body.website || "").trim().slice(0, 120);
  const workspaceName = String(body.workspaceName || "").trim().slice(0, 40);
  const userName = String(body.userName || "").trim().slice(0, 80);
  const userEmail = String(body.userEmail || "").trim().toLowerCase().slice(0, 120);
  const role = String(body.role || "").trim().slice(0, 40);

  const contactIp = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";
  const contactThrottle = allowSensitiveAttempt(scopeForIp("contact", contactIp));
  if (!contactThrottle.allowed) {
    return res.status(429).json({ error: "Too many contact requests. Please wait a few minutes and try again." });
  }

  if (website) {
    return res.json({ ok: true });
  }

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Valid email is required." });
  }
  if (!message || message.length < 8) {
    return res.status(400).json({ error: "Message is too short." });
  }

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";
  const ua = String(req.headers["user-agent"] || "").slice(0, 300);
  const entry = {
    requestId,
    name: name || userName || "Anonymous",
    email,
    subject,
    message,
    workspaceName,
    userName,
    userEmail,
    role,
    ip,
    ua,
    createdAt: new Date().toISOString(),
  };

  try {
    if (mongoConnected) {
      const collection = mongoose.connection.db.collection("contact_messages");
      collection.insertOne(entry).catch((err) => {
        console.error("[contact] Failed to store message in background:", err.message);
      });
    } else {
      contactMessages.push(entry);
      if (contactMessages.length > CONTACT_MESSAGE_LIMIT) contactMessages.shift();
    }
  } catch (err) {
    return res.status(500).json({ error: "Failed to store message." });
  }

  try {
    if (!PUSHOVER_TOKEN || !PUSHOVER_USER_KEY) {
      return res.status(503).json({ error: "Pushover delivery not configured." });
    }

    const messageLines = formatContactPushoverMessage(entry);

    sendViaPushover({
      title: `SyncBoard Contact${workspaceName ? ` • ${workspaceName}` : ""}${subject ? ` • ${subject}` : ""}`,
      message: messageLines,
    }).catch(() => {});

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to send notification." });
  }
});

const MONGO_URI = process.env.MONGO_URI;
let mongoConnected = false;

app.get(["/api/auth/me", "/api/user/profile"], async (req, res) => {
  const email = String(req.query.email || req.headers["x-user-email"] || "").trim();
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  try {
    const profile = await getHydratedUserProfile(email);
    if (!profile) {
      return res.status(404).json({ error: "User not found." });
    }
    return res.json({ ok: true, profile });
  } catch (err) {
    return res.status(500).json({ error: "Failed to load profile." });
  }
});

async function connectDB() {
  if (!MONGO_URI) {
    console.warn("[connectDB] MONGO_URI not configured, running in memory-only mode");
    return;
  }
  
  try {
    const connectionPromise = mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 5000,
    });
    
    await Promise.race([
      connectionPromise,
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error("Connection timeout after 10 seconds")), 10000)
      )
    ]);
    
    mongoConnected = true;
    console.log("[connectDB] MongoDB connected successfully.");
  } catch (err) {
    mongoConnected = false;
    console.error("[connectDB] MongoDB connection FAILED:", err.message);
  }
}

async function saveRoomToDB(workspaceName) {
  if (!mongoConnected) return;

  const key = normalizeText(workspaceName);
  if (!key) return;

  const ws = workspaces[key];
  if (!ws) return;
  let creatorEmailToSave = normalizeText(ws.creatorEmail);
  if (!creatorEmailToSave) {
    const adminMember = Array.isArray(ws.members) ? ws.members.find(m => m?.role === "admin") : null;
    if (adminMember && adminMember.email) {
      creatorEmailToSave = normalizeText(adminMember.email);
    }
  }
  
  try {
    const collection = mongoose.connection.db.collection("workspaces");
    await collection.updateOne(
      { workspaceName: key },
      {
        $set: {
          workspaceName: key,
          password: ws.password,
          projectName: ws.projectName,
          creatorEmail: creatorEmailToSave,
          isPro: ws.isPro || false,
          proExpiresAt: ws.proExpiresAt || null,
          tasks: ws.tasks || [],
          history: ws.history || [],
          members: ws.members || [],
          updatedAt: new Date().toISOString(),
        }
      },
      { upsert: true }
    );
  } catch (err) {
    console.error(`[saveRoomToDB] Error saving ${key}:`, err.message);
  }
}

async function loadRoomFromDB(workspaceName) {
  if (!mongoConnected) return null;

  const key = normalizeText(workspaceName);
  if (!key) return null;
  
  try {
    const collection = mongoose.connection.db.collection("workspaces");
    const doc = await collection.findOne({ workspaceName: key });
    
    if (doc) {
      return {
        password: doc.password,
        projectName: doc.projectName,
        creatorEmail: doc.creatorEmail,
        isPro: doc.isPro || false,
        proExpiresAt: doc.proExpiresAt || null,
        tasks: doc.tasks || [],
        history: doc.history || [],
        members: doc.members || [],
        sockets: new Map(),
      };
    }
    return null;
  } catch (err) {
    return null;
  }
}

async function saveUserToDB(email) {
  if (!mongoConnected) return;
  
  const key = normalizeEmail(email);
  if (!key) return;
  const user = users[key];
  if (!user) return;
  
  try {
    const collection = mongoose.connection.db.collection("users");
    await collection.updateOne(
      { email: key },
      {
        $set: {
          email: key,
          name: user.name,
          passwordHash: user.passwordHash,
          taskCount: user.taskCount,
          resetAt: user.resetAt,
          taskIds: user.taskIds || [],
          isPro: user.isPro,
          proPin: user.proPin,
          proActivatedAt: user.proActivatedAt || null,
          proExpiresAt: user.proExpiresAt || null,
          authProvider: user.authProvider || null,
          googleSub: user.googleSub || null,
          googlePicture: user.googlePicture || null,
          updatedAt: new Date().toISOString(),
        }
      },
      { upsert: true }
    );
  } catch (err) {
    console.error(`[saveUserToDB] Error saving ${key}:`, err.message);
  }
}

async function loadUserFromDB(email) {
  if (!mongoConnected) return null;
  
  const key = normalizeEmail(email);
  if (!key) return null;
  
  try {
    const collection = mongoose.connection.db.collection("users");
    const doc = await collection.findOne({ email: key });
    
    if (doc) {
      return {
        name: doc.name,
        passwordHash: doc.passwordHash,
        taskCount: doc.taskCount || 0,
        resetAt: doc.resetAt,
        taskIds: doc.taskIds || [],
        isPro: doc.isPro || false,
        proPin: doc.proPin,
        proActivatedAt: doc.proActivatedAt || null,
        proExpiresAt: doc.proExpiresAt || null,
        authProvider: doc.authProvider || null,
        googleSub: doc.googleSub || null,
        googlePicture: doc.googlePicture || null,
      };
    }
    return null;
  } catch (err) {
    return null;
  }
}

async function getHydratedUserProfile(email) {
  const key = normalizeEmail(email);
  if (!key) return null;

  const resetExpiredProUser = async (userRecord) => {
    if (!userRecord || !userRecord.isPro) return false;
    userRecord.isPro = false;
    userRecord.proPin = null;
    userRecord.proActivatedAt = null;
    userRecord.proExpiresAt = null;
    userRecord.taskCount = 0;
    userRecord.resetAt = null;
    userRecord.taskIds = [];
    if (mongoConnected) {
      try {
        const collection = mongoose.connection.db.collection("users");
        await collection.updateOne(
          { email: key },
          {
            $set: {
              isPro: false,
              proPin: null,
              proActivatedAt: null,
              proExpiresAt: null,
              taskCount: 0,
              resetAt: null,
              taskIds: [],
              updatedAt: new Date().toISOString(),
            },
          }
        );
      } catch (err) {}
    }
    return true;
  };

  if (!mongoConnected) {
    const cachedUser = users[key];
    if (!cachedUser) return null;
    const proState = resolveActiveProState(cachedUser);
    if (!proState.isPro) {
      await resetExpiredProUser(cachedUser);
    }
    return {
      email: key,
      name: cachedUser.name || "",
      taskCount: cachedUser.taskCount || 0,
      resetAt: cachedUser.resetAt || null,
      isPro: cachedUser.isPro || false,
      proActivatedAt: cachedUser.proActivatedAt || null,
      proExpiresAt: cachedUser.proExpiresAt || null,
      authProvider: cachedUser.authProvider || null,
      googleSub: cachedUser.googleSub || null,
      googlePicture: cachedUser.googlePicture || null,
    };
  }

  const collection = mongoose.connection.db.collection("users");
  const doc = await collection.findOne({ email: key });
  if (!doc) return null;

  let isPro = doc.isPro === true;
  let proExpiresAt = doc.proExpiresAt || null;
  const proExpired = isPro && proExpiresAt && new Date(proExpiresAt).getTime() <= Date.now();
  if (proExpired) {
    isPro = false;
    proExpiresAt = null;
    await resetExpiredProAccount(key, {
      name: doc.name || "",
      passwordHash: doc.passwordHash,
      taskCount: doc.taskCount || 0,
      resetAt: doc.resetAt || null,
      taskIds: doc.taskIds || [],
      isPro: true,
      proPin: doc.proPin,
      proActivatedAt: doc.proActivatedAt || null,
      proExpiresAt: doc.proExpiresAt || null,
      authProvider: doc.authProvider || null,
      googleSub: doc.googleSub || null,
      googlePicture: doc.googlePicture || null,
    });
  }

  users[key] = {
    name: doc.name || "",
    passwordHash: doc.passwordHash,
    taskCount: doc.taskCount || 0,
    resetAt: doc.resetAt || null,
    taskIds: doc.taskIds || [],
    isPro,
    proPin: doc.proPin,
    proActivatedAt: doc.proActivatedAt || null,
    proExpiresAt,
    authProvider: doc.authProvider || null,
    googleSub: doc.googleSub || null,
    googlePicture: doc.googlePicture || null,
  };

  const hydrated = users[key];
  return {
    email: key,
    name: hydrated?.name || "",
    taskCount: hydrated?.taskCount || 0,
    resetAt: hydrated?.resetAt || null,
    isPro: hydrated?.isPro || false,
    proActivatedAt: hydrated?.proActivatedAt || null,
    proExpiresAt: hydrated?.proExpiresAt || null,
    authProvider: hydrated?.authProvider || null,
    googleSub: hydrated?.googleSub || null,
    googlePicture: hydrated?.googlePicture || null,
  };
}

function resolveActiveProState(user) {
  if (!user) {
    return { isPro: false, proExpiresAt: null };
  }

  const isProFlag = !!user.isPro;
  const proExpiresAt = user.proExpiresAt || null;

  if (!isProFlag) {
    return { isPro: false, proExpiresAt: null };
  }

  if (proExpiresAt) {
    const expTime = new Date(proExpiresAt).getTime();
    if (!Number.isNaN(expTime) && Date.now() > expTime) {
      user.isPro = false;
      user.proPin = null;
      user.proActivatedAt = null;
      user.proExpiresAt = null;
      return { isPro: false, proExpiresAt: null };
    }
  }

  return { isPro: true, proExpiresAt };
}

const workspaces = {};
const pendingLeaveTimers = new Map();
const users = {};

const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS_PER_WINDOW = 8;
  const sensitiveAttemptBuckets = new Map();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOGIN_MAX_FAILURES = 3;
const loginFailureTracker = new Map();

function registerLoginFailure(key) {
  const rec = loginFailureTracker.get(key) || { count: 0 };
  rec.count += 1;
  loginFailureTracker.set(key, rec);
  return rec.count;
}

function clearLoginFailures(key) {
  loginFailureTracker.delete(key);
}

const JOIN_LOCKOUT_MS = 30 * 60 * 1000;
const JOIN_MAX_FAILURES = 3;
const joinFailureTracker = new Map();

function getJoinLockoutState(scope) {
  const rec = joinFailureTracker.get(scope);
  if (!rec) return { locked: false, unlockAt: 0 };
  if (rec.lockedUntil && rec.lockedUntil > Date.now()) {
    return { locked: true, unlockAt: rec.lockedUntil };
  }
  if (rec.lockedUntil && rec.lockedUntil <= Date.now()) {
    joinFailureTracker.delete(scope);
  }
  return { locked: false, unlockAt: 0 };
}

function registerJoinFailure(scope) {
  const rec = joinFailureTracker.get(scope) || { count: 0, lockedUntil: null };
  rec.count += 1;
  if (rec.count >= JOIN_MAX_FAILURES) {
    rec.lockedUntil = Date.now() + JOIN_LOCKOUT_MS;
    rec.count = 0;
  }
  joinFailureTracker.set(scope, rec);
  return rec.lockedUntil && rec.lockedUntil > Date.now() ? rec.lockedUntil : 0;
}

function clearJoinFailures(scope) {
  joinFailureTracker.delete(scope);
}

function getAttemptBucket(scope) {
  const now = Date.now();
  const existing = sensitiveAttemptBuckets.get(scope);
  if (!existing || existing.expiresAt <= now) {
    const fresh = { count: 0, expiresAt: now + ATTEMPT_WINDOW_MS };
    sensitiveAttemptBuckets.set(scope, fresh);
    return fresh;
  }
  return existing;
}

function allowSensitiveAttempt(scope) {
  const bucket = getAttemptBucket(scope);
  if (bucket.count >= MAX_ATTEMPTS_PER_WINDOW) {
    return { allowed: false, retryAfterMs: Math.max(0, bucket.expiresAt - Date.now()) };
  }

  bucket.count += 1;
  return { allowed: true, retryAfterMs: 0 };
}

function scopeForEmail(eventName, email) {
  return `${eventName}:${String(email || "").trim().toLowerCase()}`;
}

function scopeForIp(eventName, ip) {
  return `${eventName}:${String(ip || "").trim().toLowerCase()}`;
}

const FREE_TASK_LIMIT = 3;
const PRO_TASK_LIMIT = 3000;
const MONTH_MS = 30 * 24 * 60 * 60 * 1000;
const PRO_DURATION_MS = 30 * 24 * 60 * 60 * 1000;

const GIBBERISH_NAMES = [
  "Loading....",
  "Syncing....",
  "Updating....",
];

function obfuscateText(seed = 0) {
  return GIBBERISH_NAMES[Math.abs(seed) % GIBBERISH_NAMES.length];
}

async function registerUser(email, name, password) {
  const key = normalizeEmail(email);
  const passwordHash = await hashSecret(password);
  users[key] = {
    name: normalizeText(name),
    passwordHash,
    taskCount: 0,
    resetAt: null,
    taskIds: [],
    isPro: false,
    proPin: null,
    proActivatedAt: null,
    proExpiresAt: null,
  };
  await saveUserToDB(email);
  return { key, user: users[key] };
}

async function verifyLogin(email, password) {
  const key = normalizeEmail(email);
  let user = users[key];

  if (!user) {
    const dbUser = await loadUserFromDB(email);
    if (dbUser) {
      users[key] = {
        name: dbUser.name,
        passwordHash: dbUser.passwordHash,
        taskCount: dbUser.taskCount || 0,
        resetAt: dbUser.resetAt,
        taskIds: dbUser.taskIds || [],
        isPro: dbUser.isPro || false,
        proPin: dbUser.proPin,
        proActivatedAt: dbUser.proActivatedAt || null,
        proExpiresAt: dbUser.proExpiresAt || null,
      };
      user = users[key];
    }
  }

  if (!user) return { ok: false, reason: "no_account" };

  const check = await verifyUserPassword(password, user.passwordHash);
  if (!check.ok) return { ok: false, reason: "wrong_password" };

  if (check.upgraded && check.newHash) {
    user.passwordHash = check.newHash;
    await saveUserToDB(email);
  }

  return { ok: true, user, key };
}

async function verifyGoogleToken(credential) {
  const token = String(credential || "").trim();
  if (!token) return { ok: false, reason: "missing_token" };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(token)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) return { ok: false, reason: "invalid_token" };
    const payload = await response.json();

    if (!payload?.email || !payload?.sub) return { ok: false, reason: "invalid_token" };
    if (GOOGLE_CLIENT_ID && payload.aud && payload.aud !== GOOGLE_CLIENT_ID) return { ok: false, reason: "bad_audience" };
    if (payload.email_verified && String(payload.email_verified).toLowerCase() !== "true") return { ok: false, reason: "unverified_email" };

    return {
      ok: true,
      email: String(payload.email).toLowerCase().trim(),
      name: String(payload.name || payload.email.split("@")[0]).trim(),
      picture: payload.picture || null,
      sub: payload.sub || null,
    };
  } catch {
    return { ok: false, reason: "invalid_token" };
  }
}

function signGoogleRedirectPayload(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", GOOGLE_REDIRECT_TOKEN_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyGoogleRedirectPayload(token) {
  const raw = String(token || "").trim();
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = createHmac("sha256", GOOGLE_REDIRECT_TOKEN_SECRET).update(body).digest("base64url");
  if (sig !== expected) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload?.email || !payload?.name || !payload?.exp) return null;
    if (Date.now() > Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getClientRedirectUrl(req) {
  const origin = String(req.headers.origin || "").trim();
  if (origin && isOriginAllowed(origin, ALLOWED_ORIGINS)) return origin;

  const referer = String(req.headers.referer || "").trim();
  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (isOriginAllowed(refererOrigin, ALLOWED_ORIGINS)) return refererOrigin;
    } catch {}
  }

  return ALLOWED_ORIGINS.find((value) => value.startsWith("https://")) || PRIMARY_CLIENT_URL;
}

function finalizeGoogleAuth(socket, payload, source = "google") {
  const email = String(payload.email || "").toLowerCase().trim();
  const displayName = String(payload.name || payload.email?.split("@")[0] || "").trim();
  if (!email || !displayName) {
    socket.emit("auth_google_error", "Google sign-in could not be completed.");
    return;
  }

  const key = email;

  const finalizeExisting = (userRecord) => {
    userRecord.authProvider = "google";
    userRecord.googleSub = payload.sub || userRecord.googleSub || null;
    userRecord.googlePicture = payload.picture || userRecord.googlePicture || null;
    if (displayName && displayName !== userRecord.name) {
      userRecord.name = displayName;
    }
    if (userRecord.resetAt && new Date() > new Date(userRecord.resetAt)) {
      userRecord.taskCount = 0;
      userRecord.resetAt = null;
      userRecord.taskIds = [];
    }
    saveUserToDB(email).catch(() => {});
    const { count, resetAt } = getUserTaskData(email);
    getHydratedUserProfile(email).then((profile) => {
      socket.emit("auth_success", {
        email: key,
        name: profile?.name || userRecord.name,
        isPro: profile?.isPro || false,
        taskCount: count,
        resetAt,
        proExpiresAt: profile?.proExpiresAt || null,
      });
    }).catch(() => {
      socket.emit("auth_success", {
        email: key,
        name: userRecord.name,
        isPro: userRecord.isPro,
        taskCount: count,
        resetAt,
        proExpiresAt: userRecord.proExpiresAt || null,
      });
    });
  };

  const finalizeNew = () => {
    users[key] = {
      name: displayName,
      passwordHash: null,
      taskCount: 0,
      resetAt: null,
      taskIds: [],
      isPro: false,
      proPin: null,
      proActivatedAt: null,
      proExpiresAt: null,
      authProvider: "google",
      googleSub: payload.sub || null,
      googlePicture: payload.picture || null,
    };
    saveUserToDB(email).catch(() => {});
    socket.emit("auth_success", {
      email: key,
      name: displayName,
      isPro: false,
      taskCount: 0,
      resetAt: null,
      proExpiresAt: null,
    });
  };

  if (users[key]) {
    finalizeExisting(users[key]);
    return;
  }

  loadUserFromDB(email).then((dbUser) => {
    if (dbUser) {
      users[key] = {
        name: dbUser.name,
        passwordHash: dbUser.passwordHash,
        taskCount: dbUser.taskCount || 0,
        resetAt: dbUser.resetAt,
        taskIds: dbUser.taskIds || [],
        isPro: dbUser.isPro || false,
        proPin: dbUser.proPin,
        proActivatedAt: dbUser.proActivatedAt || null,
        proExpiresAt: dbUser.proExpiresAt || null,
        authProvider: dbUser.authProvider || "google",
        googleSub: dbUser.googleSub || payload.sub || null,
        googlePicture: dbUser.googlePicture || payload.picture || null,
      };
      finalizeExisting(users[key]);
      return;
    }
    finalizeNew();
  }).catch(() => {
    finalizeNew();
  });
}

async function upgradeWorkspacePinIfNeeded(ws, workspaceName, plainPin) {
  if (typeof maybeUpgradeWorkspacePin !== "function") return;
  try {
    const upgraded = await maybeUpgradeWorkspacePin(plainPin, ws.password);
    if (upgraded !== ws.password) {
      ws.password = upgraded;
      await saveRoomToDB(workspaceName);
    }
  } catch {}
}

function getUserTaskData(email) {
  const key = normalizeEmail(email);
  const user = users[key];
  if (!user) return { count: 0, resetAt: null };
  if (user.resetAt && new Date() > new Date(user.resetAt)) {
    user.taskCount = 0;
    user.resetAt   = null;
    user.taskIds   = [];
  }
  return { count: user.taskCount, resetAt: user.resetAt };
}

async function ensureUserLoaded(email) {
  const key = normalizeEmail(email);
  if (users[key]) return users[key];
  const dbUser = await loadUserFromDB(email);
  if (!dbUser) return null;
  users[key] = {
    name: dbUser.name,
    passwordHash: dbUser.passwordHash,
    taskCount: dbUser.taskCount || 0,
    resetAt: dbUser.resetAt,
    taskIds: dbUser.taskIds || [],
    isPro: dbUser.isPro || false,
    proPin: dbUser.proPin,
    proActivatedAt: dbUser.proActivatedAt || null,
    proExpiresAt: dbUser.proExpiresAt || null,
  };
  resolveActiveProState(users[key]);
  return users[key];
}

async function incrementUserTaskCountAsync(email, taskId) {
  const key = normalizeEmail(email);
  const user = await ensureUserLoaded(email);
  if (!user) return 0;
  user.taskCount++;
  if (!user.resetAt) {
    const next = new Date(Date.now() + MONTH_MS);
    user.resetAt = next.toISOString();
  }
  user.taskIds.push(taskId);
  await saveUserToDB(email);
  return user.taskCount;
}

async function markUserPro(email, proPin, expiresAtOverride) {
  const key = normalizeEmail(email);
  const user = users[key];
  if (!user) return false;
  user.isPro  = true;
  user.proPin = proPin;
  user.proActivatedAt = new Date().toISOString();
  user.proExpiresAt = expiresAtOverride || new Date(Date.now() + PRO_DURATION_MS).toISOString();

  if (!mongoConnected) return true;

  try {
    const collection = mongoose.connection.db.collection("users");
    await collection.updateOne(
      { email: key },
      {
        $set: {
          email: key,
          isPro: true,
          proPin: user.proPin,
          proActivatedAt: user.proActivatedAt,
          proExpiresAt: user.proExpiresAt,
          updatedAt: new Date().toISOString(),
        },
      },
      { upsert: true }
    );
  } catch (err) {}
  return true;
}

async function resetExpiredProAccount(email, userRecord = null) {
  const key = normalizeEmail(email);
  const user = userRecord || users[key];
  if (!user) return false;
  if (!user.isPro) return false;

  user.isPro = false;
  user.proPin = null;
  user.proActivatedAt = null;
  user.proExpiresAt = null;
  user.taskCount = 0;
  user.resetAt = null;
  user.taskIds = [];

  if (!mongoConnected) return true;

  try {
    const collection = mongoose.connection.db.collection("users");
    await collection.updateOne(
      { email: key },
      {
        $set: {
          email: key,
          isPro: false,
          proPin: null,
          proActivatedAt: null,
          proExpiresAt: null,
          taskCount: 0,
          resetAt: null,
          taskIds: [],
          updatedAt: new Date().toISOString(),
        },
      },
      { upsert: true }
    );
  } catch (err) {}
  return true;
}

async function deactivateUserPro(email) {
  const key = normalizeEmail(email);
  const user = users[key];
  if (!user) return false;
  user.isPro = false;
  user.proPin = null;
  user.proActivatedAt = null;
  user.proExpiresAt = null;

  if (!mongoConnected) return true;

  try {
    const collection = mongoose.connection.db.collection("users");
    await collection.updateOne(
      { email: key },
      {
        $set: {
          email: key,
          isPro: false,
          proPin: null,
          proActivatedAt: null,
          proExpiresAt: null,
          updatedAt: new Date().toISOString(),
        },
      },
      { upsert: true }
    );
  } catch (err) {}
  return true;
}

function getValidOnlineMembers(room) {
  const seenEmails = new Set();
  const validList = [];

  for (const [, socketData] of room?.sockets || []) {
    const email = socketData?.email || socketData?.user?.email;
    if (!email || typeof email !== "string" || !email.includes("@")) continue;
    const normalizedEmail = email.toLowerCase().trim();
    if (!normalizedEmail || seenEmails.has(normalizedEmail)) continue;

    seenEmails.add(normalizedEmail);
    validList.push({
      email: normalizedEmail,
      name: socketData?.name || socketData?.user?.name || normalizedEmail.split("@")[0],
      role: socketData?.role || "member",
      isOnline: true,
    });
  }

  return validList;
}

function getValidWorkspaceMembers(room) {
  const seenEmails = new Set();
  const validList = [];

  for (const member of room?.members || []) {
    const email = member?.email;
    if (!email || typeof email !== "string" || !email.includes("@")) continue;
    const normalizedEmail = email.toLowerCase().trim();
    if (!normalizedEmail || seenEmails.has(normalizedEmail)) continue;

    seenEmails.add(normalizedEmail);
    validList.push({
      ...member,
      email: normalizedEmail,
    });
  }

  return validList;
}

async function broadcastUsers(workspaceName) {
  const ws = workspaces[workspaceName];
  if (!ws) return;

  const online = getValidOnlineMembers(ws);

  const proByEmail = new Map();
  await Promise.all(online.map(async (u) => {
    if (!u.email) return;
    const rec = await ensureUserLoaded(u.email);
    proByEmail.set(u.email, !!rec?.isPro);
  }));

  for (const [socketId, viewer] of ws.sockets.entries()) {
    const viewerEmail = viewer.email;
    const viewerEmailNorm = (viewerEmail || "").toLowerCase().trim();
    const viewerNameNorm = (viewer.name || "").trim();
    const isPro = viewerEmailNorm ? (proByEmail.get(viewerEmailNorm) || false) : false;

    const isViewerSelf = (u) => {
      const ue = (u.email || "").toLowerCase().trim();
      const un = (u.name || "").trim();
      if (viewerEmailNorm && ue && ue === viewerEmailNorm) return true;
      if (viewerNameNorm && un && viewerNameNorm === un) return true;
      return false;
    };

    const payload = isPro
      ? online.map(u => ({ ...u, locked: false }))
      : online.map((u, idx) => {
          if (isViewerSelf(u)) return { ...u, locked: false };
          return { name: obfuscateText(idx), email: null, role: u.role, locked: true };
        });

    io.to(socketId).emit("users_update", payload);
  }
}

function broadcastMembers(workspaceName) {
  const ws = workspaces[workspaceName];
  if (!ws) return;
  io.to(workspaceName).emit("members_update", getValidWorkspaceMembers(ws));
}

function formatHistoryAction(action, taskTitle = "", targetStatus = "") {
  const normalizedAction = normalizeText(action).toLowerCase();
  const safeTaskTitle = normalizeText(taskTitle);
  const safeTargetStatus = normalizeText(targetStatus);

  if (normalizedAction === "create_task" || normalizedAction === "added task" || normalizedAction === "task_created") {
    return safeTaskTitle ? `created task '${safeTaskTitle}'` : "created a task";
  }

  if (normalizedAction === "move_task" || normalizedAction === "moved task" || normalizedAction === "task_moved") {
    if (safeTaskTitle && safeTargetStatus) return `moved task '${safeTaskTitle}' to ${safeTargetStatus}`;
    if (safeTaskTitle) return `moved task '${safeTaskTitle}'`;
    return "moved a task";
  }

  if (normalizedAction === "delete_task" || normalizedAction === "deleted task" || normalizedAction === "task_deleted") {
    return safeTaskTitle ? `deleted task '${safeTaskTitle}'` : "deleted a task";
  }

  return normalizeText(action) || "updated the workspace";
}

function formatHistoryEntry(entry = {}) {
  return {
    action: formatHistoryAction(entry.action, entry.taskTitle, entry.targetStatus),
    userName: entry.userName,
    userRole: entry.userRole,
    taskTitle: entry.taskTitle || null,
    timestamp: entry.timestamp || new Date().toISOString(),
  };
}

function pushHistory(ws, entry) {
  ws.history.unshift(formatHistoryEntry(entry));
}

io.on("connection", (socket) => {
  socket.on("auth_user", async ({ email, password, name } = {}) => {
    if (!email || !password) {
      return socket.emit("auth_error", "Email and password are required.");
    }
    if (!EMAIL_RE.test(String(email).trim())) {
      return socket.emit("auth_error", "Please enter a valid email address.");
    }
    const key = normalizeEmail(email);
    const authThrottle = allowSensitiveAttempt(scopeForEmail("auth_user", key));
    if (!authThrottle.allowed) {
      return socket.emit("auth_error", "Too many login attempts. Please wait a few minutes and try again.");
    }
    let existing = users[key];
    console.log(`[auth_user] attempt for "${key}" | mongoConnected=${mongoConnected} | in-memory=${!!existing}`);

    if (!existing) {
      const dbUser = await loadUserFromDB(email);
      console.log(`[auth_user] DB lookup for "${key}" → ${dbUser ? "found" : "NOT found"}`);
      if (dbUser) {
        users[key] = {
          name: dbUser.name,
          passwordHash: dbUser.passwordHash,
          taskCount: dbUser.taskCount || 0,
          resetAt: dbUser.resetAt,
          taskIds: dbUser.taskIds || [],
          isPro: dbUser.isPro || false,
          proPin: dbUser.proPin,
          proActivatedAt: dbUser.proActivatedAt || null,
          proExpiresAt: dbUser.proExpiresAt || null,
        };
        existing = users[key];
      }
    }

    if (existing) {
      const result = await verifyLogin(email, password);
      console.log(`[auth_user] verifyLogin for "${key}" → ok=${result.ok}${result.ok ? "" : ` reason=${result.reason}`}`);
      if (!result.ok) {
        if (result.reason === "wrong_password") {
          const failCount = registerLoginFailure(key);
          if (failCount >= LOGIN_MAX_FAILURES) {
            return socket.emit("auth_error", "Forgot your password? Sign in with Google instead to access your account.");
          }
          return socket.emit("auth_error", "Incorrect password for this email. Please try again.");
        }
        return socket.emit("auth_error", "Authentication failed.");
      }
      clearLoginFailures(key);
      existing = result.user;
      if (name && name.trim() && name.trim() !== existing.name) {
        existing.name = name.trim();
        await saveUserToDB(email);
      }
      if (existing.resetAt && new Date() > new Date(existing.resetAt)) {
        existing.taskCount = 0;
        existing.resetAt = null;
        existing.taskIds = [];
        await saveUserToDB(email);
      }
      const profile = await getHydratedUserProfile(email);
      const { count, resetAt } = getUserTaskData(email);
      return socket.emit("auth_success", {
        email: key,
        name: profile?.name || existing.name,
        isPro: profile?.isPro || false,
        taskCount: count,
        resetAt,
        proExpiresAt: profile?.proExpiresAt || null,
      });
    } else {
      if (!name || !name.trim()) {
        return socket.emit("auth_error", "Name is required for new accounts.");
      }
      const { user } = await registerUser(email, name.trim(), password);
      return socket.emit("auth_success", {
        email: key,
        name: user.name,
        isPro: false,
        taskCount: 0,
        resetAt: null,
        proExpiresAt: null,
      });
    }
  });

  socket.on("auth_google", async ({ credential, name } = {}) => {
    const tokenCheck = await verifyGoogleToken(credential);
    if (!tokenCheck.ok) {
      return socket.emit("auth_google_error", "Google sign-in could not be verified. Please try again.");
    }

    const key = normalizeEmail(tokenCheck.email);
    const authThrottle = allowSensitiveAttempt(scopeForEmail("auth_google", key));
    if (!authThrottle.allowed) {
      return socket.emit("auth_google_error", "Too many login attempts. Please wait a few minutes and try again.");
    }

    finalizeGoogleAuth(socket, {
      email: tokenCheck.email,
      name: String(name || tokenCheck.name || "").trim() || tokenCheck.name,
      picture: tokenCheck.picture || null,
      sub: tokenCheck.sub || null,
    }, "google");
  });

  socket.on("auth_google_redirect_token", ({ token } = {}) => {
    const verified = verifyGoogleRedirectPayload(token);
    if (!verified) {
      return socket.emit("auth_google_error", "Google sign-in could not be verified. Please try again.");
    }

    const authThrottle = allowSensitiveAttempt(scopeForEmail("auth_google", verified.email));
    if (!authThrottle.allowed) {
      return socket.emit("auth_google_error", "Too many login attempts. Please wait a few minutes and try again.");
    }

    finalizeGoogleAuth(socket, verified, "redirect");
  });

  socket.on("check_pro_status", ({ email } = {}) => {
    const key = normalizeEmail(email);
    getHydratedUserProfile(key).then((profile) => {
      socket.emit("pro_status", { isPro: !!profile?.isPro, proExpiresAt: profile?.proExpiresAt || null });
    }).catch(() => {
      socket.emit("pro_status", { isPro: false });
    });
  });

  socket.on("set_user_pro", async ({ email, proPin } = {}) => {
    const key = normalizeEmail(email);
    if (!key || !proPin) {
      return socket.emit("pro_activate_error", "Valid email and activation PIN are required.");
    }
    const proThrottle = allowSensitiveAttempt(scopeForEmail("set_user_pro", key));
    if (!proThrottle.allowed) {
      return socket.emit("pro_activate_error", "Too many activation attempts. Please wait a few minutes and try again.");
    }
    const pinOk = await verifyProPinWithWorker(proPin);
    if (!pinOk) {
      return socket.emit("pro_activate_error", "Invalid or expired activation PIN.");
    }
    const trimmedPin = String(proPin).trim();
    let lockedExpiresAt = null;
    if (mongoConnected) {
      try {
        const redemptions = mongoose.connection.db.collection("pro_pin_redemptions");
        const newExpiresAt = new Date(Date.now() + PRO_DURATION_MS).toISOString();
        const insertResult = await redemptions.updateOne(
          { pin: trimmedPin },
          { $setOnInsert: { pin: trimmedPin, email: key, redeemedAt: new Date().toISOString(), expiresAt: newExpiresAt } },
          { upsert: true }
        );
        if (insertResult.upsertedId) {
          lockedExpiresAt = newExpiresAt;
        } else {
          const existing = await redemptions.findOne({ pin: trimmedPin });
          if (!existing || existing.email !== key) {
            return socket.emit("pro_activate_error", "This PIN is registered to a different account.");
          }
          if (new Date(existing.expiresAt).getTime() <= Date.now()) {
            return socket.emit("pro_activate_error", "This PIN has expired after 30 days and can no longer be used.");
          }
          lockedExpiresAt = existing.expiresAt;
        }
      } catch {
        return socket.emit("pro_activate_error", "Could not verify PIN right now. Please try again.");
      }
    }
    if (!users[key]) {
      const dbUser = await loadUserFromDB(email);
      if (dbUser) {
        users[key] = {
          name: dbUser.name,
          passwordHash: dbUser.passwordHash,
          taskCount: dbUser.taskCount || 0,
          resetAt: dbUser.resetAt,
          taskIds: dbUser.taskIds || [],
          isPro: dbUser.isPro || false,
          proPin: dbUser.proPin,
          proActivatedAt: dbUser.proActivatedAt || null,
          proExpiresAt: dbUser.proExpiresAt || null,
        };
      }
    }
    if (!users[key]) {
      return socket.emit("pro_activate_error", "Account not found. Sign in first.");
    }
    await markUserPro(email, String(proPin).trim(), lockedExpiresAt);
    const { count, resetAt } = getUserTaskData(email);
    getHydratedUserProfile(email).then((profile) => {
      socket.emit("pro_activated", {
        taskCount: count,
        resetAt,
        isPro: !!profile?.isPro,
        proExpiresAt: profile?.proExpiresAt || null,
      });
    }).catch(() => {
      socket.emit("pro_activated", {
        taskCount: count,
        resetAt,
        isPro: true,
        proExpiresAt: users[key]?.proExpiresAt || null,
      });
    });
  });

  socket.on("deactivate_pro", async ({ email } = {}) => {
    const key = normalizeEmail(email);
    if (!key) {
      return socket.emit("pro_deactivate_error", "Valid email is required.");
    }
    const userRec = await ensureUserLoaded(email);
    if (!userRec) {
      return socket.emit("pro_deactivate_error", "Account not found. Sign in first.");
    }
    try {
      await deactivateUserPro(email);
      socket.emit("pro_deactivated");
    } catch (err) {
      socket.emit("pro_deactivate_error", "Failed to deactivate Pro.");
    }
  });

  socket.on("join_workspace", withSocketGuard(socket, "join_workspace", async (data = {}) => {
    const workspaceName = normalizeText(data.workspaceName);
    const password = normalizeText(data.password);
    const projectName = normalizeText(data.projectName);
    const explicitName = normalizeText(data.name || data.userName);
    const isCreating = !!data.isCreating;
    const rawEmail = data.userEmail ?? data.email ?? data?.user?.email ?? "";
    const email = normalizeEmail(rawEmail);
    const userName = explicitName || (email.includes("@") ? email.split("@")[0] : normalizeText(data.userName));
    
    const lockoutScope = email || workspaceName;
    const lockoutState = getJoinLockoutState(lockoutScope);
    if (lockoutState.locked) {
      return socket.emit("join_locked_out", { unlockAt: lockoutState.unlockAt });
    }

    const joinThrottle = allowSensitiveAttempt(scopeForEmail("join_workspace", email || workspaceName));
    if (!joinThrottle.allowed) {
      return socket.emit("error_msg", "Too many workspace attempts. Please wait a few minutes and try again.");
    }
    
    if (!workspaceName || !password || !userName || !email) {
      return socket.emit("error_msg", "Missing required fields.");
    }
    if (isCreating && password.length < 8) {
      return socket.emit("error_msg", "Password must be at least 8 characters.");
    }

    let existingWs = workspaces[workspaceName];

    if (!existingWs && !isCreating) {
      const loadedWs = await loadRoomFromDB(workspaceName);
      if (loadedWs) {
        workspaces[workspaceName] = loadedWs;
        existingWs = loadedWs;
      }
    }

    if (!isCreating) {
      if (!existingWs) {
        const unlockAt = registerJoinFailure(lockoutScope);
        if (unlockAt) return socket.emit("join_locked_out", { unlockAt });
        return socket.emit("error_msg", `Workspace not found: "${workspaceName}" does not exist. Ask your admin for the correct workspace name, or create a new workspace.`);
      }
      if (!(await verifyWorkspacePin(password, existingWs.password))) {
        const unlockAt = registerJoinFailure(lockoutScope);
        if (unlockAt) return socket.emit("join_locked_out", { unlockAt });
        return socket.emit("error_msg", `Wrong password for workspace "${workspaceName}". Ask your workspace admin for the correct password.`);
      }
      await upgradeWorkspacePinIfNeeded(existingWs, workspaceName, password);
    }

    if (isCreating) {
      if (existingWs) {
        if (!(await verifyWorkspacePin(password, existingWs.password))) {
          return socket.emit("error_msg", `Workspace "${workspaceName}" already exists with a different password. Choose a different name or use the correct password.`);
        }
        await upgradeWorkspacePinIfNeeded(existingWs, workspaceName, password);
      } else {
        workspaces[workspaceName] = {
          password: await hashSecret(password),
          projectName: projectName || workspaceName,
          creatorEmail: email,
          isPro: false,
          proExpiresAt: null,
          tasks: [],
          history: [],
          members: [],
          sockets: new Map(),
        };
        await saveRoomToDB(workspaceName);
      }
    }

    const ws = workspaces[workspaceName];
    if (!ws) {
      return socket.emit("error_msg", "Workspace could not be initialized.");
    }
    const normalizedUserEmail = email;
    const storedCreatorEmail = normalizeEmail(ws.creatorEmail);

    let role = "member";
    if (isCreating) {
      role = "admin";
    } else if (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) {
      role = "admin";
    }

    const joinedProfile = await getHydratedUserProfile(email);
    const { isPro: joinedUserIsPro, proExpiresAt: joinedUserProExpiresAt } = resolveActiveProState(joinedProfile ? { ...joinedProfile } : null);
   

    ws.sockets.set(socket.id, { name: userName, displayName: userName, role, email });
    clearJoinFailures(lockoutScope);
    socket.join(workspaceName);

    try {
      const leaveKey = `${workspaceName}|${(email||"").toLowerCase()}`;
      const pending = pendingLeaveTimers.get(leaveKey);
      if (pending) { clearTimeout(pending); pendingLeaveTimers.delete(leaveKey); }
    } catch (err) {}

    const memberKey = email;
    const existingMemberIndex = ws.members.findIndex(m => normalizeEmail(m?.email) === memberKey);
    
    if (existingMemberIndex !== -1) {
      const existingMember = ws.members[existingMemberIndex];
      if (existingMember.name !== userName) {
        existingMember.name = userName;
      }
      if (role === "admin") {
        existingMember.role = "admin";
      }
    } else {
      ws.members.push({ name: userName, displayName: userName, role, email: memberKey, joinedAt: new Date().toISOString() });
    }

    await saveRoomToDB(workspaceName);

        const resolvedIsPro = !!joinedUserIsPro;
    const resolvedProExpiresAt = joinedUserProExpiresAt || null;
    const { count, resetAt } = getUserTaskData(email);

    socket.emit("load_workspace", {
      tasks: ws.tasks,
      projectName: ws.projectName,
      role,
      history: ws.history,
      members: ws.members,
      taskCount: count,
      resetAt,
      isPro: resolvedIsPro,
      proExpiresAt: resolvedProExpiresAt,
    });

    broadcastUsers(workspaceName);
    broadcastMembers(workspaceName);
  }));

  socket.on("rejoin_workspace", withSocketGuard(socket, "rejoin_workspace", async (data = {}) => {
    const workspaceName = normalizeText(data.workspaceName);
    const explicitName = normalizeText(data.name || data.userName);
    const rawEmail = data.userEmail ?? data.email ?? data?.user?.email ?? "";
    const email = normalizeEmail(rawEmail);
    const userName = explicitName || (email.includes("@") ? email.split("@")[0] : normalizeText(data.userName));
    const rejoinThrottle = allowSensitiveAttempt(scopeForEmail("rejoin_workspace", email || workspaceName));
    if (!rejoinThrottle.allowed) {
      return socket.emit("error_msg", "Too many reconnect attempts. Please wait a few minutes and try again.");
    }
    
    if (!workspaceName || !userName || !email) {
      return socket.emit("error_msg", "Missing required fields for rejoin.");
    }

    let ws = workspaces[workspaceName];
    if (!ws) {
      const loadedWs = await loadRoomFromDB(workspaceName);
      if (loadedWs) {
        workspaces[workspaceName] = loadedWs;
        ws = loadedWs;
      }
    }
    
    if (!ws) {
      return socket.emit("error_msg", `Workspace "${workspaceName}" not found.`);
    }

    const normalizedUserEmail = email;
    const storedCreatorEmail = normalizeEmail(ws.creatorEmail);
    
    let role = "member";
    if (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) {
      role = "admin";
    }

    ws.sockets.set(socket.id, { name: userName, displayName: userName, role, email });
    socket.join(workspaceName);

    try {
      const leaveKey = `${workspaceName}|${(email||"").toLowerCase()}`;
      const pending = pendingLeaveTimers.get(leaveKey);
      if (pending) { clearTimeout(pending); pendingLeaveTimers.delete(leaveKey); }
    } catch (err) {}

    const memberKey = email;
    const existingMember = ws.members.find(m => normalizeEmail(m?.email) === memberKey);
    if (existingMember && existingMember.name !== userName) {
      existingMember.name = userName;
      existingMember.displayName = userName;
      await saveRoomToDB(workspaceName);
    }

    const joinedProfile = await getHydratedUserProfile(email);
    const { isPro: joinedUserIsPro, proExpiresAt: joinedUserProExpiresAt } = resolveActiveProState(joinedProfile ? { ...joinedProfile } : null);
   
    await saveRoomToDB(workspaceName);

    const resolvedIsPro = !!joinedUserIsPro;
    const resolvedProExpiresAt = joinedUserProExpiresAt || null;
    const { count, resetAt } = getUserTaskData(email);

    socket.emit("load_workspace", {
      tasks: ws.tasks,
      projectName: ws.projectName,
      role,
      history: ws.history,
      members: ws.members,
      taskCount: count,
      resetAt,
      isPro: resolvedIsPro,
      proExpiresAt: resolvedProExpiresAt,
    });

    broadcastUsers(workspaceName);
    broadcastMembers(workspaceName);
  }));

  socket.on("update_tasks", withSocketGuard(socket, "update_tasks", async ({ workspaceName, updatedTasks, actionMeta, newTaskId } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName);
    const ws = workspaces[safeWorkspaceName];
    if (!ws) return;

    const user = ws.sockets.get(socket.id);
    if (!user) return;
    if (user.role !== "member" && user.role !== "admin") {
      return socket.emit("permission_denied", "Viewers cannot modify tasks.");
    }

    const isNewTask = !!(newTaskId && user.email);
    if (isNewTask) {
      const userRec = await ensureUserLoaded(user.email);
      if (!userRec) {
        socket.emit("error_msg", "User record not found. Please log in again.");
        return;
      }
      const { count, resetAt } = getUserTaskData(user.email);
      const limit = userRec.isPro ? PRO_TASK_LIMIT : FREE_TASK_LIMIT;
      if (count >= limit) {
        socket.emit("task_count_update", { taskCount: count, resetAt });
        socket.emit("task_limit_reached", { taskCount: count, resetAt, limit, isPro: userRec.isPro });
        socket.emit("receive_update", { tasks: ws.tasks, history: ws.history });
        return;
      }
    }

    ws.tasks = updatedTasks || [];
    if (isNewTask) {
      const newCount = await incrementUserTaskCountAsync(user.email, newTaskId);
      const { resetAt } = getUserTaskData(user.email);
      socket.emit("task_count_update", { taskCount: newCount, resetAt });
    }

    if (actionMeta) {
      pushHistory(ws, {
        action: actionMeta.action,
        taskTitle: actionMeta.taskTitle || null,
        targetStatus: actionMeta.targetStatus || actionMeta.status || null,
        userName: user.name,
        userRole: user.role,
        timestamp: new Date().toISOString(),
      });
    }

    await saveRoomToDB(safeWorkspaceName);

    socket.to(safeWorkspaceName).emit("receive_update", {
      tasks: ws.tasks,
      history: ws.history,
    });

    socket.to(safeWorkspaceName).emit("history_update", ws.history);
  }));

  socket.on("check_task_limit", async ({ email } = {}) => {
    if (!email) return;
    const key = normalizeEmail(email);
    let ws_user = users[key];
    if (!ws_user) {
      const dbUser = await loadUserFromDB(email);
      if (dbUser) {
        users[key] = {
          name: dbUser.name,
          passwordHash: dbUser.passwordHash,
          taskCount: dbUser.taskCount || 0,
          resetAt: dbUser.resetAt,
          taskIds: dbUser.taskIds || [],
          isPro: dbUser.isPro || false,
          proPin: dbUser.proPin,
        };
        ws_user = users[key];
      }
    }
    
    const { count, resetAt } = getUserTaskData(email);
    const limit = ws_user?.isPro ? PRO_TASK_LIMIT : FREE_TASK_LIMIT;
    socket.emit("task_limit_status", {
      taskCount: count,
      resetAt,
      limit,
      isPro: ws_user?.isPro || false,
      canAdd: count < limit,
    });
  });

  socket.on("typing_start", ({ workspaceName, context } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName);
    const ws = workspaces[safeWorkspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user) return;
    socket.to(safeWorkspaceName).emit("typing_update", { name: user.name, role: user.role, context });
  });

  socket.on("typing_stop", ({ workspaceName } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName);
    const ws = workspaces[safeWorkspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user) return;
    socket.to(safeWorkspaceName).emit("typing_clear", { name: user.name });
  });

  socket.on("disconnecting", () => {
    for (const room of socket.rooms) {
      if (room === socket.id) continue;
      const ws = workspaces[room];
      if (!ws) continue;
      const user = ws.sockets.get(socket.id);
      if (!user) continue;

     
    ws.sockets.delete(socket.id);

      try {
        const leaveKey = `${room}|${(user.email||"").toLowerCase()}`;
        const existing = pendingLeaveTimers.get(leaveKey);
        if (existing) clearTimeout(existing);
        
        socket.to(room).emit("typing_clear", { name: user.name });
        
        const stillOnline = Array.from(ws.sockets.values()).some(
          (u) => (u.email || "").toLowerCase() === (user.email || "").toLowerCase()
        );
        
        if (!stillOnline) {
          saveRoomToDB(room);
        }
        
        broadcastUsers(room);
      } catch (err) {
        console.error("[disconnecting] Error handling disconnect:", err);
      }
    }
  });     

  socket.on("check_workspace_handle", withSocketGuard(socket, "check_workspace_handle", async ({ workspaceName } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName).toLowerCase();
    if (!safeWorkspaceName) {
      return socket.emit("workspace_handle_status", { workspaceName: safeWorkspaceName, taken: false });
    }
    let taken = !!workspaces[safeWorkspaceName];
    if (!taken && mongoConnected) {
      try {
        const collection = mongoose.connection.db.collection("workspaces");
        const doc = await collection.findOne({ workspaceName: safeWorkspaceName }, { projection: { _id: 1 } });
        taken = !!doc;
      } catch {}
    }
    socket.emit("workspace_handle_status", { workspaceName: safeWorkspaceName, taken });
  }));

  socket.on("delete_workspace", async ({ workspaceName, email } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName);
    const safeEmail = normalizeEmail(email);
    const deleteThrottle = allowSensitiveAttempt(scopeForEmail("delete_workspace", safeEmail || safeWorkspaceName));
    if (!deleteThrottle.allowed) {
      return socket.emit("error_msg", "Too many delete attempts. Please wait a few minutes and try again.");
    }
    
    const ws = workspaces[safeWorkspaceName];
    if (!ws) {
      return socket.emit("error_msg", "Workspace not found.");
    }

    const user = ws.sockets.get(socket.id);
    if (!user || user.role !== "admin") {
      return socket.emit("error_msg", "Only admins can delete workspaces.");
    }

    delete workspaces[safeWorkspaceName];
    if (mongoConnected) {
      try {
        const collection = mongoose.connection.db.collection("workspaces");
        await collection.deleteOne({ workspaceName: safeWorkspaceName });
      } catch (err) {}
    }

    io.to(safeWorkspaceName).emit("error_msg", `This workspace is being deleted by an admin. You will be disconnected.`);
    socket.leave(safeWorkspaceName);
    socket.emit("workspace_deleted_success");
  });

  socket.on("clear_history", async ({ workspaceName } = {}) => {
    const safeWorkspaceName = normalizeText(workspaceName);
    const clearThrottle = allowSensitiveAttempt(scopeForEmail("clear_history", safeWorkspaceName));
    if (!clearThrottle.allowed) {
      return socket.emit("permission_denied", "Too many history actions. Please wait a few minutes and try again.");
    }
    const ws = workspaces[safeWorkspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user || user.role !== "admin") {
      return socket.emit("permission_denied", "Only admins can clear history.");
    }
    ws.history = [];
    await saveRoomToDB(safeWorkspaceName);
    socket.to(safeWorkspaceName).emit("history_update", ws.history);
    socket.emit("history_update", ws.history);
    socket.emit("history_cleared");
  });
});

const PORT = process.env.PORT || 3001;

async function startServer() {   
  await connectDB();
  server.listen(PORT, () => {
    console.log(`[Server] ✓ SyncBoard listening on :${PORT}`);
  });
}

startServer().catch(err => {
  console.error("[startServer] Fatal error:", err.message);
  process.exit(1);
});

app.use((err, req, res, next) => {
  const origin = req?.headers?.origin;
  if (!origin || isOriginAllowed(origin, ALLOWED_ORIGINS)) {
    applyCorsHeaders(res, origin);
  }
  if (res.headersSent) {
    return next(err);
  }
  return res.status(err?.status || 500).json({ error: err?.message || "Internal server error" });
});