import express  from "express";
import http     from "http";
import { Server } from "socket.io";
import cors     from "cors";
import dotenv   from "dotenv";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import helmet   from "helmet";
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
  signToken,
  verifyToken,
} from "./security.mjs";
import { buildBoardContextWithRefs } from "./boardContext.mjs";
import { askGemini } from "./gemini.mjs";
import { transcribeAudio, normalizeAudioMime } from "./gemini.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, ".env") });

const IS_DEV = process.env.NODE_ENV !== "production";
const ALLOWED_ORIGINS = parseAllowedOrigins();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_REDIRECT_TOKEN_SECRET = process.env.GOOGLE_REDIRECT_TOKEN_SECRET || createHmac("sha256", `${Date.now()}`).update(`${Math.random()}`).digest("hex");
if (!process.env.GOOGLE_REDIRECT_TOKEN_SECRET) {
  console.warn("[GOOGLE_REDIRECT_TOKEN_SECRET] Not set — using a random per-process secret. Google OAuth redirect tokens will be invalidated on every restart until GOOGLE_REDIRECT_TOKEN_SECRET is set.");
}
const SESSION_SECRET = process.env.SESSION_SECRET || createHmac("sha256", `${Date.now()}`).update(`${Math.random()}`).digest("hex");
if (!process.env.SESSION_SECRET) {
  console.warn("[SESSION_SECRET] Not set — using a random per-process secret. Sessions will be invalidated on every restart until SESSION_SECRET is set.");
}
const SESSION_COOKIE_NAME = "sb_session";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_TICKET_TTL_MS = 30 * 1000; // one-time exchange ticket, 30s
const PRIMARY_CLIENT_URL = ALLOWED_ORIGINS[0] || "http://localhost:5173";
const devLog = (...args) => { if (IS_DEV) console.log(...args); };

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception thrown:", err);
});

const app = express();
app.use(helmet());
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
  const contactThrottle = await allowSensitiveAttempt(scopeForIp("contact", contactIp));
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
  const email = getVerifiedSessionEmail(req.headers.cookie || "");
  if (!email) {
    return res.status(401).json({ error: "Not authenticated." });
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
 

app.post("/api/session/exchange", async (req, res) => {
  const ticket = String(req.body?.ticket || "").trim();
  if (!ticket) {
    return res.status(400).json({ error: "Missing ticket." });
  }
  const payload = verifyToken(ticket, SESSION_SECRET);
  if (!payload?.email) {
    return res.status(401).json({ error: "Invalid or expired ticket." });
  }
  setSessionCookie(res, payload.email);
  return res.json({ ok: true });
});

app.post("/api/session/logout", async (req, res) => {
  clearSessionCookie(res);
  return res.json({ ok: true });
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
    try {
      await mongoose.connection.db.collection("rate_limits").createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0 }
      );
    } catch (idxErr) {
      console.error("[connectDB] Failed to create rate_limits TTL index:", idxErr.message);
    }
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
          mentions: Array.isArray(ws.mentions) ? ws.mentions : [],
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
        mentions: Array.isArray(doc.mentions) ? doc.mentions : [],
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
const sensitiveAttemptBucketsMemory = new Map(); // fallback only, used when Mongo is unavailable

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOGIN_MAX_FAILURES = 3;
const LOGIN_FAILURE_TTL_MS = 24 * 60 * 60 * 1000;
const loginFailureTrackerMemory = new Map(); // fallback only

const JOIN_LOCKOUT_MS = 30 * 60 * 1000;
const JOIN_MAX_FAILURES = 3;
const JOIN_FAILURE_TTL_MS = JOIN_LOCKOUT_MS;
const joinFailureTrackerMemory = new Map(); // fallback only

const RATE_LIMIT_COLLECTION = "rate_limits";
function rateLimitCollection() {
  return mongoConnected ? mongoose.connection.db.collection(RATE_LIMIT_COLLECTION) : null;
}

async function registerLoginFailure(key) {
  const col = rateLimitCollection();
  if (!col) {
    const rec = loginFailureTrackerMemory.get(key) || { count: 0 };
    rec.count += 1;
    loginFailureTrackerMemory.set(key, rec);
    return rec.count;
  }
  try {
    const id = `login:${key}`;
    const result = await col.findOneAndUpdate(
      { _id: id },
      { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date(Date.now() + LOGIN_FAILURE_TTL_MS) } },
      { upsert: true, returnDocument: "after", includeResultMetadata: true }
    );
    return result.value.count;
  } catch (err) {
    console.error("[registerLoginFailure] Mongo error, falling back to memory:", err.message);
    const rec = loginFailureTrackerMemory.get(key) || { count: 0 };
    rec.count += 1;
    loginFailureTrackerMemory.set(key, rec);
    return rec.count;
  }
}

async function clearLoginFailures(key) {
  loginFailureTrackerMemory.delete(key);
  const col = rateLimitCollection();
  if (!col) return;
  try {
    await col.deleteOne({ _id: `login:${key}` });
  } catch (err) {
    console.error("[clearLoginFailures] Mongo error:", err.message);
  }
}

async function getJoinLockoutState(scope) {
  const col = rateLimitCollection();
  if (!col) {
    const rec = joinFailureTrackerMemory.get(scope);
    if (!rec) return { locked: false, unlockAt: 0 };
    if (rec.lockedUntil && rec.lockedUntil > Date.now()) return { locked: true, unlockAt: rec.lockedUntil };
    if (rec.lockedUntil && rec.lockedUntil <= Date.now()) joinFailureTrackerMemory.delete(scope);
    return { locked: false, unlockAt: 0 };
  }
  try {
    const doc = await col.findOne({ _id: `join:${scope}` });
    if (!doc || !doc.lockedUntil) return { locked: false, unlockAt: 0 };
    if (doc.lockedUntil > Date.now()) return { locked: true, unlockAt: doc.lockedUntil };
    return { locked: false, unlockAt: 0 };
  } catch (err) {
    console.error("[getJoinLockoutState] Mongo error:", err.message);
    return { locked: false, unlockAt: 0 };
  }
}

async function registerJoinFailure(scope) {
  const col = rateLimitCollection();
  if (!col) {
    const rec = joinFailureTrackerMemory.get(scope) || { count: 0, lockedUntil: null };
    rec.count += 1;
    if (rec.count >= JOIN_MAX_FAILURES) {
      rec.lockedUntil = Date.now() + JOIN_LOCKOUT_MS;
      rec.count = 0;
    }
    joinFailureTrackerMemory.set(scope, rec);
    const isLocked = rec.lockedUntil && rec.lockedUntil > Date.now();
    return {
      unlockAt: isLocked ? rec.lockedUntil : 0,
      attemptsRemaining: isLocked ? 0 : Math.max(0, JOIN_MAX_FAILURES - rec.count),
    };
  }
  try {
    const id = `join:${scope}`;
    const updated = await col.findOneAndUpdate(
      { _id: id },
      { $inc: { count: 1 }, $setOnInsert: { lockedUntil: null }, $set: { expiresAt: new Date(Date.now() + JOIN_FAILURE_TTL_MS) } },
      { upsert: true, returnDocument: "after", includeResultMetadata: true }
    );
    const rec = updated.value;
    if (rec.count >= JOIN_MAX_FAILURES && !rec.lockedUntil) {
      const lockedUntil = Date.now() + JOIN_LOCKOUT_MS;
      await col.updateOne({ _id: id }, { $set: { lockedUntil, count: 0, expiresAt: new Date(lockedUntil) } });
      return { unlockAt: lockedUntil, attemptsRemaining: 0 };
    }
    const isLocked = rec.lockedUntil && rec.lockedUntil > Date.now();
    return {
      unlockAt: isLocked ? rec.lockedUntil : 0,
      attemptsRemaining: isLocked ? 0 : Math.max(0, JOIN_MAX_FAILURES - rec.count),
    };
  } catch (err) {
    console.error("[registerJoinFailure] Mongo error, falling back to memory:", err.message);
    const rec = joinFailureTrackerMemory.get(scope) || { count: 0, lockedUntil: null };
    rec.count += 1;
    if (rec.count >= JOIN_MAX_FAILURES) {
      rec.lockedUntil = Date.now() + JOIN_LOCKOUT_MS;
      rec.count = 0;
    }
    joinFailureTrackerMemory.set(scope, rec);
    const isLocked = rec.lockedUntil && rec.lockedUntil > Date.now();
    return {
      unlockAt: isLocked ? rec.lockedUntil : 0,
      attemptsRemaining: isLocked ? 0 : Math.max(0, JOIN_MAX_FAILURES - rec.count),
    };
  }
}

async function clearJoinFailures(scope) {
  joinFailureTrackerMemory.delete(scope);
  const col = rateLimitCollection();
  if (!col) return;
  try {
    await col.deleteOne({ _id: `join:${scope}` });
  } catch (err) {
    console.error("[clearJoinFailures] Mongo error:", err.message);
  }
}

async function allowSensitiveAttempt(scope) {
  const now = Date.now();
  const col = rateLimitCollection();
  if (!col) {
    const existing = sensitiveAttemptBucketsMemory.get(scope);
    let bucket = existing;
    if (!existing || existing.expiresAt <= now) {
      bucket = { count: 0, expiresAt: now + ATTEMPT_WINDOW_MS };
      sensitiveAttemptBucketsMemory.set(scope, bucket);
    }
    if (bucket.count >= MAX_ATTEMPTS_PER_WINDOW) {
      return { allowed: false, retryAfterMs: Math.max(0, bucket.expiresAt - now) };
    }
    bucket.count += 1;
    return { allowed: true, retryAfterMs: 0 };
  }
  try {
    const doc = await col.findOne({ _id: scope });
    if (!doc || doc.expiresAt.getTime() <= now) {
      await col.updateOne(
        { _id: scope },
        { $set: { count: 1, expiresAt: new Date(now + ATTEMPT_WINDOW_MS) } },
        { upsert: true }
      );
      return { allowed: true, retryAfterMs: 0 };
    }
    if (doc.count >= MAX_ATTEMPTS_PER_WINDOW) {
      return { allowed: false, retryAfterMs: Math.max(0, doc.expiresAt.getTime() - now) };
    }
    await col.updateOne({ _id: scope }, { $inc: { count: 1 } });
    return { allowed: true, retryAfterMs: 0 };
  } catch (err) {
    console.error("[allowSensitiveAttempt] Mongo error, falling back to memory:", err.message);
    const existing = sensitiveAttemptBucketsMemory.get(scope);
    let bucket = existing;
    if (!existing || existing.expiresAt <= now) {
      bucket = { count: 0, expiresAt: now + ATTEMPT_WINDOW_MS };
      sensitiveAttemptBucketsMemory.set(scope, bucket);
    }
    if (bucket.count >= MAX_ATTEMPTS_PER_WINDOW) {
      return { allowed: false, retryAfterMs: Math.max(0, bucket.expiresAt - now) };
    }
    bucket.count += 1;
    return { allowed: true, retryAfterMs: 0 };
  }
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

function parseCookieHeader(header) {
  const out = {};
  String(header || "").split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  });
  return out;
}

function getVerifiedSessionEmail(cookieHeader) {
  const cookies = parseCookieHeader(cookieHeader);
  const raw = cookies[SESSION_COOKIE_NAME];
  if (!raw) return null;
  const payload = verifyToken(raw, SESSION_SECRET);
  if (!payload?.email) return null;
  return normalizeEmail(payload.email);
}

function issueSessionTicket(email) {
  return signToken({ email: normalizeEmail(email), exp: Date.now() + SESSION_TICKET_TTL_MS }, SESSION_SECRET);
}

function setSessionCookie(res, email) {
  const token = signToken({ email: normalizeEmail(email), exp: Date.now() + SESSION_TTL_MS }, SESSION_SECRET);
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`);
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
  socket.data.verifiedEmail = key;

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
        sessionTicket: issueSessionTicket(key),
      });
    }).catch(() => {
      socket.emit("auth_success", {
        email: key,
        name: userRecord.name,
        isPro: userRecord.isPro,
        taskCount: count,
        resetAt,
        proExpiresAt: userRecord.proExpiresAt || null,
        sessionTicket: issueSessionTicket(key),
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
      sessionTicket: issueSessionTicket(key),
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
    const authThrottle = await allowSensitiveAttempt(scopeForEmail("auth_user", key));
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
          const failCount = await registerLoginFailure(key);
          if (failCount >= LOGIN_MAX_FAILURES) {
            return socket.emit("auth_error", "Forgot your password? Sign in with Google instead to access your account.");
          }
          return socket.emit("auth_error", "Incorrect password for this email. Please try again.");
        }
        return socket.emit("auth_error", "Authentication failed.");
      }
      await clearLoginFailures(key);
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
      socket.data.verifiedEmail = key;
      return socket.emit("auth_success", {
        email: key,
        name: profile?.name || existing.name,
        isPro: profile?.isPro || false,
        taskCount: count,
        resetAt,
        proExpiresAt: profile?.proExpiresAt || null,
        sessionTicket: issueSessionTicket(key),
      });
    } else {
      if (!name || !name.trim()) {
        return socket.emit("auth_error", "Name is required for new accounts.");
      }
      const { user } = await registerUser(email, name.trim(), password);
      socket.data.verifiedEmail = key;
      return socket.emit("auth_success", {
        email: key,
        name: user.name,
        isPro: false,
        taskCount: 0,
        resetAt: null,
        proExpiresAt: null,
        sessionTicket: issueSessionTicket(key),
      });
    }
  });



  socket.on("auth_google", async ({ credential, name } = {}) => {
    const tokenCheck = await verifyGoogleToken(credential);
    if (!tokenCheck.ok) {
      return socket.emit("auth_google_error", "Google sign-in could not be verified. Please try again.");
    }

    const key = normalizeEmail(tokenCheck.email);
    const authThrottle = await allowSensitiveAttempt(scopeForEmail("auth_google", key));
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

  socket.on("auth_google_redirect_token", async ({ token } = {}) => {
    const verified = verifyGoogleRedirectPayload(token);
    if (!verified) {
      return socket.emit("auth_google_error", "Google sign-in could not be verified. Please try again.");
    }

    const authThrottle = await allowSensitiveAttempt(scopeForEmail("auth_google", verified.email));
    if (!authThrottle.allowed) {
      return socket.emit("auth_google_error", "Too many login attempts. Please wait a few minutes and try again.");
    }

    finalizeGoogleAuth(socket, verified, "redirect");
  });

;

  socket.on("set_user_pro", async ({ email, proPin } = {}) => {
    const key = normalizeEmail(email);
    if (!key || !proPin) {
      return socket.emit("pro_activate_error", "Valid email and activation PIN are required.");
    }
    const proThrottle = await allowSensitiveAttempt(scopeForEmail("set_user_pro", key));
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

  socket.on("deactivate_pro", async () => {
    // Identity comes ONLY from the signed session cookie. Anything the client sends is ignored.
    const key = getVerifiedSessionEmail(socket.handshake?.headers?.cookie || "") || normalizeEmail(socket.data?.verifiedEmail || "");
    if (!key) {
      return socket.emit("session_expired", { reason: "no_session" });
    }
    const throttle = await allowSensitiveAttempt(scopeForEmail("deactivate_pro", key));
    if (!throttle.allowed) {
      return socket.emit("pro_deactivate_error", "Too many attempts. Please wait a few minutes and try again.");
    }
    const userRec = await ensureUserLoaded(key);
    if (!userRec) {
      return socket.emit("pro_deactivate_error", "Account not found. Sign in first.");
    }
    try {
      await deactivateUserPro(key);
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
    const lockoutState = await getJoinLockoutState(lockoutScope);
    if (lockoutState.locked) {
      return socket.emit("join_locked_out", { unlockAt: lockoutState.unlockAt });
    }

    const joinThrottle = await allowSensitiveAttempt(scopeForEmail("join_workspace", email || workspaceName));
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
        const { unlockAt, attemptsRemaining } = await registerJoinFailure(lockoutScope);
        if (unlockAt) return socket.emit("join_locked_out", { unlockAt });
        socket.emit("join_wrong_password", { attemptsRemaining });
        return socket.emit("error_msg", `Workspace not found: "${workspaceName}" does not exist. Ask your admin for the correct workspace name, or create a new workspace.`);
      }
      if (!(await verifyWorkspacePin(password, existingWs.password))) {
        const { unlockAt, attemptsRemaining } = await registerJoinFailure(lockoutScope);
        if (unlockAt) return socket.emit("join_locked_out", { unlockAt });
        socket.emit("join_wrong_password", { attemptsRemaining });
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
          mentions: [],
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

    const prevWorkspace = socket.data.currentWorkspace;
    if (prevWorkspace && prevWorkspace !== workspaceName) {
      const prevWs = workspaces[prevWorkspace];
      if (prevWs) {
        prevWs.sockets.delete(socket.id);
        socket.leave(prevWorkspace);
        broadcastUsers(prevWorkspace);
      }
    }
    socket.data.currentWorkspace = workspaceName;

    ws.sockets.set(socket.id, { name: userName, displayName: userName, role, email });
    await clearJoinFailures(lockoutScope);
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

    socket.emit("session_ticket", { ticket: issueSessionTicket(email) });

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
    const claimedEmail = normalizeEmail(data.userEmail ?? data.email ?? data?.user?.email ?? "");

    const verifiedEmail = getVerifiedSessionEmail(socket.handshake?.headers?.cookie || "");
    if (!verifiedEmail) {
      return socket.emit("session_expired", { reason: "no_session" });
    }
    if (claimedEmail && claimedEmail !== verifiedEmail) {
      console.warn(`[rejoin_workspace] claimed email "${claimedEmail}" did not match session cookie "${verifiedEmail}" — using verified session.`);
    }

    const email = verifiedEmail;
    const userName = explicitName || (email.includes("@") ? email.split("@")[0] : normalizeText(data.userName));
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
    
    const normalizedUserEmail = email;
    const storedCreatorEmail = normalizeEmail(ws?.creatorEmail);
    const isKnownMember = !!ws && (
      (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) ||
      (Array.isArray(ws.members) && ws.members.some(m => normalizeEmail(m?.email) === normalizedUserEmail))
    );

    if (!ws || !isKnownMember) {
      const failThrottle = await allowSensitiveAttempt(scopeForEmail("rejoin_workspace", email));
      if (!failThrottle.allowed) {
        return socket.emit("error_msg", "Too many reconnect attempts. Please wait a few minutes and try again.");
      }
      return socket.emit("error_msg", `Workspace "${workspaceName}" not found.`);
    }
    
    let role = "member";
    if (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) {
      role = "admin";
    }

    const prevWorkspace = socket.data.currentWorkspace;
    if (prevWorkspace && prevWorkspace !== workspaceName) {
      const prevWs = workspaces[prevWorkspace];
      if (prevWs) {
        prevWs.sockets.delete(socket.id);
        socket.leave(prevWorkspace);
        broadcastUsers(prevWorkspace);
      }
    }
    socket.data.currentWorkspace = workspaceName;

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

    const MAX_TASKS_PER_BOARD = 500;
    const MAX_TASK_TITLE_LEN = 200;
    const MAX_TASK_DESC_LEN = 5000;
    const MAX_TASK_IMAGE_CHARS = Number(process.env.MAX_TASK_IMAGE_CHARS) || 2_000_000;
    const MAX_BOARD_IMAGE_CHARS = Number(process.env.MAX_BOARD_IMAGE_CHARS) || 8_000_000;
    const IMAGE_DATA_URL_RE = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

    const existingImages = new Map();
    for (const t of Array.isArray(ws.tasks) ? ws.tasks : []) {
      if (t && typeof t.id === "string" && typeof t.image === "string" && t.image) {
        existingImages.set(t.id, t.image);
      }
    }
    let keptImageChars = 0;
    const newImageCandidates = [];
    const rejectedImages = { notPro: 0, badFormat: 0, tooLarge: 0, boardFull: 0 };

    let truncatedTitleCount = 0;
    let truncatedDescCount = 0;
    let droppedInvalidCount = 0;

    const sanitizeTask = (task) => {
      if (!task || typeof task !== "object" || Array.isArray(task)) {
        droppedInvalidCount++;
        return null;
      }

      let title = task.title;
      if (typeof title !== "string") {
        title = "";
      } else if (title.length > MAX_TASK_TITLE_LEN) {
        title = title.slice(0, MAX_TASK_TITLE_LEN);
        truncatedTitleCount++;
      }

      let description = task.description;
      if (typeof description !== "string") {
        description = "";
      } else if (description.length > MAX_TASK_DESC_LEN) {
        description = description.slice(0, MAX_TASK_DESC_LEN);
        truncatedDescCount++;
      }

      const cleaned = { ...task, title, description, image: null };
      const incomingImage = task.image;
      if (typeof incomingImage === "string" && incomingImage) {
        if (typeof task.id === "string" && existingImages.get(task.id) === incomingImage) {
          cleaned.image = incomingImage;
          keptImageChars += incomingImage.length;
        } else {
          newImageCandidates.push({ cleaned, image: incomingImage });
        }
      }
      return cleaned;
    };

    const rawTasks = Array.isArray(updatedTasks) ? updatedTasks : [];
    const wasTaskListTooLong = rawTasks.length > MAX_TASKS_PER_BOARD;
    const sanitizedTasks = rawTasks.slice(0, MAX_TASKS_PER_BOARD).map(sanitizeTask).filter(Boolean);

    
    // Only admins may remove tasks (a delete = an existing id missing from the new list).
    if (user.role !== "admin") {
      const nextIds = new Set(sanitizedTasks.map((t) => t?.id).filter((id) => typeof id === "string"));
      const removesTask = (Array.isArray(ws.tasks) ? ws.tasks : []).some(
        (t) => typeof t?.id === "string" && !nextIds.has(t.id)
      );
      if (removesTask) {
        socket.emit("permission_denied", "Only admins can delete tasks. Your board was refreshed.");
        socket.emit("receive_update", { tasks: ws.tasks, history: ws.history, silent: true });
        return;
      }
    }

    if (newImageCandidates.length) {
      let senderIsPro = false;
      if (user.email) {
        const senderRec = await ensureUserLoaded(user.email);
        senderIsPro = !!senderRec?.isPro;
      }
      let boardImageChars = keptImageChars;
      for (const { cleaned, image } of newImageCandidates) {
        if (!senderIsPro) { rejectedImages.notPro++; continue; }
        if (image.length > MAX_TASK_IMAGE_CHARS) { rejectedImages.tooLarge++; continue; }
        if (!IMAGE_DATA_URL_RE.test(image)) { rejectedImages.badFormat++; continue; }
        if (boardImageChars + image.length > MAX_BOARD_IMAGE_CHARS) { rejectedImages.boardFull++; continue; }
        boardImageChars += image.length;
        cleaned.image = image;
      }
      const totalRejected = Object.values(rejectedImages).reduce((a, b) => a + b, 0);
      if (totalRejected) socket.emit("task_image_rejected", rejectedImages);
    }

    const prevTasks = Array.isArray(ws.tasks) ? ws.tasks : [];
    ws.tasks = sanitizedTasks;

    try {
      await applyMentions(ws, user, prevTasks, sanitizedTasks);
    } catch (err) {
      console.error("[mentions] error:", err?.message);
    }

    if (truncatedTitleCount || truncatedDescCount || droppedInvalidCount || wasTaskListTooLong) {
      socket.emit("task_field_truncated", {
        truncatedTitleCount,
        truncatedDescCount,
        droppedInvalidCount,
        taskListCapped: wasTaskListTooLong,
      });
    }
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

   io.to(safeWorkspaceName).emit("receive_update", {
      tasks: ws.tasks,
      history: ws.history,
    });

    io.to(safeWorkspaceName).emit("history_update", ws.history);
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
    const deleteThrottle = await allowSensitiveAttempt(scopeForEmail("delete_workspace", safeEmail || safeWorkspaceName));
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
    const clearThrottle = await allowSensitiveAttempt(scopeForEmail("clear_history", safeWorkspaceName));
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

// ───────────── @Mentions (Pro only, parsed on the server) ─────────────
const MENTIONS_MAX_PER_SAVE = 5;
const MENTIONS_PER_MIN = 10;
const MENTIONS_MAX_STORED_PER_USER = 100;

function buildMentionIndex(ws) {
  const nameMap = new Map(); // lowercase name -> Set(emails)
  for (const m of Array.isArray(ws?.members) ? ws.members : []) {
    const email = normalizeEmail(m?.email);
    if (!email) continue;
    for (const n of [m?.displayName, m?.name]) {
      const s = typeof n === "string" ? n.trim().toLowerCase() : "";
      if (!s || s.length > 60) continue;
      if (!nameMap.has(s)) nameMap.set(s, new Set());
      nameMap.get(s).add(email);
    }
  }
  const namesByLen = [...nameMap.keys()].sort((a, b) => b.length - a.length);
  return { nameMap, namesByLen };
}

// "@" must start the text or follow whitespace. Longest member name wins and must end at a non-letter.
// A name shared by two members is ambiguous, so nobody is mentioned.
function extractMentionEmails(text, nameMap, namesByLen) {
  const found = new Set();
  if (typeof text !== "string" || !text.includes("@")) return found;
  const lower = text.toLowerCase();
  let ats = 0;
  for (let i = 0; i < lower.length && ats < 20; i++) {
    if (lower[i] !== "@") continue;
    ats++;
    if (i > 0 && !/\s/.test(lower[i - 1])) continue;
    for (const name of namesByLen) {
      if (!lower.startsWith(name, i + 1)) continue;
      const next = lower[i + 1 + name.length];
      if (next && /[\p{L}\p{N}_]/u.test(next)) continue;
      const emails = nameMap.get(name);
      if (emails && emails.size === 1) found.add([...emails][0]);
      break;
    }
  }
  return found;
}

function mentionTextOf(t) {
  const title = typeof t?.title === "string" ? t.title : "";
  const desc = typeof t?.description === "string" ? t.description : "";
  return `${title}\n${desc}`;
}

function trimMentionsFor(ws, email) {
  let mine = ws.mentions.filter((m) => m.toEmail === email);
  while (mine.length > MENTIONS_MAX_STORED_PER_USER) {
    const victim = mine.find((m) => m.read) || mine[0];
    ws.mentions = ws.mentions.filter((m) => m !== victim);
    mine = mine.filter((m) => m !== victim);
  }
}

// Returns the Set of recipient emails that got a NEW mention (used for live push in step 2).
async function applyMentions(ws, sender, prevTasks, nextTasks) {
  if (!Array.isArray(ws.mentions)) ws.mentions = [];
  const recipients = new Set();

  // 1) Mentions of deleted tasks are removed.
  const liveIds = new Set(nextTasks.map((t) => t?.id).filter((id) => typeof id === "string"));
  if (ws.mentions.length) ws.mentions = ws.mentions.filter((m) => liveIds.has(m?.taskId));

  // 2) New mentions: only @names that are new compared to the old text.
  const senderEmail = normalizeEmail(sender?.email);
  if (!senderEmail) { console.log("[mentions] stop: no sender email"); return recipients; }
  const { nameMap, namesByLen } = buildMentionIndex(ws);
  console.log("[mentions] member names indexed:", namesByLen.length);
  if (!namesByLen.length) return recipients;

  const prevById = new Map();
  for (const t of prevTasks) if (t && typeof t.id === "string") prevById.set(t.id, t);

  const candidates = [];
  scan:
  for (const t of nextTasks) {
    if (typeof t?.id !== "string" || t.id.length > 100) continue;
    const prev = prevById.get(t.id);
    if (prev && prev.title === t.title && prev.description === t.description) continue;
    const nowSet = extractMentionEmails(mentionTextOf(t), nameMap, namesByLen);
    if (!nowSet.size) continue;
    const prevSet = prev ? extractMentionEmails(mentionTextOf(prev), nameMap, namesByLen) : new Set();
    for (const email of nowSet) {
      if (email === senderEmail || prevSet.has(email)) continue;
      if (ws.mentions.some((m) => m.taskId === t.id && m.toEmail === email)) continue;
      candidates.push({ task: t, email });
      if (candidates.length >= MENTIONS_MAX_PER_SAVE) break scan;
    }
  }
  console.log("[mentions] candidates found:", candidates.length);
  if (!candidates.length) return recipients;

  // 3) Only a Pro sender creates mentions (Free: the @name stays plain text).
  let senderPro = false;
  try {
    const profile = await getHydratedUserProfile(senderEmail);
    senderPro = profile?.isPro === true;
  } catch {
    senderPro = false;
  }
  console.log("[mentions] senderPro:", senderPro);
  if (!senderPro) return recipients;

  const fromName = String(sender.displayName || sender.name || "").slice(0, 60);
  for (const { task, email } of candidates) {
    const rl = await countWindowedAction(`mention:${senderEmail}`, 60 * 1000, MENTIONS_PER_MIN);
    if (!rl.allowed) break;
    if (!Array.isArray(ws.tasks) || !ws.tasks.some((t) => t?.id === task.id)) continue; // deleted meanwhile
    ws.mentions.push({
      id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`,
      taskId: task.id,
      taskTitle: String(task.title || "").slice(0, 200),
      fromName,
      toEmail: email,
      createdAt: new Date().toISOString(),
      read: false,
    });
    trimMentionsFor(ws, email);
    recipients.add(email);
  }
  return recipients;
}

// ───────────── AI chat (Gemini, read-only) ─────────────
const AI_PER_MIN = Number(process.env.AI_PER_MIN) || 6;
const AI_PER_DAY = Number(process.env.AI_PER_DAY) || 40;
const AI_GLOBAL_PER_DAY = Number(process.env.AI_GLOBAL_PER_DAY) || 400; // protects the shared free-tier key
const AI_GLOBAL_PER_MIN = Number(process.env.AI_GLOBAL_PER_MIN) || 12; // shared by chat + voice, stays under Gemini's ~15 RPM
const AI_MAX_MESSAGE_CHARS = 1000;
const AI_MAX_HISTORY = 10;
const AI_MAX_HISTORY_CHARS = 2000;
const AI_ACT_PER_MIN = Math.max(1, parseInt(process.env.AI_ACT_PER_MIN || "10", 10) || 10);
const aiWindowMemory = new Map(); // fallback only, used when Mongo is unavailable

// Fixed-window counter in the rate_limits collection (atomic upsert, TTL-cleaned).
async function countWindowedAction(scope, windowMs, max) {
  const now = Date.now();
  const bucket = Math.floor(now / windowMs);
  const id = `${scope}:${bucket}`;
  const windowEnd = (bucket + 1) * windowMs;
  const retryAfterMs = Math.max(0, windowEnd - now);
  const col = rateLimitCollection();
  if (col) {
    try {
      const opts = { upsert: true, returnDocument: "after", includeResultMetadata: true };
      let result;
      try {
        result = await col.findOneAndUpdate(
          { _id: id },
          { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date(windowEnd + 60 * 1000) } },
          opts
        );
      } catch (e) {
        if (e?.code !== 11000) throw e; // two first-requests raced on insert: just increment
        result = await col.findOneAndUpdate({ _id: id }, { $inc: { count: 1 } }, { returnDocument: "after", includeResultMetadata: true });
      }
      const count = result?.value?.count ?? 1;
      return { allowed: count <= max, retryAfterMs };
    } catch (err) {
      console.error("[countWindowedAction] Mongo error, falling back to memory:", err.message);
    }
  }
  if (aiWindowMemory.size > 5000) aiWindowMemory.clear();
  const count = (aiWindowMemory.get(id) || 0) + 1;
  aiWindowMemory.set(id, count);
  return { allowed: count <= max, retryAfterMs };
}

const AI_MOVE_STATUSES = ["todo", "in-progress", "done"];
const AI_STATUS_LABELS = { todo: "To Do", "in-progress": "In Progress", done: "Done" };
const AI_MAX_MOVES = 5; // keep equal to MAX_MOVES in gemini.mjs

// Turns the model's raw call into a card built ONLY from server data. Returns:
// { proposal } | { already: {title, toLabel} } | null (invalid, dropped)
function buildMoveProposal(ws, refs, move) {
  const n = Number(move?.taskNumber);
  const target = move?.targetStatus;
  if (!Number.isInteger(n) || n < 1 || n > refs.length) return null;
  if (typeof target !== "string" || !AI_MOVE_STATUSES.includes(target)) return null;
  const id = refs[n - 1];
  if (!id) return null;
  const task = (Array.isArray(ws?.tasks) ? ws.tasks : []).find((t) => t && t.id === id);
  if (!task || !AI_MOVE_STATUSES.includes(task.status)) return null;
  const title = String(task.title || "").replace(/[\u0000-\u001F\u007F]+/g, " ").trim().slice(0, 100) || "(untitled)";
  if (task.status === target) return { already: { title, toLabel: AI_STATUS_LABELS[target] } };
  return {
    proposal: {
      type: "move_task",
      taskId: id,
      title,
      from: task.status,
      to: target,
      fromLabel: AI_STATUS_LABELS[task.status],
      toLabel: AI_STATUS_LABELS[target],
    },
  };
}


app.post("/api/ai/chat", async (req, res) => {
  try {
    // 1) Auth
    const email = getVerifiedSessionEmail(req.headers.cookie || "");
    if (!email) return res.status(401).json({ error: "Not authenticated." });

    // 2) Input validation
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const workspaceName = typeof body.workspaceName === "string" ? normalizeText(body.workspaceName) : "";
    const message = typeof body.message === "string" ? body.message.trim() : "";
    if (!workspaceName || workspaceName.length > 100) return res.status(400).json({ error: "Invalid workspace." });
    if (!message) return res.status(400).json({ error: "Message is empty." });
    if (message.length > AI_MAX_MESSAGE_CHARS) {
      return res.status(400).json({ error: `Message too long (max ${AI_MAX_MESSAGE_CHARS} characters).` });
    }
    if (body.history !== undefined && !Array.isArray(body.history)) {
      return res.status(400).json({ error: "Invalid history." });
    }
    const history = [];
    for (const h of (body.history || []).slice(-AI_MAX_HISTORY)) {
      if (!h || typeof h !== "object" || typeof h.text !== "string") continue;
      const role = h.role === "user" ? "user" : h.role === "assistant" || h.role === "model" ? "model" : null;
      const text = h.text.trim().slice(0, AI_MAX_HISTORY_CHARS);
      if (role && text) history.push({ role, text });
    }
    while (history.length && history[0].role !== "user") history.shift();

    // 3) Membership: only a workspace the user belongs to is ever read
    let ws = workspaces[workspaceName];
    if (!ws) {
      const loaded = await loadRoomFromDB(workspaceName);
      if (loaded) {
        workspaces[workspaceName] = loaded;
        ws = loaded;
      }
    }
    const creatorEmail = normalizeEmail(ws?.creatorEmail);
    const isMember = !!ws && (
      (creatorEmail && creatorEmail === email) ||
      (Array.isArray(ws.members) && ws.members.some((m) => normalizeEmail(m?.email) === email))
    );
    if (!isMember) return res.status(403).json({ error: "You are not a member of this workspace." });

    // 4) Rate limits: per minute, per day, then global
    const minute = await countWindowedAction(`ai_min:${email}`, 60 * 1000, AI_PER_MIN);
    if (!minute.allowed) {
      const retryAfterSec = Math.ceil(minute.retryAfterMs / 1000);
      res.set("Retry-After", String(retryAfterSec));
      return res.status(429).json({ code: "rate_minute", error: "You're sending messages too fast. Wait a moment and try again.", retryAfterSec });
    }
    // Plan first (Free and Pro have separate daily budgets, so Free can't use up Pro's).
    let isPro = false;
    let planUnknown = false;
    try {
      const profile = await getHydratedUserProfile(email);
      if (!profile) planUnknown = true; // user record not found / DB problem
      isPro = profile?.isPro === true;
    } catch {
      planUnknown = true; // treated as Free, and the AI is told the plan is unverified
    }
    const day = await countWindowedAction(`ai_day:${email}`, 24 * 60 * 60 * 1000, isPro ? AI_PER_DAY : AI_FREE_PER_DAY);
    if (!day.allowed) {
      return res.status(429).json({ code: "rate_daily", error: "You've reached today's AI limit. Try again tomorrow." });
    }
    const global = await countWindowedAction(
      isPro ? "ai_day_global" : "ai_free_global",
      24 * 60 * 60 * 1000,
      isPro ? AI_GLOBAL_PER_DAY : AI_FREE_GLOBAL_PER_DAY
    );
    if (!global.allowed) {
      return res.status(429).json({ code: "rate_global", error: "The AI assistant has reached its daily capacity. Try again tomorrow." });
    }
    const busy = await countWindowedAction("ai_global_min", 60 * 1000, AI_GLOBAL_PER_MIN);
    if (!busy.allowed) {
      const retryAfterSec = Math.ceil(busy.retryAfterMs / 1000);
      res.set("Retry-After", String(retryAfterSec));
      return res.status(429).json({ code: "rate_busy", error: "The AI is busy right now. Try again in a few seconds.", retryAfterSec });
    }
    // 5) Build context (client may send its local date; accepted only if within 1 day of server date)
    const serverToday = new Date().toISOString().slice(0, 10);
    let today = serverToday;
    if (typeof body.today === "string" && /^\d{4}-\d{2}-\d{2}$/.test(body.today)) {
      const diffDays = Math.abs(Date.parse(body.today + "T00:00:00Z") - Date.parse(serverToday + "T00:00:00Z")) / 86400000;
      if (diffDays <= 1) today = body.today;
    }
    const team = isPro
      ? {
          members: getValidWorkspaceMembers(ws).map((m) => ({ name: m.displayName || m.name, role: m.role })),
          online: getValidOnlineMembers(ws).map((u) => ({ name: u.name, role: u.role })),
        }
      : null;
    const { text: boardContext, refs } = buildBoardContextWithRefs(ws, today, {
      isPro,
      team,
      planUnknown,
      tz: typeof body.tz === "string" ? body.tz : "UTC",
    });

    // 6) Ask Gemini
    try {
      const plan = planUnknown ? "unknown" : isPro ? "Pro" : "Free";
      const result = await askGemini({ boardContext, history, message, plan, canPropose: isPro });
         let reply = result.text;
      const proposals = [];
      const already = [];
      if (isPro && Array.isArray(result.moves) && result.moves.length) {
        const usedIds = new Set();
        for (const mv of result.moves.slice(0, AI_MAX_MOVES)) {
          const built = buildMoveProposal(ws, refs, mv);
          if (built?.proposal) {
            if (usedIds.has(built.proposal.taskId)) continue; // each task once
            usedIds.add(built.proposal.taskId);
            proposals.push(built.proposal);
          } else if (built?.already) {
            already.push(built.already);
          }
        }
        // Card text comes from server data, never from the model's words.
        if (proposals.length === 1) {
          reply = `Ready to move "${proposals[0].title}" to ${proposals[0].toLabel}. Confirm below.`;
        } else if (proposals.length > 1) {
          reply = `Ready to move ${proposals.length} tasks, in this order. Confirm below.`;
        } else if (already.length === 1) {
          reply = `"${already[0].title}" is already in ${already[0].toLabel}.`;
        } else if (already.length > 1) {
          reply = "Those tasks are already in the columns you asked for.";
        } else if (!reply) {
          reply = "I couldn't tell which tasks you mean. Can you give me their names?";
        }
        if (proposals.length && already.length) {
          reply += ` ${already.length} already in place, skipped.`;
        }
      }
      return res.json({ ok: true, reply, ...(proposals.length ? { proposals } : {}) });
    } catch (err) {
      console.error("[ai/chat] AI error:", err?.code || err?.message);
      switch (err?.code) {
        case "quota":
          return res.status(429).json({ code: "provider_quota", error: "The AI is busy right now (free-tier limit reached). Try again in a minute." });
        case "timeout":
          return res.status(504).json({ error: "The AI took too long to answer. Try again." });
        case "blocked":
        case "too_long":
          return res.status(422).json({ error: "The AI couldn't answer that. Try a shorter or more specific question." });
        case "not_configured":
          return res.status(503).json({ error: "The AI assistant isn't set up on the server yet." });
        default:
          return res.status(502).json({ error: "The AI service had a problem. Try again shortly." });
      }
    }
  } catch (err) {
    console.error("[ai/chat] Unexpected error:", err?.message);
    return res.status(500).json({ error: "Something went wrong." });
  }
});


// ---------- AI voice: speech -> text (Pro only) ----------
// Audio is never stored or logged. The route returns plain text only; it never touches
// the board. The text still goes through /api/ai/chat + the Confirm card like typing.
const aiVoiceEnvInt = (name, def) => {
  const n = parseInt(process.env[name] || "", 10);
  return Number.isFinite(n) && n > 0 ? n : def;
};

const AI_FREE_PER_DAY = aiVoiceEnvInt("AI_FREE_PER_DAY", 10);
const AI_FREE_GLOBAL_PER_DAY = aiVoiceEnvInt("AI_FREE_GLOBAL_PER_DAY", 100);
const AI_VOICE_PER_MIN = aiVoiceEnvInt("AI_VOICE_PER_MIN", 6);
const AI_VOICE_PER_DAY = aiVoiceEnvInt("AI_VOICE_PER_DAY", 20);
const AI_VOICE_GLOBAL_PER_DAY = aiVoiceEnvInt("AI_VOICE_GLOBAL_PER_DAY", 100);
const AI_VOICE_MAX_BYTES = 1.5 * 1024 * 1024;
const AI_VOICE_MIN_BYTES = 1000;

// The real file type from its first bytes. The Content-Type header alone is not trusted.
function sniffAudioMime(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return "audio/webm";
  if (buf.toString("latin1", 4, 8) === "ftyp") return "audio/mp4";
  if (buf.toString("latin1", 0, 4) === "OggS") return "audio/ogg";
  if (buf.toString("latin1", 0, 4) === "RIFF" && buf.toString("latin1", 8, 12) === "WAVE") return "audio/wav";
  return null;
}

// Cheap checks BEFORE the body is read, so a Free account or an attacker can't make us receive 1.5 MB.
async function aiVoiceGate(req, res, next) {
  try {
    const email = getVerifiedSessionEmail(req.headers.cookie || "");
    if (!email) return res.status(401).json({ error: "Not authenticated." });

    const mime = normalizeAudioMime(req.headers["content-type"]);
    if (!mime) return res.status(400).json({ code: "bad_audio", error: "Unsupported audio type." });

    const len = Number(req.headers["content-length"]);
    if (!Number.isFinite(len) || len <= 0) return res.status(400).json({ code: "bad_audio", error: "Missing audio." });
    if (len > AI_VOICE_MAX_BYTES) return res.status(413).json({ code: "too_big", error: "Recording is too long." });

    const lim = await countWindowedAction(`ai_voice_min:${email}`, 60 * 1000, AI_VOICE_PER_MIN);
    if (!lim.allowed) {
      const retryAfterSec = Math.ceil(lim.retryAfterMs / 1000);
      res.set("Retry-After", String(retryAfterSec));
      return res.status(429).json({ code: "rate_minute", error: "Too many recordings. Wait a moment and try again.", retryAfterSec });
    }

    let profile = null;
    try {
      profile = await getHydratedUserProfile(email);
    } catch {
      profile = null;
    }
    if (!profile) return res.status(503).json({ error: "Can't verify your plan right now. Try again in a moment." });
    if (profile.isPro !== true) return res.status(403).json({ error: "Voice input is a Pro feature." });

    req.voiceEmail = email;
    req.voiceMime = mime;
    return next();
  } catch (err) {
    console.error("[ai/transcribe] gate error:", err?.message);
    return res.status(500).json({ error: "Something went wrong." });
  }
}

app.post(
  "/api/ai/transcribe",
  aiVoiceGate,
  express.raw({ type: () => true, limit: AI_VOICE_MAX_BYTES }),
  async (req, res) => {
    try {
      const email = req.voiceEmail;
      const audio = req.body;
      if (!Buffer.isBuffer(audio) || audio.length < AI_VOICE_MIN_BYTES) {
        return res.status(400).json({ code: "bad_audio", error: "That recording was too short or empty." });
      }
      if (sniffAudioMime(audio) !== req.voiceMime) {
        return res.status(400).json({ code: "bad_audio", error: "Couldn't read that recording." });
      }

      // Daily caps count only recordings that passed validation.
      const day = await countWindowedAction(`ai_voice_day:${email}`, 24 * 60 * 60 * 1000, AI_VOICE_PER_DAY);
      if (!day.allowed) {
        return res.status(429).json({ code: "rate_daily", error: "You've reached today's voice limit. You can still type." });
      }
      const global = await countWindowedAction("ai_voice_global", 24 * 60 * 60 * 1000, AI_VOICE_GLOBAL_PER_DAY);
      if (!global.allowed) {
        return res.status(429).json({ code: "rate_global", error: "Voice is busy right now. Please type instead." });
      }

            const busy = await countWindowedAction("ai_global_min", 60 * 1000, AI_GLOBAL_PER_MIN);
      if (!busy.allowed) {
        const retryAfterSec = Math.ceil(busy.retryAfterMs / 1000);
        res.set("Retry-After", String(retryAfterSec));
        return res.status(429).json({ code: "rate_busy", error: "Voice is busy right now. Try again in a few seconds.", retryAfterSec });
      }

      try {
        const text = await transcribeAudio({ audio, mime: req.voiceMime });
        res.set("Cache-Control", "no-store");
        return res.json({ ok: true, text });
      } catch (err) {
        console.error("[ai/transcribe] AI error:", err?.code || err?.message);
        switch (err?.code) {
          case "no_speech":
            return res.status(422).json({ code: "no_speech", error: "Didn't catch that. Try again." });
          case "bad_audio":
            return res.status(400).json({ code: "bad_audio", error: "Couldn't read that recording." });
          case "quota":
            return res.status(429).json({ code: "provider_quota", error: "Voice is busy right now. Try again in a minute or type instead." });
          case "timeout":
            return res.status(504).json({ error: "Transcribing took too long. Try again." });
          case "blocked":
          case "too_long":
            return res.status(422).json({ error: "Couldn't transcribe that. Try again." });
          case "not_configured":
            return res.status(503).json({ error: "The AI assistant isn't set up on the server yet." });
          default:
            return res.status(502).json({ error: "The voice service had a problem. Try again shortly." });
        }
      }
    } catch (err) {
      console.error("[ai/transcribe] Unexpected error:", err?.message);
      return res.status(500).json({ error: "Something went wrong." });
    }
  }
);
const PORT = process.env.PORT || 3001;
// Runs a move the user CONFIRMED in the chat. Same rules as the socket move,
// but changes only the one task found by id. Never trusts model or client text.
app.post("/api/ai/action", async (req, res) => {
  try {
    // 1) Auth
    const email = getVerifiedSessionEmail(req.headers.cookie || "");
    if (!email) return res.status(401).json({ error: "Not authenticated." });

    // 2) Validation (whitelists only)
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const workspaceName = typeof body.workspaceName === "string" ? normalizeText(body.workspaceName) : "";
    const taskId = typeof body.taskId === "string" ? body.taskId.trim() : "";
    if (!workspaceName || workspaceName.length > 100) return res.status(400).json({ error: "Invalid workspace." });
    if (body.action !== "move_task") return res.status(400).json({ error: "Unsupported action." });
    if (!taskId || taskId.length > 100) return res.status(400).json({ error: "Invalid task." });
    if (!AI_MOVE_STATUSES.includes(body.targetStatus) || !AI_MOVE_STATUSES.includes(body.expectedFrom)) {
      return res.status(400).json({ error: "Invalid column." });
    }
    const targetStatus = body.targetStatus;
    const expectedFrom = body.expectedFrom;

    // 3) Membership + role (derived on the server, never from the client)
    let ws = workspaces[workspaceName];
    if (!ws) {
      const loaded = await loadRoomFromDB(workspaceName);
      if (loaded) {
        workspaces[workspaceName] = loaded;
        ws = loaded;
      }
    }
    if (!ws) return res.status(403).json({ error: "You are not a member of this workspace." });
    const creatorEmail = normalizeEmail(ws.creatorEmail);
    const member = Array.isArray(ws.members) ? ws.members.find((m) => normalizeEmail(m?.email) === email) : null;
    const isCreator = !!creatorEmail && creatorEmail === email;
    if (!isCreator && !member) return res.status(403).json({ error: "You are not a member of this workspace." });
    const role = isCreator ? "admin" : member?.role;
    if (role !== "admin" && role !== "member") {
      return res.status(403).json({ error: "Your role can't change tasks." });
    }
    const actorName = normalizeText(member?.displayName || member?.name || "") || "A teammate";

    // 4) Rate limit (own bucket; no Gemini cost)
    const lim = await countWindowedAction(`ai_act:${email}`, 60 * 1000, AI_ACT_PER_MIN);
    if (!lim.allowed) {
      res.set("Retry-After", String(Math.ceil(lim.retryAfterMs / 1000)));
      return res.status(429).json({ error: "Too many actions. Wait a moment and try again." });
    }

    // 5) Pro re-check at execution time (expiry included). If we can't verify, we don't move anything.
    let profile = null;
    try {
      profile = await getHydratedUserProfile(email);
    } catch {
      profile = null;
    }
    if (!profile) return res.status(503).json({ error: "Can't verify your plan right now. Try again in a moment." });
    if (profile.isPro !== true) return res.status(403).json({ error: "Moving tasks with the AI is a Pro feature." });

    // 6) From here to the push there is NO await, so a concurrent update can't be overwritten.
    const tasks = Array.isArray(ws.tasks) ? ws.tasks : [];
    const current = tasks.find((t) => t && t.id === taskId);
    if (!current) return res.status(404).json({ error: "That task no longer exists." });
    if (current.status === targetStatus) {
      return res.status(409).json({ code: "already", error: `Already in ${AI_STATUS_LABELS[targetStatus]}.` });
    }
    if (current.status !== expectedFrom) {
      return res.status(409).json({ code: "stale", error: "This task changed since the proposal. Ask again." });
    }

    const nowISO = new Date().toISOString();
    const isDone = targetStatus === "done";
    ws.tasks = tasks.map((t) =>
      t && t.id === taskId
        ? {
            ...t,
            status: targetStatus,
            log: `Moved by ${actorName}`,
            completedAt: isDone ? nowISO : null,
            completedBy: isDone ? actorName : null,
          }
        : t
    );
    if (!Array.isArray(ws.history)) ws.history = [];
    pushHistory(ws, {
      action: "move_task",
      taskTitle: current.title || null,
      targetStatus: AI_STATUS_LABELS[targetStatus],
      userName: actorName,
      userRole: role,
      timestamp: nowISO,
    });

    await saveRoomToDB(workspaceName);

for (const [sid, u] of ws.sockets) {
  if (normalizeEmail(u?.email) === email) {
    io.to(sid).emit("receive_update", { tasks: ws.tasks, history: ws.history, silent: true });
  } else {
    io.to(sid).emit("receive_update", { tasks: ws.tasks, history: ws.history });
    io.to(sid).emit("history_update", ws.history);
  }
}

    return res.json({
      ok: true,
      task: { id: taskId, title: String(current.title || ""), status: targetStatus },
      toLabel: AI_STATUS_LABELS[targetStatus],
    });
  } catch (err) {
    console.error("[ai/action] Unexpected error:", err?.message);
    return res.status(500).json({ error: "Something went wrong." });
  }
});



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
