
import express  from "express";
import http     from "http";
import { Server } from "socket.io";
import cors     from "cors";
import dotenv   from "dotenv";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import rateLimit from "express-rate-limit";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import {
  hashSecret,
  verifyUserPassword,
  verifyWorkspacePin,
  maybeUpgradeWorkspacePin,
  verifyProPinWithWorker,
  parseAllowedOrigins,
  isOriginAllowed,
} from "./security.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, ".env") });

const IS_DEV = process.env.NODE_ENV !== "production";
const ALLOWED_ORIGINS = parseAllowedOrigins();
const devLog = (...args) => { if (IS_DEV) console.log(...args); };
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = (process.env.SMTP_PASS || "").replace(/\s+/g, "");
const CONTACT_EMAIL_TO = process.env.CONTACT_EMAIL_TO || SMTP_USER || "";

const maskEmail = (value) => {
  const text = String(value || "").trim();
  if (!text) return "";
  const [local, domain] = text.split("@");
  if (!domain) return text;
  const head = local.slice(0, 2);
  return `${head}${local.length > 2 ? "***" : ""}@${domain}`;
};

const logMailError = (err, context = {}) => {
  const details = {
    message: err?.message,
    code: err?.code,
    command: err?.command,
    response: err?.response,
    responseCode: err?.responseCode,
    errno: err?.errno,
    syscall: err?.syscall,
    address: err?.address,
    port: err?.port,
    host: err?.host,
    context,
  };
  console.error("[contact] SMTP error:", JSON.stringify(details, null, 2));
  if (err?.stack) console.error("[contact] SMTP stack:\n" + err.stack);
};

const mailTransporter = SMTP_USER && SMTP_PASS
  ? nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    })
  : null;

if (mailTransporter) {
  console.log("[startup] SMTP transporter configured:", {
    user: maskEmail(SMTP_USER),
    to: maskEmail(CONTACT_EMAIL_TO),
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
  });
  mailTransporter.verify()
    .then(() => devLog("[startup] SMTP transporter verified"))
    .catch((err) => console.error("[startup] SMTP transporter verification failed:", err.message));
}

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: {
    origin: (origin, cb) => {
      cb(null, isOriginAllowed(origin, ALLOWED_ORIGINS));
    },
    methods: ["GET", "POST"],
    credentials: true,
  },
  maxHttpBufferSize: 10 * 1024 * 1024,
  pingInterval: 25000,
  pingTimeout: 60000,
  transports: ["websocket", "polling"],
});

app.use(cors({
  origin: (origin, cb) => cb(null, isOriginAllowed(origin, ALLOWED_ORIGINS)),
  credentials: true,
}));
app.use((req, res, next) => {
  if (req.path === "/api/contact") {
    const startedAt = Date.now();
    const requestId = req.headers["x-contact-request-id"] || "";
    console.log("[contact] request entered middleware:", {
      requestId,
      method: req.method,
      origin: req.headers.origin || "",
      contentType: req.headers["content-type"] || "",
      contentLength: req.headers["content-length"] || "",
      ip: (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "",
    });
    res.on("finish", () => {
      console.log("[contact] response finished:", {
        method: req.method,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAt,
      });
    });
  }
  next();
});
app.use(express.json({ limit: "2mb" }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: IS_DEV ? 1000 : 300,
  standardHeaders: true,
  legacyHeaders: false,
}));
 app.get("/", (_, res) => res.send("SyncBoard Pro server running ✓"));
 const CONTACT_MESSAGE_LIMIT = 500;
const contactMessages = [];

const sendMailWithTimeout = async (mailOptions, timeoutMs = 12000) => {
  if (!mailTransporter) throw new Error("Email delivery not configured.");
  const startedAt = Date.now();
  console.log("[contact] sending email:", {
    to: maskEmail(mailOptions.to),
    replyTo: maskEmail(mailOptions.replyTo),
    subject: mailOptions.subject,
    timeoutMs,
  });
  return Promise.race([
    mailTransporter.sendMail(mailOptions).then((info) => {
      console.log("[contact] email sent:", {
        messageId: info?.messageId,
        accepted: info?.accepted,
        rejected: info?.rejected,
        durationMs: Date.now() - startedAt,
      });
      return info;
    }).catch((err) => {
      logMailError(err, { stage: "sendMail", durationMs: Date.now() - startedAt });
      throw err;
    }),
    new Promise((_, reject) => {
      setTimeout(() => {
        console.error("[contact] email send timeout:", {
          timeoutMs,
          durationMs: Date.now() - startedAt,
          to: maskEmail(mailOptions.to),
        });
        reject(new Error("Email delivery timed out."));
      }, timeoutMs);
    }),
  ]);
};

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

  console.log("[contact] request received:", {
    requestId,
    name: name || userName || "Anonymous",
    email: maskEmail(email),
    subject,
    workspaceName,
    role,
    origin: req.headers.origin || "",
    ip: (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "",
  });

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
      await collection.insertOne(entry);
    } else {
      contactMessages.push(entry);
      if (contactMessages.length > CONTACT_MESSAGE_LIMIT) contactMessages.shift();
    }
  } catch (err) {
    console.error("[contact] Failed to store message:", err.message);
    return res.status(500).json({ error: "Failed to store message." });
  }

  if (!mailTransporter || !CONTACT_EMAIL_TO) {
    return res.status(503).json({ error: "Email delivery not configured." });
  }

  const mailSubject = `SyncBoard Support${workspaceName ? ` • ${workspaceName}` : ""}${subject ? ` • ${subject}` : ""}`;
  const text = [
    `Name: ${entry.name}`,
    `Email: ${entry.email}`,
    entry.subject ? `Subject: ${entry.subject}` : "",
    entry.userName ? `User Name: ${entry.userName}` : "",
    entry.userEmail ? `User Email: ${entry.userEmail}` : "",
    entry.role ? `Role: ${entry.role}` : "",
    entry.workspaceName ? `Workspace: ${entry.workspaceName}` : "",
    `IP: ${entry.ip}`,
    "",
    entry.message,
  ].filter(Boolean).join("\n");

  try {
    await sendMailWithTimeout({
      from: `SyncBoard Contact <${SMTP_USER}>`,
      to: CONTACT_EMAIL_TO,
      replyTo: entry.email,
      subject: mailSubject,
      text,
    });
    return res.json({ ok: true });
  } catch (err) {
    logMailError(err, { stage: "contact-route", requestId, workspaceName: entry.workspaceName, email: entry.email });
    return res.status(500).json({ error: "Failed to send email." });
  }
});
 const MONGO_URI = process.env.MONGO_URI;
if (IS_DEV) devLog("[startup] MONGO_URI:", MONGO_URI ? "configured" : "missing");
let mongoConnected = false;

async function connectDB() {
  if (!MONGO_URI) {
    console.warn("[connectDB] MONGO_URI not configured, running in memory-only mode");
    return;
  }
  
  try {
    console.log("[connectDB] Attempting to connect to MongoDB...");
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
    console.log("[connectDB] ✓ Connected to MongoDB");
  } catch (err) {
    console.error("[connectDB] ✗ Failed to connect to MongoDB:", err.message);
    mongoConnected = false;
  }
}

async function saveRoomToDB(workspaceName) {
  if (!mongoConnected) {
    console.log("[saveRoomToDB] MongoDB not connected, skipping DB save");
    return;
  }
  
  const ws = workspaces[workspaceName];
  if (!ws) return;
   let creatorEmailToSave = ws.creatorEmail;
  if (!creatorEmailToSave) {
    console.warn(`[saveRoomToDB] ⚠️  WARNING: ws.creatorEmail is undefined for workspace "${workspaceName}"!`);
     const adminMember = ws.members.find(m => m.role === "admin");
    if (adminMember && adminMember.email) {
      creatorEmailToSave = adminMember.email;
      console.log(`[saveRoomToDB] 🔧 Using admin member as creator: "${creatorEmailToSave}"`);
    }
  }
  
  console.log(`[saveRoomToDB] Saving workspace "${workspaceName}" with creatorEmail: "${creatorEmailToSave || "UNDEFINED"}"`);
  
  try {
    const collection = mongoose.connection.db.collection("workspaces");
    const result = await collection.updateOne(
      { workspaceName: workspaceName },
      {
        $set: {
          workspaceName: workspaceName,
          password: ws.password,
          projectName: ws.projectName,
          creatorEmail: creatorEmailToSave,
          tasks: ws.tasks || [],
          history: ws.history || [],
          members: ws.members || [],
          updatedAt: new Date().toISOString(),
        }
      },
      { upsert: true }
    );
    
    console.log(`[saveRoomToDB] ✓ Saved ${workspaceName} to MongoDB | creatorEmail: "${creatorEmailToSave}"`);
  } catch (err) {
    console.error(`[saveRoomToDB] Error saving ${workspaceName}:`, err.message);
  }
}

async function loadRoomFromDB(workspaceName) {
  if (!mongoConnected) {
    console.log("[loadRoomFromDB] MongoDB not connected");
    return null;
  }
  
  try {
    const collection = mongoose.connection.db.collection("workspaces");
    const doc = await collection.findOne({ workspaceName: workspaceName });
    
    if (doc) {
      console.log(`[loadRoomFromDB] ✓ Loaded ${workspaceName} from MongoDB`);
      return {
        password: doc.password,
        projectName: doc.projectName,
        creatorEmail: doc.creatorEmail,
        tasks: doc.tasks || [],
        history: doc.history || [],
        members: doc.members || [],
        sockets: new Map(),
      };
    }
    
    console.log(`[loadRoomFromDB] Workspace ${workspaceName} not found in MongoDB`);
    return null;
  } catch (err) {
    console.error(`[loadRoomFromDB] Error loading ${workspaceName}:`, err.message);
    return null;
  }
}


async function saveUserToDB(email) {
  if (!mongoConnected) {
    console.warn("[saveUserToDB] ⚠️  MongoDB not connected, CANNOT save user data!");
    return;
  }
  
  const key = email.toLowerCase().trim();
  const user = users[key];
  if (!user) {
    console.warn(`[saveUserToDB] User ${key} not found in memory!`);
    return;
  }
  
  try {
    const collection = mongoose.connection.db.collection("users");
    const result = await collection.updateOne(
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
          updatedAt: new Date().toISOString(),
        }
      },
      { upsert: true }
    );
    console.log(`[saveUserToDB] ✓ Saved user ${key} to MongoDB | taskCount: ${user.taskCount} | matched: ${result.matchedCount}, upserted: ${result.upsertedId ? 'new' : 'existing'}`);
  } catch (err) {
    console.error(`[saveUserToDB] ✗ Error saving ${key}:`, err.message);
  }
}

async function loadUserFromDB(email) {
  if (!mongoConnected) {
    console.log("[loadUserFromDB] MongoDB not connected");
    return null;
  }
  
  const key = email.toLowerCase().trim();
  
  try {
    const collection = mongoose.connection.db.collection("users");
    const doc = await collection.findOne({ email: key });
    
    if (doc) {
      console.log(`[loadUserFromDB] ✓ Loaded user ${key} from MongoDB (taskCount: ${doc.taskCount})`);
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
      };
    }
    
    console.log(`[loadUserFromDB] User ${key} not found in MongoDB`);
    return null;
  } catch (err) {
    console.error(`[loadUserFromDB] Error loading ${key}:`, err.message);
    return null;
  }
}
 const workspaces  = {};
const MAX_HISTORY = Infinity;
 const users = {};

const FREE_TASK_LIMIT = 3;
const PRO_TASK_LIMIT  = 3000;
const MONTH_MS        = 30 * 24 * 60 * 60 * 1000;
const PRO_DURATION_MS = 30 * 24 * 60 * 60 * 1000;

const GIBBERISH_NAMES = [
  "AAAAABBBBBCCCCCDDDDD",
  "QQQQQWWWWWEEEEE",
  "ZXCVBNMASDFGHJKL",
];

function obfuscateText(seed = 0) {
  return GIBBERISH_NAMES[Math.abs(seed) % GIBBERISH_NAMES.length];
}

async function registerUser(email, name, password) {
  const key = email.toLowerCase().trim();
  const passwordHash = await hashSecret(password);
  users[key] = {
    name: name.trim(),
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
  const key = email.toLowerCase().trim();
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

async function upgradeWorkspacePinIfNeeded(ws, workspaceName, plainPin) {
  const upgraded = await maybeUpgradeWorkspacePin(plainPin, ws.password);
  if (upgraded !== ws.password) {
    ws.password = upgraded;
    await saveRoomToDB(workspaceName);
  }
}

function getUserTaskData(email) {
  const key  = email.toLowerCase().trim();
  const user = users[key];
  if (!user) return { count: 0, resetAt: null };
  if (user.resetAt && new Date() > new Date(user.resetAt)) {
    user.taskCount = 0;
    user.resetAt   = null;
    user.taskIds   = [];
  }
  return { count: user.taskCount, resetAt: user.resetAt };
}

function ensureProValidity(email) {
  const key = email.toLowerCase().trim();
  const user = users[key];
  if (!user) return false;
  if (user.isPro && !user.proActivatedAt && !user.proExpiresAt) {
    const now = Date.now();
    user.proActivatedAt = new Date(now).toISOString();
    user.proExpiresAt = new Date(now + PRO_DURATION_MS).toISOString();
    saveUserToDB(email).catch(err => console.error("[ensureProValidity] Error saving to DB:", err.message));
  }
  if (user.isPro && user.proExpiresAt && !user.proActivatedAt) {
    const start = new Date(user.proExpiresAt).getTime() - PRO_DURATION_MS;
    user.proActivatedAt = new Date(start).toISOString();
    saveUserToDB(email).catch(err => console.error("[ensureProValidity] Error saving to DB:", err.message));
  }
  if (user.isPro && user.proActivatedAt && !user.proExpiresAt) {
    user.proExpiresAt = new Date(new Date(user.proActivatedAt).getTime() + PRO_DURATION_MS).toISOString();
    saveUserToDB(email).catch(err => console.error("[ensureProValidity] Error saving to DB:", err.message));
  }
  if (user.isPro && user.proExpiresAt && new Date() > new Date(user.proExpiresAt)) {
    user.isPro = false;
    user.proPin = null;
    user.proActivatedAt = null;
    user.proExpiresAt = null;
    saveUserToDB(email).catch(err => console.error("[ensureProValidity] Error saving to DB:", err.message));
    return false;
  }
  return user.isPro === true;
}

function incrementUserTaskCount(email, taskId) {
  const key  = email.toLowerCase().trim();
  const user = users[key];
  if (!user) return 0;
  user.taskCount++;
  if (!user.resetAt) {
    const next = new Date(Date.now() + MONTH_MS);
    user.resetAt = next.toISOString();
  }
  user.taskIds.push(taskId);
  console.log(`[incrementUserTaskCount] ${key}: taskCount now ${user.taskCount}, saving to DB...`);
  return user.taskCount;
}

async function ensureUserLoaded(email) {
  const key = email.toLowerCase().trim();
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
  return users[key];
}

async function incrementUserTaskCountAsync(email, taskId) {
  const key  = email.toLowerCase().trim();
  const user = await ensureUserLoaded(email);
  if (!user) return 0;
  user.taskCount++;
  if (!user.resetAt) {
    const next = new Date(Date.now() + MONTH_MS);
    user.resetAt = next.toISOString();
  }
  user.taskIds.push(taskId);
  console.log(`[incrementUserTaskCountAsync] ${key}: taskCount now ${user.taskCount}, saving to DB...`);
   await saveUserToDB(email);
  console.log(`[incrementUserTaskCountAsync] ✓ Saved ${key} with taskCount=${user.taskCount}`);
  return user.taskCount;
}

function markUserPro(email, proPin) {
  const key  = email.toLowerCase().trim();
  const user = users[key];
  if (!user) return false;
  const now = Date.now();
  const existingExpiry = user.proExpiresAt ? new Date(user.proExpiresAt).getTime() : null;
  const shouldResetWindow = !existingExpiry || Number.isNaN(existingExpiry) || existingExpiry <= now;

  user.isPro  = true;
  user.proPin = proPin;
  if (shouldResetWindow) {
    user.proActivatedAt = new Date(now).toISOString();
    user.proExpiresAt = new Date(now + PRO_DURATION_MS).toISOString();
  }
   saveUserToDB(email).catch(err => console.error("[markUserPro] Error saving to DB:", err.message));
  return true;
}

async function deactivateUserPro(email) {
  const key  = email.toLowerCase().trim();
  const user = users[key];
  if (!user) return false;
  user.isPro = false;
  await saveUserToDB(email);
  return true;
}

async function broadcastUsers(workspaceName) {
  const ws = workspaces[workspaceName];
  if (!ws) return;

  const memberEmailByName = new Map();
  ws.members.forEach(m => {
    if (m?.name && m?.email) memberEmailByName.set(m.name, m.email);
  });

  const uniqueMap = new Map();
  for (const u of ws.sockets.values()) {
    const filledEmail = u.email || memberEmailByName.get(u.name);
    const key = (filledEmail || u.name || "").toLowerCase();
    if (!key) continue;

    const existing = uniqueMap.get(key);
    if (!existing) {
      uniqueMap.set(key, { name: u.name, email: filledEmail || null, role: u.role });
      continue;
    }

    if (!existing.email && filledEmail) {
      uniqueMap.set(key, { name: u.name, email: filledEmail, role: u.role });
    }
  }


  for (const [key, val] of uniqueMap.entries()) {
    if (!val.email && val.name) {
      const emailFromMember = memberEmailByName.get(val.name);
      if (emailFromMember) {
        uniqueMap.delete(key);
        uniqueMap.set(emailFromMember.toLowerCase(), { name: val.name, email: emailFromMember, role: val.role });
      }
    }
  }

  const online = [...uniqueMap.values()];
  console.log(`[broadcastUsers] ${workspaceName}: ${online.length} users online -`, online.map(u => u.name).join(", "));

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
    const isPro = viewerEmail ? (proByEmail.get(viewerEmail) || false) : false;

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
  io.to(workspaceName).emit("members_update", ws.members);
}

function pushHistory(ws, entry) {
  ws.history.unshift(entry);
}


io.on("connection", (socket) => {
  console.log(`[connect] ${socket.id}`);


  socket.on("auth_user", async ({ email, password, name }) => {
    if (!email || !password) {
      return socket.emit("auth_error", "Email and password are required.");
    }
    const key = email.toLowerCase().trim();
    console.log(`[auth_user] Auth attempt for ${key}`);
    let existing = users[key];


    if (!existing) {
      console.log(`[auth_user] User not in memory, loading from MongoDB...`);
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
        existing = users[key];
        console.log(`[auth_user] ✓ Loaded user ${key} from MongoDB (taskCount: ${existing.taskCount})`);
      }
    } else {
      console.log(`[auth_user] User ${key} already in memory (taskCount: ${existing.taskCount})`);
    }

    if (existing) {
      const result = await verifyLogin(email, password);
      if (!result.ok) {
        if (result.reason === "wrong_password") {
          return socket.emit("auth_error", "Incorrect password for this email. Please try again.");
        }
        return socket.emit("auth_error", "Authentication failed.");
      }
      existing = result.user;
       if (name && name.trim() && name.trim() !== existing.name) {
        console.log(`[auth_user] Updating name for ${key}: "${existing.name}" → "${name.trim()}"`);
        existing.name = name.trim();
        await saveUserToDB(email);
      }
       if (existing.resetAt && new Date() > new Date(existing.resetAt)) {
        existing.taskCount = 0;
        existing.resetAt = null;
        existing.taskIds = [];
        await saveUserToDB(email);
        console.log(`[auth_user] Reset task count for ${key}`);
      }
      ensureProValidity(email);
      const { count, resetAt } = getUserTaskData(email);
      console.log(`[auth_user] Sending auth_success to client with taskCount=${count}`);
      return socket.emit("auth_success", {
        email: key,
        name:  existing.name,
        isPro: existing.isPro,
        taskCount: count,
        resetAt,
        proExpiresAt: existing.proExpiresAt || null,
      });
    } else {
       if (!name || !name.trim()) {
        return socket.emit("auth_error", "Name is required for new accounts.");
      }
      devLog(`[auth_user] Creating new user ${key}`);
      const { user } = await registerUser(email, name.trim(), password);
      return socket.emit("auth_success", {
        email:     key,
        name:      user.name,
        isPro:     false,
        taskCount: 0,
        resetAt:   null,
        proExpiresAt: null,
      });
    }
  });

  socket.on("check_pro_status", ({ email, proPin }) => {
    const key  = email?.toLowerCase().trim();
    const user = users[key];
    if (email) ensureProValidity(email);
    if (user && user.isPro) {
      socket.emit("pro_status", { isPro: true });
    } else {
      socket.emit("pro_status", { isPro: false });
    }
  });

  socket.on("set_user_pro", async ({ email, proPin }) => {
    const key = email?.toLowerCase().trim();
    if (!key || !proPin) {
      return socket.emit("pro_activate_error", "Valid email and activation PIN are required.");
    }
    const pinOk = await verifyProPinWithWorker(proPin);
    if (!pinOk) {
      return socket.emit("pro_activate_error", "Invalid or expired activation PIN.");
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
    markUserPro(email, String(proPin).trim());
    const { count, resetAt } = getUserTaskData(email);
    const userRec = users[key];
    socket.emit("pro_activated", {
      taskCount: count,
      resetAt,
      isPro: true,
      proExpiresAt: userRec?.proExpiresAt || null,
    });
  });

  socket.on("deactivate_pro", async ({ email }) => {
    const key = email?.toLowerCase().trim();
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
      console.error("[deactivate_pro] Error:", err.message);
      socket.emit("pro_deactivate_error", "Failed to deactivate Pro.");
    }
  });


  socket.on("join_workspace", async (data) => {
    devLog(`[join_workspace] ${data?.workspaceName} | creating=${!!data?.isCreating}`);
    const { workspaceName, password, projectName, userName, isCreating } = data;
     const rawEmail = data.userEmail || data.email || (data.user && data.user.email) || "";
    const email = rawEmail.trim().toLowerCase();
    devLog(`[join_workspace] ${userName} @ ${workspaceName}`);
    if (!workspaceName || !password || !userName || !email) {
      console.error(`[join_workspace] ✗ Missing required fields!`, { workspaceName: !!workspaceName, password: !!password, userName: !!userName, email: !!email });
      return socket.emit("error_msg", "Missing required fields.");
    }

    let existingWs = workspaces[workspaceName];


    if (!existingWs && !isCreating) {
      console.log(`[join_workspace] Workspace not in memory, attempting to load from MongoDB...`);
      const loadedWs = await loadRoomFromDB(workspaceName);
      if (loadedWs) {
        workspaces[workspaceName] = loadedWs;
        existingWs = loadedWs;
        console.log(`[join_workspace] ✓ Hydrated ${workspaceName} from MongoDB`);
      } else {
        console.log(`[join_workspace] ✗ Workspace not found in MongoDB either`);
      }
    }

    if (!isCreating) {
      if (!existingWs) {
        return socket.emit("error_msg", `Workspace not found: "${workspaceName}" does not exist. Ask your admin for the correct workspace name, or create a new workspace.`);
      }
      if (!(await verifyWorkspacePin(password, existingWs.password))) {
        return socket.emit("error_msg", `Wrong PIN for workspace "${workspaceName}". Ask your workspace admin for the correct 6-digit PIN.`);
      }
      await upgradeWorkspacePinIfNeeded(existingWs, workspaceName, password);
    }

    if (isCreating) {
      if (existingWs) {
        if (!(await verifyWorkspacePin(password, existingWs.password))) {
          return socket.emit("error_msg", `Workspace "${workspaceName}" already exists with a different PIN. Choose a different name or use the correct PIN.`);
        }
        await upgradeWorkspacePinIfNeeded(existingWs, workspaceName, password);
        devLog(`[join_workspace] joining existing workspace as admin`);
      } else {
        workspaces[workspaceName] = {
          password: await hashSecret(password),
          projectName: projectName || workspaceName,
          creatorEmail: email.toLowerCase().trim(),
          tasks:       [],
          history:     [],
          members:     [],
          sockets:     new Map(),
        };
        devLog(`[join_workspace] created ${workspaceName}`);
        await saveRoomToDB(workspaceName);
      }
    }

    const ws   = workspaces[workspaceName];
    const normalizedUserEmail = email.trim().toLowerCase();
    const storedCreatorEmail = (ws.creatorEmail || "").trim().toLowerCase();
    
    console.log(`DEBUG: Role Assignment Check`);
    console.log(`  User Email (normalized): "${normalizedUserEmail}"`);
    console.log(`  Stored Creator Email:    "${storedCreatorEmail}"`);
    console.log(`  isCreating flag:         ${isCreating}`);
    console.log(`  Creator email exists:    ${!!storedCreatorEmail}`);
    

    let role = "member";
    if (isCreating) {
      role = "admin";
      console.log(`🎯 Role = ADMIN (isCreating=true)`);
    } else if (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) {
      role = "admin";
      console.log(`🎯 Role = ADMIN (Email match found! "${normalizedUserEmail}" === "${storedCreatorEmail}")`);
    } else {
      console.log(`⚠️ Role = MEMBER (Emails do not match or storedCreatorEmail is empty)`);
      if (!storedCreatorEmail) {
        console.warn(`⚠️  WARNING: storedCreatorEmail is empty! This might cause issues on rejoin.`);
      }
    }

    ws.sockets.set(socket.id, { name: userName, role, email });
    socket.join(workspaceName);
    console.log(`[join_workspace] Added ${userName} to workspace. Total sockets in workspace: ${ws.sockets.size}`);
     const memberKey = email.toLowerCase().trim();
    const existingMemberIndex = ws.members.findIndex(
      m => m.email && m.email.toLowerCase().trim() === memberKey
    );
    
    if (existingMemberIndex !== -1) {

      const existingMember = ws.members[existingMemberIndex];
      if (existingMember.name !== userName) {
        console.log(`[join_workspace] Updated member name: "${existingMember.name}" → "${userName}"`);
        existingMember.name = userName;
      }
      if (role === "admin") {
        existingMember.role = "admin";
      }
    } else {
     
      ws.members.push({ name: userName, role, email: memberKey, joinedAt: new Date().toISOString() });
    }

    pushHistory(ws, {
      action:    "joined the workspace",
      userName,
      userRole:  role,
      taskTitle: null,
      timestamp: new Date().toISOString(),
    });

    await saveRoomToDB(workspaceName);

    const userRec = await ensureUserLoaded(email);
    ensureProValidity(email);
    const refreshedUser = users[email.toLowerCase().trim()];
    const { count, resetAt } = getUserTaskData(email);

    socket.emit("load_workspace", {
      tasks:       ws.tasks,
      projectName: ws.projectName,
      role,
      history:     ws.history,
      members:     ws.members,
      taskCount:   count,
      resetAt,
      isPro:       refreshedUser?.isPro || false,
      proExpiresAt: refreshedUser?.proExpiresAt || null,
    });

    broadcastUsers(workspaceName);
    broadcastMembers(workspaceName);
    socket.to(workspaceName).emit("history_update", ws.history);

    console.log(`[join] ${userName} (${email}) → ${workspaceName} (${role})`);
  });

  socket.on("rejoin_workspace", async (data) => {
    console.log(`\n[rejoin_workspace] ════════════════════════════════════════════`);
    console.log(`DEBUG: Full payload received:`, JSON.stringify(data, null, 2));
    
    const { workspaceName, userName } = data;
     const rawEmail = data.userEmail || data.email || (data.user && data.user.email) || "";
    const email = rawEmail.trim().toLowerCase();
    console.log(`DEBUG: Extracted email from payload - Raw: "${rawEmail}" | Normalized: "${email}"`);
    
    console.log(`  User: ${userName} | Workspace: ${workspaceName} | Email: ${email} | SocketID: ${socket.id}`);
    
    if (!workspaceName || !userName || !email) {
      console.error(`[rejoin_workspace] ✗ Missing required fields!`, { workspaceName: !!workspaceName, userName: !!userName, email: !!email });
      return socket.emit("error_msg", "Missing required fields for rejoin.");
    }

    let ws = workspaces[workspaceName];
    console.log(`[rejoin_workspace] Workspace found in memory: ${!!ws}`);
     if (!ws) {
      console.log(`[rejoin_workspace] Workspace not in memory, attempting to load from MongoDB...`);
      const loadedWs = await loadRoomFromDB(workspaceName);
      if (loadedWs) {
        workspaces[workspaceName] = loadedWs;
        ws = loadedWs;
        console.log(`[rejoin_workspace] ✓ Hydrated ${workspaceName} from MongoDB`);
      }
    }
    
    if (!ws) {
      console.error(`[rejoin_workspace] Workspace "${workspaceName}" not found!`);
      return socket.emit("error_msg", `Workspace "${workspaceName}" not found.`);
    }
     const normalizedUserEmail = email.trim().toLowerCase();
    const storedCreatorEmail = (ws.creatorEmail || "").trim().toLowerCase();
    
    console.log(`DEBUG: Role Assignment Check`);
    console.log(`  User Email (normalized): "${normalizedUserEmail}"`);
    console.log(`  Stored Creator Email:    "${storedCreatorEmail}"`);
    console.log(`  Creator email exists:    ${!!storedCreatorEmail}`);
    
    let role = "member";
    if (storedCreatorEmail && storedCreatorEmail === normalizedUserEmail) {
      role = "admin";
      console.log(`🎯 Role = ADMIN (Email match found! "${normalizedUserEmail}" === "${storedCreatorEmail}")`);
    } else {
      console.log(`⚠️ Role = MEMBER (Emails do not match or storedCreatorEmail is empty)`);
      if (!storedCreatorEmail) {
        console.warn(`⚠️  CRITICAL: storedCreatorEmail is EMPTY! Admin role cannot be restored on rejoin.`);
      }
    }
     ws.sockets.set(socket.id, { name: userName, role, email });
    socket.join(workspaceName);
    console.log(`[rejoin_workspace] Rejoined ${userName} to workspace. Total sockets: ${ws.sockets.size}`);
     const memberKey = email.toLowerCase().trim();
    const existingMember = ws.members.find(
      m => m.email && m.email.toLowerCase().trim() === memberKey
    );
    if (existingMember && existingMember.name !== userName) {
      console.log(`[rejoin_workspace] Updated member name: "${existingMember.name}" → "${userName}"`);
      existingMember.name = userName;
       await saveRoomToDB(workspaceName);
    }
     const userRec = await ensureUserLoaded(email);
    ensureProValidity(email);
    const refreshedUser = users[email.toLowerCase().trim()];
    const { count, resetAt } = getUserTaskData(email);

    console.log(`[rejoin_workspace] Emitting load_workspace with taskCount=${count}, resetAt=${resetAt}, isPro=${userRec?.isPro || false}`);
    socket.emit("load_workspace", {
      tasks:       ws.tasks,
      projectName: ws.projectName,
      role,
      history:     ws.history,
      members:     ws.members,
      taskCount:   count,
      resetAt,
      isPro:       refreshedUser?.isPro || false,
      proExpiresAt: refreshedUser?.proExpiresAt || null,
    });
    console.log(`[rejoin_workspace] load_workspace emitted successfully\n`);

    broadcastUsers(workspaceName);
    broadcastMembers(workspaceName);
    socket.to(workspaceName).emit("history_update", ws.history);
  });
   socket.on("update_tasks", async ({ workspaceName, updatedTasks, actionMeta, newTaskId }) => {
    const ws = workspaces[workspaceName];
    if (!ws) return;

    const user = ws.sockets.get(socket.id);
    if (!user) return;
    if (user.role !== "member" && user.role !== "admin") {
      return socket.emit("permission_denied", "Viewers cannot modify tasks.");
    }
     const userRec = await ensureUserLoaded(user.email);
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
      console.log(`[update_tasks] Emitting task_count_update: taskCount=${newCount}`);
      socket.emit("task_count_update", { taskCount: newCount, resetAt });
    }

    if (actionMeta) {
      pushHistory(ws, {
        action:    actionMeta.action,
        taskTitle: actionMeta.taskTitle || null,
        userName:  user.name,
        userRole:  user.role,
        timestamp: new Date().toISOString(),
      });
    }
     await saveRoomToDB(workspaceName);

    socket.to(workspaceName).emit("receive_update", {
      tasks:   ws.tasks,
      history: ws.history,
    });

    socket.emit("history_update", ws.history);
  });
   socket.on("check_task_limit", async ({ email }) => {
    if (!email) return;
    const key = email.toLowerCase().trim();
    let ws_user = users[key];
     if (!ws_user) {
      console.log(`[check_task_limit] User ${key} not in memory, attempting to load...`);
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
        console.log(`[check_task_limit] ✓ Loaded user ${key} from MongoDB (taskCount: ${ws_user.taskCount})`);
      }
    }
    
    const { count, resetAt } = getUserTaskData(email);
    const limit = ws_user?.isPro ? PRO_TASK_LIMIT : FREE_TASK_LIMIT;
    console.log(`[check_task_limit] ${key} | taskCount: ${count} | limit: ${limit} | canAdd: ${count < limit}`);
    socket.emit("task_limit_status", {
      taskCount: count,
      resetAt,
      limit,
      isPro: ws_user?.isPro || false,
      canAdd: count < limit,
    });
  });
   socket.on("typing_start", ({ workspaceName, context }) => {
    const ws = workspaces[workspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user) return;
    socket.to(workspaceName).emit("typing_update", { name: user.name, role: user.role, context });
  });

  socket.on("typing_stop", ({ workspaceName }) => {
    const ws = workspaces[workspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user) return;
    socket.to(workspaceName).emit("typing_clear", { name: user.name });
  });
   socket.on("disconnect", () => {
    console.log(`[disconnect] ${socket.id}`);
    for (const [wsName, ws] of Object.entries(workspaces)) {
      if (ws.sockets.has(socket.id)) {
        const user = ws.sockets.get(socket.id);
        ws.sockets.delete(socket.id);
        socket.to(wsName).emit("typing_clear", { name: user.name });
        const stillOnline = Array.from(ws.sockets.values()).some(
          (u) => (u.email || "").toLowerCase() === (user.email || "").toLowerCase()
        );
        if (!stillOnline) {
          pushHistory(ws, {
            action: "left the workspace",
            userName: user.name,
            userRole: user.role,
            taskTitle: null,
            timestamp: new Date().toISOString(),
          });
          saveRoomToDB(wsName);
          io.to(wsName).emit("history_update", ws.history);
        }
        broadcastUsers(wsName);
        break;
      }
    }
  });
   socket.on("delete_workspace", async ({ workspaceName, email }) => {
    console.log(`[delete_workspace] User: ${email} | Workspace: ${workspaceName}`);
    
    const ws = workspaces[workspaceName];
    if (!ws) {
      return socket.emit("error_msg", "Workspace not found.");
    }

    const user = ws.sockets.get(socket.id);
    if (!user || user.role !== "admin") {
      return socket.emit("error_msg", "Only admins can delete workspaces.");
    }
     delete workspaces[workspaceName];
    console.log(`[delete_workspace] ✓ Deleted ${workspaceName} from memory`);
     if (mongoConnected) {
      try {
        const collection = mongoose.connection.db.collection("workspaces");
        await collection.deleteOne({ workspaceName });
        console.log(`[delete_workspace] ✓ Deleted ${workspaceName} from MongoDB`);
      } catch (err) {
        console.error(`[delete_workspace] Error deleting from DB:`, err.message);
      }
    }
     io.to(workspaceName).emit("error_msg", `Workspace "${workspaceName}" has been deleted by admin.`);
    socket.leave(workspaceName);
    
    socket.emit("workspace_deleted_success");
  });
   socket.on("clear_history", async ({ workspaceName }) => {
    const ws = workspaces[workspaceName];
    if (!ws) return;
    const user = ws.sockets.get(socket.id);
    if (!user || user.role !== "admin") {
      return socket.emit("permission_denied", "Only admins can clear history.");
    }
    ws.history = [];
    await saveRoomToDB(workspaceName);
    io.to(workspaceName).emit("history_update", ws.history);
    socket.emit("history_update", ws.history); // ← ENSURE sender gets it too
    socket.emit("history_cleared");
  });
});
 const PORT = process.env.PORT || 3001;

async function startServer() {
   await connectDB();
  
  server.listen(PORT, () => {
    console.log(`[Server] ✓ SyncBoard listening on :${PORT}`);
    if (mongoConnected) {
      console.log(`[Server] ✓ MongoDB persistence enabled`);
    } else {
      console.log(`[Server] ⚠️  MongoDB not available - running in memory-only mode`);
    }
  });
}

startServer().catch(err => {
  console.error("[startServer] Fatal error:", err.message);
  process.exit(1);
});
