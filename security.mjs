import bcrypt from "bcryptjs";
import { createHmac } from "crypto";

const BCRYPT_ROUNDS = 10;

export function isBcryptHash(value) {
  return typeof value === "string" && /^\$2[aby]\$/.test(value);
}

/** @deprecated Legacy — used only to verify & migrate existing accounts */
export function legacyHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(36);
}

export async function hashSecret(plain) {
  return bcrypt.hash(String(plain).trim(), BCRYPT_ROUNDS);
}

export async function verifyUserPassword(plain, storedHash) {
  if (!storedHash) return { ok: false };
  const trimmed = String(plain).trim();

  if (isBcryptHash(storedHash)) {
    const ok = await bcrypt.compare(trimmed, storedHash);
    return { ok, upgraded: false };
  }

  if (legacyHash(trimmed) === storedHash) {
    return { ok: true, upgraded: true, newHash: await hashSecret(trimmed) };
  }

  return { ok: false };
}

export async function verifyWorkspacePin(plain, stored) {
  if (stored == null || stored === "") return false;
  const trimmed = String(plain).trim();

  if (isBcryptHash(stored)) {
    return bcrypt.compare(trimmed, stored);
  }

  return stored === trimmed;
}

export async function maybeUpgradeWorkspacePin(plain, stored) {
  if (isBcryptHash(stored)) return stored;
  const ok = await verifyWorkspacePin(plain, stored);
  if (!ok) return stored;
  return hashSecret(plain);
}

export async function verifyProPinWithWorker(pin) {
  const workerUrl = (process.env.WORKER_URL || "").replace(/\/$/, "");
  if (!pin) return false;
  if (!workerUrl) {
    return process.env.NODE_ENV !== "production";
  }

  try {
    const res = await fetch(`${workerUrl}/api/verify-pin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin: String(pin).trim() }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    return !!data.valid;
  } catch {
    return false;
  }
}

export function parseAllowedOrigins() {
  const raw = process.env.CLIENT_URL || "";
  const defaults = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://syncboardpro.netlify.app",
  ];

  return [...new Set([
    ...raw.split(",").map((s) => s.trim()).filter(Boolean),
    ...defaults,
  ])];
}

export function isOriginAllowed(origin, allowed) {
  if (!origin) return true;
  if (allowed.includes("*")) return true;
  return allowed.includes(origin);
}

export function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function verifyToken(token, secret) {
  const raw = String(token || "").trim();
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = createHmac("sha256", secret).update(body).digest("base64url");
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (payload?.exp && Date.now() > Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}