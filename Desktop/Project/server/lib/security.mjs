import bcrypt from "bcryptjs";

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
  const raw = process.env.CLIENT_URL || "http://localhost:5173";
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

export function isOriginAllowed(origin, allowed) {
  if (!origin) return true;
  if (allowed.includes("*")) return true;
  return allowed.includes(origin);
}
