// SyncBoard server security tests. Run from a scratch folder (NOT the repo):
//   npm init -y && npm i socket.io-client
//   node socket-tests.mjs
// Optional env: API (default live backend), PRO_EMAIL + PRO_PASSWORD (your own Pro account, enables T3).
// Creates throwaway users/workspaces named sbtest-*. Delete them in Atlas afterwards.
import { io } from "socket.io-client";

const API = process.env.API || "https://dropstream-backend.onrender.com";
const RUN = Math.random().toString(36).slice(2, 8);
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const report = (name, pass, detail) => {
  results.push({ name, pass });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? "  -> " + detail : ""}`);
};

function connect(cookie) {
  return new Promise((resolve, reject) => {
    const s = io(API, {
      transports: ["websocket"],
      extraHeaders: cookie ? { cookie } : {},
      reconnection: false,
      timeout: 60000,
    });
    s.events = [];
    s.onAny((ev, payload) => s.events.push({ ev, payload }));
    s.on("connect", () => resolve(s));
    s.on("connect_error", (e) => reject(e));
  });
}
const waitFor = async (s, ev, ms = 8000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const hit = s.events.find((e) => e.ev === ev);
    if (hit) return hit.payload;
    await sleep(100);
  }
  return null;
};
const clear = (s) => (s.events.length = 0);

async function exchange(ticket) {
  const r = await fetch(`${API}/api/session/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ticket }),
  });
  const sc = r.headers.get("set-cookie") || "";
  const m = sc.match(/sb_session=[^;]+/);
  return { status: r.status, cookie: m ? m[0] : null };
}
async function profileStatus(cookie) {
  const r = await fetch(`${API}/api/user/profile`, { headers: { cookie } });
  return r.status;
}

// Log in / register through auth_user, get a real cookie.
async function account(email, password, name) {
  const s = await connect();
  s.emit("auth_user", { email, password, name });
  const ok = await waitFor(s, "auth_success");
  s.close();
  if (!ok?.sessionTicket) throw new Error("auth failed for " + email);
  const { cookie } = await exchange(ok.sessionTicket);
  if (!cookie) throw new Error("no cookie for " + email);
  return { email: email.toLowerCase(), cookie };
}
// Create a workspace as this account (uses join_workspace, the app's real path).
async function createWs(acc, wsName, wsPass) {
  const s = await connect(acc.cookie);
  s.emit("join_workspace", {
    workspaceName: wsName, password: wsPass, isCreating: true,
    email: acc.email, name: "tester", projectName: wsName,
  });
  const loaded = await waitFor(s, "load_workspace");
  if (!loaded) throw new Error("workspace create failed: " + JSON.stringify(s.events.slice(-3)));
  return s;
}
const img = (chars) => "data:image/png;base64," + "A".repeat(chars - 22);
const task = (id, image) => ({ id, title: "t" + id, description: "", status: "todo", image: image || null });

const pw = "Sbtest-" + RUN + "-pass1";
const A = { email: `sbtest-a-${RUN}@example.com`, name: "A" };
const B = { email: `sbtest-b-${RUN}@example.com`, name: "B" };
const WS = `sbtest-${RUN}`;
const WSPASS = "wspass-" + RUN + "-xx";

try {
  const a = await account(A.email, pw, A.name);
  const b = await account(B.email, pw, B.name);
  const sa = await createWs(a, WS, WSPASS);

  // T0 - can someone with NO login get a session ticket for someone else's email?
  {
    const atk = await connect();
    atk.emit("join_workspace", {
      workspaceName: `sbtest-atk-${RUN}`, password: "attacker-pass-1", isCreating: true,
      email: a.email, name: "attacker", projectName: "x",
    });
    const t = await waitFor(atk, "session_ticket");
    if (!t?.ticket) {
      report("T0 forged identity: no ticket for an email you never logged in as", true);
    } else {
      const ex = await exchange(t.ticket);
      const prof = ex.cookie ? await profileStatus(ex.cookie) : null;
      report("T0 forged identity: no ticket for an email you never logged in as", false,
        `got ticket for ${a.email} without its password; cookie=${!!ex.cookie}; /api/user/profile=${prof}`);
    }
    atk.close();
  }

  // T1 - non-member (valid login, not in workspace) must not rejoin
  {
    const sb = await connect(b.cookie);
    sb.emit("rejoin_workspace", { workspaceName: WS, userName: "B", email: b.email });
    await sleep(3000);
    const loaded = sb.events.some((e) => e.ev === "load_workspace");
    const err = sb.events.find((e) => e.ev === "error_msg");
    report("T1 non-member rejoin rejected", !loaded, `load_workspace=${loaded}; error_msg=${err ? JSON.stringify(err.payload).slice(0, 60) : "none"}`);
    sb.close();
  }

  // T2 - free user cannot persist an image (server-side)
  {
    clear(sa);
    sa.emit("update_tasks", { workspaceName: WS, updatedTasks: [task("1", img(2000))] });
    const rej = await waitFor(sa, "task_image_rejected");
    const upd = await waitFor(sa, "receive_update");
    const stored = upd?.tasks?.[0]?.image;
    report("T2 free user image dropped", !!rej && !stored, `rejected=${JSON.stringify(rej)}; storedImage=${stored ? "YES" : "no"}`);
  }

  // T3 - Pro-only: size cap + board budget
  if (process.env.PRO_EMAIL && process.env.PRO_PASSWORD) {
    const p = await account(process.env.PRO_EMAIL, process.env.PRO_PASSWORD, "pro");
    const sp = await createWs(p, `sbtest-pro-${RUN}`, WSPASS);
    const wsP = `sbtest-pro-${RUN}`;
    clear(sp);
    sp.emit("update_tasks", { workspaceName: wsP, updatedTasks: [task("big", img(2_000_001))] });
    const r1 = await waitFor(sp, "task_image_rejected");
    report("T3a Pro: image over 2,000,000 chars rejected", r1?.tooLarge === 1, JSON.stringify(r1));

    let list = [];
    for (let i = 1; i <= 4; i++) {
      list = [...list, task("p" + i, img(1_900_000 + i))]; // unique strings; each valid
      clear(sp);
      sp.emit("update_tasks", { workspaceName: wsP, updatedTasks: list });
      await waitFor(sp, "receive_update", 20000);
    }
    clear(sp);
    sp.emit("update_tasks", { workspaceName: wsP, updatedTasks: [...list, task("p5", img(500_000))] });
    const r2 = await waitFor(sp, "task_image_rejected", 20000);
    const upd = await waitFor(sp, "receive_update", 20000);
    const p5 = upd?.tasks?.find((t) => t.id === "p5");
    report("T3b Pro: board budget (8,000,000) enforced", r2?.boardFull === 1 && !p5?.image, `rejected=${JSON.stringify(r2)}; p5Image=${p5?.image ? "kept" : "dropped"}`);
    sp.close();
  } else {
    console.log("SKIP  T3 (set PRO_EMAIL and PRO_PASSWORD to run size cap + board budget)");
  }
  // T4 - can a socket that never logged in change someone else's password? (run last: it changes A's password)
  {
    const atk = await connect();
    const newPw = "Hacked-" + RUN + "-9";
    atk.emit("set_account_password", { email: a.email, newPassword: newPw });
    const ok = await waitFor(atk, "set_password_success", 6000);
    let takeover = false;
    if (ok) {
      const s2 = await connect();
      s2.emit("auth_user", { email: a.email, password: newPw });
      takeover = !!(await waitFor(s2, "auth_success", 6000));
      s2.close();
    }
    report("T4 set_account_password requires being logged in as that account", !ok,
      ok ? `password changed without login; login with new password worked=${takeover}` : "rejected/no success event");
    atk.close();
  }
  sa.close();
} catch (e) {
  console.log("ERROR", e.message, e.cause || "");
}
console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed`);
process.exit(0);
