// server/boardContext.mjs
// Turns a workspace object into a compact, safe text snapshot for the AI.
// Pure function: no DB calls, no side effects.

const STATUS_LABELS = { todo: "To Do", "in-progress": "In Progress", done: "Done" };
const PRIORITY_LABELS = { low: "Low", medium: "Medium", high: "High" };
const PRIORITY_RANK = { high: 0, medium: 1, low: 2 };

const MAX_CONTEXT_CHARS = 20000; // ~5-6k tokens
const MAX_TASKS_LISTED = 200;

// Flatten user text: no newlines/control chars, no < >, capped length.
function clean(value, max) {
  const s = typeof value === "string" ? value : "";
  const flat = s
    .replace(/[\u0000-\u001F\u007F]+/g, " ")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return flat.length > max ? flat.slice(0, max - 1) + "…" : flat;
}

// Accepts "YYYY-MM-DD" or an ISO string, returns "YYYY-MM-DD" or null.
function dateOnly(value) {
  if (typeof value !== "string") return null;
  const m = value.match(/^(\d{4}-\d{2}-\d{2})/);
  if (!m) return null;
  return Number.isNaN(Date.parse(m[1] + "T00:00:00Z")) ? null : m[1];
}

// Only accepts a real IANA zone (e.g. "Asia/Karachi"); anything else falls back to UTC.
function safeTimeZone(tz) {
  if (typeof tz !== "string" || tz.length > 64) return "UTC";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return tz;
  } catch {
    return "UTC";
  }
}

function dateTime(value, tz = "UTC") {
  if (typeof value !== "string") return null;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  const p = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    }).formatToParts(new Date(t)).map((x) => [x.type, x.value])
  );
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`;
}

function dayDiff(a, b) {
  return Math.round((Date.parse(a + "T00:00:00Z") - Date.parse(b + "T00:00:00Z")) / 86400000);
}

function formatTask(t, n) {
  const parts = [`${n}. [${STATUS_LABELS[t.status] || "Unknown"}] [${PRIORITY_LABELS[t.priority] || "Unknown"}] "${t.title}"`];
  if (t.dueDate) parts.push(t.overdue ? `due ${t.dueDate} (OVERDUE by ${-t.daysLeft}d)` : `due ${t.dueDate}`);
  if (t.createdBy) parts.push(`created by ${t.createdBy}`);
  if (t.createdAt) parts.push(`created ${t.createdAt}`);
  if (t.isDone && (t.completedAt || t.completedBy)) {
    parts.push(`completed ${[t.completedAt, t.completedBy && `by ${t.completedBy}`].filter(Boolean).join(" ")}`);
  }

  if (t.hasImage) parts.push("has image attachment");
  if (t.description) parts.push(`description: ${t.description}`);
  return parts.join(" | ");
}

// Pro only. Newest first, max 10. Same data the Log panel shows.
function buildActivityLines(history, tz) {
  const list = Array.isArray(history) ? history : [];
  return list
    .filter((h) => h && typeof h === "object")
    .map((h) => ({
      ms: Date.parse(h.timestamp),
      when: dateTime(h.timestamp, tz),
      who: clean(h.userName, 40),
      what: clean(h.action, 150),
    }))
    .filter((h) => h.what)
    .sort((a, b) => (Number.isNaN(b.ms) ? 0 : b.ms) - (Number.isNaN(a.ms) ? 0 : a.ms))
    .slice(0, 10)
    .map((h) => `- ${h.when || "unknown time"} | ${h.who || "someone"} ${h.what}`);
}
function buildTeamLines(team) {
  const members = Array.isArray(team?.members) ? team.members : [];
  const online = Array.isArray(team?.online) ? team.online : [];
  const fmt = (list) =>
    list
      .slice(0, 50)
      .map((m) => `${clean(m?.name, 40) || "unknown"} (${clean(m?.role, 20) || "member"})`)
      .join(", ");
  return [
    `Team members (${members.length}): ${fmt(members) || "none"}`,
    `Online right now (${online.length}, snapshot at the time of the question): ${fmt(online) || "nobody"}`,
  ];
}

export function buildBoardContextWithRefs(ws, todayISO, { isPro = false, team = null, planUnknown = false, tz = "UTC" } = {}) {
  const today = dateOnly(todayISO) || new Date().toISOString().slice(0, 10);
  const zone = safeTimeZone(tz);
  const rawTasks = Array.isArray(ws?.tasks) ? ws.tasks : [];

  const tasks = rawTasks
    .filter((t) => t && typeof t === "object" && !Array.isArray(t))
    .map((t) => {
      const status = STATUS_LABELS[t.status] ? t.status : "unknown";
      const priority = PRIORITY_LABELS[t.priority] ? t.priority : "unknown";
      const dueDate = dateOnly(t.dueDate);
      const isDone = status === "done";
      const daysLeft = dueDate ? dayDiff(dueDate, today) : null;
      return {
        id: typeof t.id === "string" ? t.id : "",
        title: clean(t.title, 100) || "(untitled)",
        description: clean(t.description, 300),
        status,
        priority,
        dueDate,
        daysLeft,
        isDone,
        overdue: !isDone && daysLeft !== null && daysLeft < 0,
        createdBy: isPro ? clean(t.creatorName || t.addedBy, 40) : "",
        createdAt: dateTime(t.createdAt, zone),
        createdMs: Number.isNaN(Date.parse(t.createdAt)) ? 0 : Date.parse(t.createdAt),
        completedBy: isPro ? clean(t.completedBy, 40) : "",        
        completedAt: dateOnly(t.completedAt),

        hasImage: typeof t.image === "string" && t.image.length > 0, // image data itself is never copied
      };
    });

  // Counts are computed in code (models are bad at counting) over ALL tasks.
  const counts = { total: tasks.length, todo: 0, "in-progress": 0, done: 0, unknown: 0 };
  let overdue = 0, dueSoon = 0, highOpen = 0;
  for (const t of tasks) {
    counts[t.status]++;
    if (t.overdue) overdue++;
    if (!t.isDone && t.daysLeft !== null && t.daysLeft >= 0 && t.daysLeft <= 7) dueSoon++;
    if (!t.isDone && t.priority === "high") highOpen++;
  }

  // Open tasks first, overdue on top, then by due date, then priority.
  tasks.sort(
    (a, b) =>
      Number(a.isDone) - Number(b.isDone) ||
      Number(b.overdue) - Number(a.overdue) ||
      (a.dueDate || "9999").localeCompare(b.dueDate || "9999") ||
      (PRIORITY_RANK[a.priority] ?? 3) - (PRIORITY_RANK[b.priority] ?? 3)
  );


  const newest = tasks.reduce((best, t) => (t.createdMs > (best?.createdMs || 0) ? t : best), null);

   const activity = isPro ? buildActivityLines(ws?.history, zone) : [];

  let out = [
    `Board: "${clean(ws?.projectName, 80) || "Untitled"}"`,
    `Today: ${today}`,
    `All times below are in the user's local time zone (${zone}).`,
    `Columns: To Do, In Progress, Done`,
    `Counts: total ${counts.total} | To Do ${counts.todo} | In Progress ${counts["in-progress"]} | Done ${counts.done}` +
      (counts.unknown ? ` | Unknown status ${counts.unknown}` : "") +
      ` | Overdue ${overdue} | Due within 7 days ${dueSoon} | High priority not done ${highOpen}`,
    newest ? `Most recently created task: "${newest.title}" (created ${newest.createdAt})` : `Most recently created task: none`,
    ...(isPro
      ? [
          `Recent board activity (newest first, last 10 only, times in UTC; older activity is not available):`,
          ...(activity.length ? activity : [`(no activity recorded)`]),
          ...(team ? buildTeamLines(team) : [`Team list and online status are not available right now.`]),
        ]
      : [
          planUnknown
            ? `Plan could not be verified right now (temporary problem), so Pro-only data (who created or moved tasks, history, team, online) is withheld. If the user asks for it, say you can't check their plan right now and to try again in a moment. Do not say it is Pro-only.`
            : `Restricted (Pro only, not available on the Free plan): who created, moved or completed tasks, task history/last actions, and online/team members.`,
        ]),
    `Tasks (listed by urgency, NOT by creation time: not-done first, overdue on top, then done):`,
  ].join("\n");

  let listed = 0;
  const refs = []; // refs[n-1] = real task id of the task shown as number n
  for (const t of tasks) {
    if (listed >= MAX_TASKS_LISTED) break;
    const line = "\n" + formatTask(t, listed + 1);
    if (out.length + line.length > MAX_CONTEXT_CHARS) break;
    out += line;
    refs.push(t.id || null);
    listed++;
  }
  if (tasks.length === 0) out += "\n(no tasks)";
  else if (listed < tasks.length) out += `\n(${tasks.length - listed} more tasks not shown; counts above include all tasks.)`;
  return { text: out, refs };
}

// Old signature kept so the existing /api/ai/chat route keeps working.
export function buildBoardContext(ws, todayISO, opts) {
  return buildBoardContextWithRefs(ws, todayISO, opts).text;
}
