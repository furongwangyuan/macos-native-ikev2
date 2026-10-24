import { and, asc, eq, gte, lt, sql } from "drizzle-orm";

export const TIMEZONE = "Asia/Kuala_Lumpur";
export const INTERVAL_MS = 60000;
export const DAY_MS = 86400000;
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_POINT_BYTES = 16384;
const encoder = new TextEncoder();
const fields = ["id", "name", "upload_bytes", "download_bytes", "counter_epoch", "counter_state", "totals_since"];
const iso = value => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

export function malaysiaDay(now = Date.now()) {
  return new Date(now + 8 * 3600000).toISOString().slice(0, 10);
}

export function historyRange(day, now = Date.now()) {
  const today = malaysiaDay(now);
  const first = Date.parse(`${today}T00:00:00+08:00`) - 6 * DAY_MS;
  const selected = day ?? today;
  const start = typeof selected === "string" && /^\d{4}-\d{2}-\d{2}$/.test(selected)
    ? Date.parse(`${selected}T00:00:00+08:00`) : NaN;
  if (!Number.isFinite(start) || malaysiaDay(start) !== selected || start < first || start > first + 6 * DAY_MS) {
    throw new RangeError("history_day");
  }
  return { day: selected, start, end: start + DAY_MS, first, retainedEnd: first + 7 * DAY_MS };
}

function validatePoint(point) {
  if (!exact(point, ["observed_at", "devices"]) || !iso(point.observed_at) || !Array.isArray(point.devices) || point.devices.length > 16) throw new TypeError("history_point");
  const ids = new Set();
  const day = malaysiaDay(Date.parse(point.observed_at));
  const midnight = Date.parse(`${day}T00:00:00+08:00`);
  for (const device of point.devices) {
    if (!exact(device, fields) || typeof device.id !== "string" || !/^[A-Za-z0-9_-]{1,48}$/.test(device.id) || ids.has(device.id) ||
        typeof device.name !== "string" || [...device.name].length < 1 || [...device.name].length > 80 || /[\u0000-\u001f\u007f]/u.test(device.name)) throw new TypeError("history_device");
    ids.add(device.id);
    if (device.counter_state === "unavailable") {
      if ([device.upload_bytes, device.download_bytes, device.counter_epoch, device.totals_since].some(value => value !== null)) throw new TypeError("history_unavailable");
    } else if (device.counter_state === "partial") {
      if ([device.upload_bytes, device.download_bytes].some(value => typeof value !== "string" || !/^(0|[1-9][0-9]{0,29})$/.test(value)) ||
          typeof device.counter_epoch !== "string" || !new RegExp(`^daily_[A-Za-z0-9_-]{1,48}_${day.replaceAll("-", "")}$`).test(device.counter_epoch) ||
          !iso(device.totals_since) || Date.parse(device.totals_since) < midnight || Date.parse(device.totals_since) > Date.parse(point.observed_at)) throw new TypeError("history_counter");
    } else throw new TypeError("history_counter_state");
  }
  return point;
}

// Caller supplies the existing normalizeSnapshot result. Never interpolate gaps
// or turn unavailable counters into zero; one row contains the entire snapshot.
export function historyPoint(snapshot, now) {
  const observedMs = snapshot.observed_at === null ? NaN : Date.parse(snapshot.observed_at);
  if (snapshot.collector.state !== "ok" || !Number.isFinite(observedMs) || observedMs > now || now - observedMs > 60000) return null;
  const point = validatePoint({ observed_at: snapshot.observed_at,
    devices: snapshot.devices.map(device => Object.fromEntries(fields.map(key => [key, device[key]]))) });
  const payload = JSON.stringify(point);
  if (encoder.encode(payload).byteLength > MAX_POINT_BYTES) throw new RangeError("history_point_size");
  return { minuteMs: Math.floor(observedMs / INTERVAL_MS) * INTERVAL_MS, observedMs, payload };
}

export async function ingestSnapshot(db, { latestSnapshot, usageHistory }, snapshot, now = Date.now()) {
  const observedMs = snapshot.observed_at === null ? 0 : Date.parse(snapshot.observed_at);
  const payload = JSON.stringify(snapshot), receivedAt = new Date(now).toISOString();
  const latest = db.insert(latestSnapshot).values({ id: 1, payload, observedMs, receivedAt })
    .onConflictDoUpdate({ target: latestSnapshot.id, set: { payload, observedMs, receivedAt },
      setWhere: sql`${latestSnapshot.observedMs} <= ${observedMs}` });
  const point = historyPoint(snapshot, now);
  if (!point) { await latest; return; }
  // D1 batch is atomic. After the existing latest update, only that current
  // observation may insert a minute. A late older request cannot backfill it.
  const insert = db.insert(usageHistory).select(db.select({
    minuteMs: sql`${point.minuteMs}`.as("minute_ms"),
    observedMs: sql`${point.observedMs}`.as("observed_ms"),
    payload: sql`${point.payload}`.as("payload"),
  }).from(latestSnapshot).where(and(eq(latestSnapshot.id, 1), eq(latestSnapshot.observedMs, observedMs))))
    .onConflictDoNothing({ target: usageHistory.minuteMs }).returning({ minuteMs: usageHistory.minuteMs });
  const [, inserted] = await db.batch([latest, insert]);
  // A duplicate second does not run DELETE. Physical retention is pruned on
  // the next newly inserted minute; reads always enforce the seven-day window.
  if (inserted.length) await db.delete(usageHistory).where(lt(usageHistory.minuteMs, historyRange(null, now).first));
}

export async function loadHistory(db, { usageHistory }, day, now = Date.now()) {
  const range = historyRange(day, now);
  const rows = await db.select().from(usageHistory)
    .where(and(gte(usageHistory.minuteMs, range.start), lt(usageHistory.minuteMs, range.end)))
    .orderBy(asc(usageHistory.minuteMs)).limit(1441);
  if (rows.length > 1440) throw new RangeError("history_point_count");
  // This is the first retained real observation, not a fabricated midnight or
  // a promise that the gaps between stored points were observed.
  const earliest = await db.select({ observedMs: usageHistory.observedMs }).from(usageHistory)
    .where(and(gte(usageHistory.minuteMs, range.first), lt(usageHistory.minuteMs, range.retainedEnd)))
    .orderBy(asc(usageHistory.minuteMs)).limit(1);
  let bytes = 256;
  const points = rows.map(row => {
    if (typeof row.payload !== "string") throw new TypeError("history_stored_point");
    const size = encoder.encode(row.payload).byteLength;
    bytes += size + 1;
    if (size > MAX_POINT_BYTES || bytes > MAX_RESPONSE_BYTES) throw new RangeError("history_response_size");
    const point = validatePoint(JSON.parse(row.payload));
    if (Date.parse(point.observed_at) !== row.observedMs || Math.floor(row.observedMs / INTERVAL_MS) * INTERVAL_MS !== row.minuteMs || malaysiaDay(row.observedMs) !== range.day) throw new TypeError("history_stored_binding");
    return point;
  });
  const started = earliest[0]?.observedMs;
  if (started !== undefined && (!Number.isSafeInteger(started) || started < range.first || started >= range.retainedEnd)) throw new TypeError("history_started_at");
  const result = { version: 1, day: range.day, timezone: TIMEZONE, interval_seconds: 60,
    started_at: started === undefined ? null : new Date(started).toISOString(), points };
  const body = JSON.stringify(result);
  if (encoder.encode(body).byteLength > MAX_RESPONSE_BYTES) throw new RangeError("history_response_size");
  return body;
}
