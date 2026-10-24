import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "../db/schema.ts";
import { normalizeSnapshot } from "../public/monitor/model.mjs";
import { historyRange, historyPoint, ingestSnapshot, loadHistory, DAY_MS } from "../lib/usage-history.mjs";

const now = Date.parse("2026-10-23T04:10:20.000Z");
function snapshot(ms = now, overrides = {}) {
  const day = new Date(ms + 8 * 3600000).toISOString().slice(0, 10);
  const midnight = new Date(Date.parse(`${day}T00:00:00+08:00`)).toISOString();
  return normalizeSnapshot({ schema_version: 3, registry_revision: 1, observed_at: new Date(ms).toISOString(),
    collector: { state: "ok", started_at: midnight }, server: { state: "running" },
    coverage: { kind: "ipsec_child_counters", totals_scope: "calendar_day", timezone: "Asia/Kuala_Lumpur", day,
      day_started_at: midnight, observed_since: midnight, limitation: "仅实测累计值" },
    devices: [{ id: "device02", name: "设备二", registration_state: "enabled", state: "offline", connected_since: null,
      rate_window_ms: null, upload_bps: null, download_bps: null, upload_bytes: "120", download_bytes: "300",
      totals_since: midnight, counter_epoch: `daily_epoch_${day.replaceAll("-", "")}`, counter_state: "partial" }], ...overrides });
}
function database() {
  const sqlite = new DatabaseSync(":memory:");
  // Apply the actual immutable migrations, not a handwritten test schema.
  for (const name of ["0000_long_steel_serpent.sql", "0001_certain_xavin.sql"]) sqlite.exec(readFileSync(new URL(`../drizzle/${name}`, import.meta.url), "utf8"));
  const statements = [];
  function prepared(query, args = []) {
    return { bind: (...values) => prepared(query, values),
      execute() { statements.push(query); return { results: sqlite.prepare(query).all(...args) }; },
      async all() { return this.execute(); },
      async run() { statements.push(query); return { results: [], meta: sqlite.prepare(query).run(...args) }; },
      async raw() { statements.push(query); const statement = sqlite.prepare(query); statement.setReturnArrays(true); return statement.all(...args); } };
  }
  const client = { prepare: prepared, async batch(items) {
    sqlite.exec("BEGIN");
    try { const result = items.map(item => item.execute()); sqlite.exec("COMMIT"); return result; }
    catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  } };
  return { db: drizzle(client, { schema }), sqlite, statements };
}

test("real SQLite keeps first minute immutable; older requests cannot fill missing minutes; latest still updates", async () => {
  const { db, sqlite, statements } = database();
  try {
    await ingestSnapshot(db, schema, snapshot(now), now);
    const first = sqlite.prepare("select * from usage_history").get();
    const newer = snapshot(now + 1000); newer.devices[0].upload_bytes = "200";
    await ingestSnapshot(db, schema, newer, now + 1000);
    assert.deepEqual(sqlite.prepare("select * from usage_history").get(), first);
    assert.equal(JSON.parse(sqlite.prepare("select payload from latest_snapshot").get().payload).devices[0].upload_bytes, "200");
    await ingestSnapshot(db, schema, snapshot(now - 30000), now + 1000); // preceding minute, still fresh, but out of order
    assert.equal(sqlite.prepare("select count(*) n from usage_history").get().n, 1);
    assert.equal(statements.filter(value => value.startsWith("delete from")).length, 1);
    await ingestSnapshot(db, schema, snapshot(now + 60000), now + 60000);
    assert.equal(sqlite.prepare("select count(*) n from usage_history").get().n, 2);
    const result = JSON.parse(await loadHistory(db, schema, null, now + 60000));
    assert.equal(result.started_at, new Date(now).toISOString());
    assert.equal(result.points[0].devices[0].upload_bytes, "120");
    assert.deepEqual(Object.keys(result.points[0].devices[0]).sort(), ["id", "name", "upload_bytes", "download_bytes", "counter_epoch", "counter_state", "totals_since"].sort());
    assert.deepEqual(JSON.parse(await loadHistory(db, schema, "2026-10-22", now)).points, []);
  } finally { sqlite.close(); }
});

test("unavailable, stale, future snapshots produce no history; unknown counters stay null", async () => {
  const { db, sqlite } = database();
  try {
    for (const value of [snapshot(now - 60001), snapshot(now + 1), snapshot(now, { collector: { state: "unavailable", started_at: null } })]) {
      await ingestSnapshot(db, schema, value, now);
    }
    assert.equal(sqlite.prepare("select count(*) n from usage_history").get().n, 0);
    const value = snapshot(now + 60000);
    Object.assign(value.devices[0], { upload_bytes: null, download_bytes: null, totals_since: null, counter_epoch: null, counter_state: "unavailable" });
    await ingestSnapshot(db, schema, value, now + 60000);
    const response = JSON.parse(await loadHistory(db, schema, null, now + 60000));
    assert.equal(response.points.length, 1);
    assert.equal(response.points[0].devices[0].upload_bytes, null);
  } finally { sqlite.close(); }
});

test("Malaysia midnight, seven calendar days, real timestamps and deletion only on an inserted minute", async () => {
  const { db, sqlite, statements } = database();
  try {
    const midnight = Date.parse("2026-10-23T16:00:00.000Z"); // Oct 24 locally
    assert.equal(historyRange(null, midnight - 1).day, "2026-10-23");
    assert.equal(historyRange(null, midnight).day, "2026-10-24");
    assert.throws(() => historyRange("2026-10-17", midnight), /history_day/);
    for (const day of ["2026-02-30", "2026-10-25", "2026-1-24", "", "2026-10-24T00:00:00Z"]) assert.throws(() => historyRange(day, midnight), /history_day/);
    await ingestSnapshot(db, schema, snapshot(midnight - 7 * DAY_MS), midnight - 7 * DAY_MS);
    await ingestSnapshot(db, schema, snapshot(midnight - 6 * DAY_MS), midnight - 6 * DAY_MS);
    await ingestSnapshot(db, schema, snapshot(midnight), midnight);
    assert.equal(sqlite.prepare("select count(*) n from usage_history").get().n, 2);
    const result = JSON.parse(await loadHistory(db, schema, null, midnight));
    assert.equal(result.day, "2026-10-24"); assert.equal(result.points.length, 1);
    assert.equal(result.started_at, new Date(midnight - 6 * DAY_MS).toISOString());
    const count = statements.filter(value => value.startsWith("delete from")).length;
    await ingestSnapshot(db, schema, snapshot(midnight + 1000), midnight + 1000);
    assert.equal(statements.filter(value => value.startsWith("delete from")).length, count);
  } finally { sqlite.close(); }
});

test("empty history is empty, corrupt rows and whole-day oversized responses fail rather than returning zeros", async () => {
  const { db, sqlite } = database();
  try {
    assert.deepEqual(JSON.parse(await loadHistory(db, schema, null, now)), { version: 1, day: "2026-10-23", timezone: "Asia/Kuala_Lumpur", interval_seconds: 60, started_at: null, points: [] });
    const base = historyRange(null, now).start;
    const insert = sqlite.prepare("insert into usage_history values (?, ?, ?)");
    insert.run(base, base, '{"observed_at":"broken","devices":[]}');
    await assert.rejects(loadHistory(db, schema, null, now), /history_point/);
    sqlite.exec("delete from usage_history");
    for (let i = 0; i < 1440; i++) {
      const value = snapshot(base + i * 60000);
      value.devices = Array.from({ length: 16 }, (_, j) => ({ ...value.devices[0], id: `device${j}`, name: "🙂".repeat(80) }));
      const point = historyPoint(value, base + i * 60000);
      insert.run(point.minuteMs, point.observedMs, point.payload);
    }
    await assert.rejects(loadHistory(db, schema, null, now), /history_response_size/);
  } finally { sqlite.close(); }
});
