import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const latestSnapshot = sqliteTable("latest_snapshot", {
  id: integer("id").primaryKey(),
  payload: text("payload").notNull(),
  observedMs: integer("observed_ms").notNull(),
  receivedAt: text("received_at").notNull(),
});

// One immutable first-valid snapshot per observed minute, not per device.
export const usageHistory = sqliteTable("usage_history", {
  minuteMs: integer("minute_ms").primaryKey(),
  observedMs: integer("observed_ms").notNull(),
  payload: text("payload").notNull(),
});
