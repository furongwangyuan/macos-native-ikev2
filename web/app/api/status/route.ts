import { getDb } from "@/db";
import { latestSnapshot } from "@/db/schema";

export const dynamic = "force-dynamic";
const empty = {
  schema_version: 3, registry_revision: null, observed_at: null,
  collector: { state: "unavailable", started_at: null }, server: { state: "unknown" },
  coverage: { kind: "ipsec_child_counters", totals_scope: "calendar_day", timezone: "Asia/Kuala_Lumpur",
    day: null, day_started_at: null, observed_since: null,
    limitation: "只显示马来西亚时间当日已采样的小计；采样缺口不会估填，也不代表宽带计费流量。" },
  devices: [],
};

export async function GET() {
  // The owner-private Sites access policy protects browser and service access.
  const rows = await getDb().select().from(latestSnapshot).limit(1);
  return new Response(rows[0]?.payload ?? JSON.stringify(empty), {
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
  });
}
