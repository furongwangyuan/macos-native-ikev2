import { getDb } from "@/db";
import { usageHistory } from "@/db/schema";
import { historyRange, loadHistory } from "@/lib/usage-history.mjs";

export const dynamic = "force-dynamic";
const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };

export async function GET(request: Request) {
  // Same owner-private Sites dispatch policy as /api/status. No new bearer
  // credentials, public sharing, visitor identifier or alternate auth path.
  const url = new URL(request.url), days = url.searchParams.getAll("day");
  const now = Date.now();
  if (days.length > 1 || [...url.searchParams.keys()].some(key => key !== "day")) return Response.json({ error: "history_day" }, { status: 400, headers });
  const day = days[0] ?? null;
  try { historyRange(day, now); }
  catch { return Response.json({ error: "history_day" }, { status: 400, headers }); }
  try {
    return new Response(await loadHistory(getDb(), { usageHistory }, day, now), { headers });
  } catch {
    // Storage errors/oversized or corrupt data are not presented as an empty day.
    return Response.json({ error: "history_unavailable" }, { status: 503, headers });
  }
}
