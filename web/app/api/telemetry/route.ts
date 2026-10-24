import { getDb } from "@/db";
import { latestSnapshot, usageHistory } from "@/db/schema";
import { ingestSnapshot } from "@/lib/usage-history.mjs";
import { normalizeSnapshot } from "@/public/monitor/model.mjs";

export const dynamic = "force-dynamic";
const reply = (value: object, status = 200) => Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

export async function POST(request: Request) {
  // Sites dispatch checks OAI-Sites-Authorization for the Mac uploader.
  // It supplies no visitor identity; this shared endpoint stays owner-private.
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) return reply({ error: "origin" }, 403);
  if (!/^application\/json(?:;|$)/i.test(request.headers.get("content-type") ?? "")) return reply({ error: "content_type" }, 415);
  if (!request.body) return reply({ error: "body" }, 400);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) {
    const part = await reader.read(); if (part.done) break;
    size += part.value.byteLength;
    if (size > 131072) { await reader.cancel(); return reply({ error: "size" }, 413); }
    chunks.push(part.value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
  let snapshot;
  try { snapshot = normalizeSnapshot(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))); }
  catch { return reply({ error: "snapshot" }, 400); }
  const observedMs = snapshot.observed_at === null ? 0 : Date.parse(snapshot.observed_at);
  if (observedMs > Date.now() + 60000) return reply({ error: "future_observation" }, 400);
  await ingestSnapshot(getDb(), { latestSnapshot, usageHistory }, snapshot);
  return reply({ accepted: true, observed_at: snapshot.observed_at });
}
