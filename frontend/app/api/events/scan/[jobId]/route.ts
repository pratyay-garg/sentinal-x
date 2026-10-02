import { cookies } from "next/headers";

import { SESSION_COOKIE, verifySession } from "@/lib/auth";
import { backendUrl } from "@/lib/proxy";

type Context = { params: Promise<{ jobId: string }> };

export async function GET(request: Request, context: Context) {
  const jar = await cookies();
  if (!verifySession(jar.get(SESSION_COOKIE)?.value)) {
    return Response.json({ detail: "authentication required" }, { status: 401 });
  }
  const jobId = (await context.params).jobId;
  if (!/^[0-9a-f-]{36}$/i.test(jobId)) {
    return Response.json({ detail: "invalid job id" }, { status: 422 });
  }
  const apiKey = process.env.DISCOVERY_API_KEY;
  if (!apiKey) return Response.json({ detail: "backend key missing" }, { status: 503 });
  const encoder = new TextEncoder();
  let cursor = 0;
  const stream = new ReadableStream({
    async start(controller) {
      const deadline = Date.now() + 5 * 60_000;
      try {
        while (!request.signal.aborted && Date.now() < deadline) {
          const url = backendUrl(`api/v1/discovery/scans/${jobId}/events`, `?after=${cursor}`);
          const response = await fetch(url, { headers: { "X-API-Key": apiKey }, cache: "no-store" });
          if (!response.ok) {
            controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ status: response.status })}\n\n`));
            break;
          }
          const events = (await response.json()) as Array<{ seq?: number; event?: string; data?: unknown; created_at?: string }>;
          for (const event of events) {
            if (typeof event.seq === "number") cursor = Math.max(cursor, event.seq);
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
          }
          controller.enqueue(encoder.encode(": keepalive\n\n"));
          await new Promise((resolve) => setTimeout(resolve, 1500));
        }
      } catch {
        controller.enqueue(encoder.encode(`event: error\ndata: {"detail":"event stream interrupted"}\n\n`));
      } finally {
        controller.close();
      }
    },
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
