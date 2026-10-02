import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE, verifySession } from "@/lib/auth";
import { backendKey, backendUrl } from "@/lib/proxy";

type Context = { params: Promise<{ path: string[] }> };

async function proxy(request: NextRequest, context: Context) {
  const jar = await cookies();
  if (!verifySession(jar.get(SESSION_COOKIE)?.value)) {
    return NextResponse.json({ detail: "authentication required" }, { status: 401 });
  }
  const path = (await context.params).path.join("/");
  let url: URL;
  try {
    url = backendUrl(path, request.nextUrl.search);
  } catch (error) {
    return NextResponse.json(
      { detail: error instanceof Error ? error.message : "route denied" },
      { status: 404 },
    );
  }
  const headers = new Headers({ "X-API-Key": backendKey(request.method, path) });
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const body = request.method === "GET" || request.method === "HEAD"
    ? undefined
    : await request.arrayBuffer();
  try {
    const upstream = await fetch(url, { method: request.method, headers, body, cache: "no-store" });
    const responseHeaders = new Headers();
    responseHeaders.set("content-type", upstream.headers.get("content-type") ?? "application/json");
    return new NextResponse(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return NextResponse.json({ detail: "backend unavailable" }, { status: 503 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;

