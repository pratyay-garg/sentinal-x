import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import {
  SESSION_COOKIE,
  authConfigured,
  createSession,
  passwordMatches,
  sessionCookieOptions,
  verifySession,
} from "@/lib/auth";

export async function GET() {
  const jar = await cookies();
  const configured = authConfigured();
  return NextResponse.json({
    configured,
    authenticated: configured && verifySession(jar.get(SESSION_COOKIE)?.value),
  });
}

export async function POST(request: Request) {
  if (!authConfigured()) {
    return NextResponse.json({ detail: "console authentication is not configured" }, { status: 503 });
  }
  let password = "";
  try {
    const body = (await request.json()) as { password?: unknown };
    password = typeof body.password === "string" ? body.password : "";
  } catch {
    return NextResponse.json({ detail: "invalid request" }, { status: 400 });
  }
  if (!passwordMatches(password)) {
    return NextResponse.json({ detail: "invalid credentials" }, { status: 401 });
  }
  const response = NextResponse.json({ authenticated: true });
  response.cookies.set(SESSION_COOKIE, createSession(), sessionCookieOptions);
  return response;
}

export async function DELETE() {
  const response = NextResponse.json({ authenticated: false });
  response.cookies.set(SESSION_COOKIE, "", { ...sessionCookieOptions, maxAge: 0 });
  return response;
}
