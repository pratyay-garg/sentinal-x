import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "sentinalx_session";
const MAX_AGE_SECONDS = 12 * 60 * 60;

function required(name: string): string {
  const value = process.env[name];
  if (!value || value.startsWith("change-me")) {
    throw new Error(`${name} must be configured with a strong value`);
  }
  return value;
}

export function authConfigured(): boolean {
  return ["CONSOLE_PASSWORD", "CONSOLE_SESSION_SECRET"].every((name) => {
    const value = process.env[name];
    return Boolean(value && !value.startsWith("change-me"));
  });
}

function equal(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function signature(timestamp: string): string {
  return createHmac("sha256", required("CONSOLE_SESSION_SECRET"))
    .update(`sentinalx:${timestamp}`)
    .digest("base64url");
}

export function passwordMatches(candidate: string): boolean {
  return equal(candidate, required("CONSOLE_PASSWORD"));
}

export function createSession(): string {
  const timestamp = String(Math.floor(Date.now() / 1000));
  return `${timestamp}.${signature(timestamp)}`;
}

export function verifySession(token: string | undefined): boolean {
  if (!token) return false;
  const [timestamp, supplied, extra] = token.split(".");
  if (!timestamp || !supplied || extra) return false;
  const issued = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(issued) || issued > now + 30 || now - issued > MAX_AGE_SECONDS) {
    return false;
  }
  return equal(supplied, signature(timestamp));
}

export const sessionCookieOptions = {
  httpOnly: true,
  sameSite: "strict" as const,
  secure: process.env.CONSOLE_SECURE_COOKIES === "true",
  path: "/",
  maxAge: MAX_AGE_SECONDS,
};
