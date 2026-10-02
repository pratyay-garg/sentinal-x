import type { Json } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/backend/${path.replace(/^\//, "")}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as { detail?: Json };
      if (payload.detail) message = typeof payload.detail === "string"
        ? payload.detail : JSON.stringify(payload.detail);
    } catch { /* non-JSON upstream */ }
    throw new ApiError(response.status, message);
  }
  return response.json() as Promise<T>;
}

export function formatDate(value: string | null | undefined): string {
  return value ? new Intl.DateTimeFormat(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).format(new Date(value)) : "—";
}

export function pct(value: number | null | undefined): string {
  return value == null ? "—" : `${(value * 100).toFixed(1)}%`;
}

