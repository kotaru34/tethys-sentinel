import type { APIErrorShape, SessionInfo } from "./types";

let session: SessionInfo | null = null;

export class APIError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "APIError";
    this.status = status;
  }
}

async function errorFromResponse(response: Response): Promise<APIError> {
  let message = `${response.status} ${response.statusText}`.trim();
  try {
    const body = (await response.json()) as APIErrorShape;
    if (body.error) {
      message = body.error;
    }
  } catch {
    // Keep the status text if the response is not JSON.
  }
  return new APIError(response.status, message || `HTTP ${response.status}`);
}

export async function establishSession(): Promise<SessionInfo> {
  const response = await fetch("/api/v1/session", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw await errorFromResponse(response);
  }
  const next = (await response.json()) as SessionInfo;
  if (!next.operator_identity || !next.csrf_token) {
    throw new APIError(502, "operator session response is incomplete");
  }
  session = next;
  return next;
}

export function currentSession(): SessionInfo | null {
  return session;
}

export async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    signal,
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw await errorFromResponse(response);
  }
  return (await response.json()) as T;
}

export async function postJSON<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const active = session ?? (await establishSession());
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    signal,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Tethys-CSRF-Token": active.csrf_token,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    if (response.status === 403) {
      session = null;
    }
    throw await errorFromResponse(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
