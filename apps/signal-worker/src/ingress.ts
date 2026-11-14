type SlackRequest = { appId: string; teamId: string; kind: "events" | "interactivity"; challenge?: string };

export function readSlackRequest(body: Uint8Array): SlackRequest | null {
  const text = new TextDecoder().decode(body);
  let value: unknown;
  let kind: SlackRequest["kind"] = "events";
  try {
    if (text.startsWith("payload=")) {
      kind = "interactivity";
      value = JSON.parse(decodeURIComponent(text.slice("payload=".length)));
    } else value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(value)) return null;
  const appId = typeof value.api_app_id === "string" ? value.api_app_id : undefined;
  const teamId =
    (typeof value.team_id === "string" && value.team_id) ||
    (isRecord(value.team) && typeof value.team.id === "string" ? value.team.id : undefined) ||
    (Array.isArray(value.authorizations) &&
    isRecord(value.authorizations[0]) &&
    typeof value.authorizations[0].team_id === "string"
      ? value.authorizations[0].team_id
      : undefined);
  if (!appId || !teamId) return null;
  return { appId, teamId, kind, ...(typeof value.challenge === "string" ? { challenge: value.challenge } : {}) };
}

export async function verifySlackSignature(
  body: Uint8Array,
  timestamp: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  if (!/^\d+$/u.test(timestamp) || !/^v0=[a-f0-9]{64}$/u.test(signature)) return false;
  if (Math.abs(Date.now() - Number(timestamp) * 1_000) > 5 * 60 * 1_000) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    hexToBuffer(signature.slice(3)),
    new TextEncoder().encode(`v0:${timestamp}:${new TextDecoder().decode(body)}`),
  );
}

export async function verifyGitHubSignature(body: Uint8Array, signature: string, secret: string): Promise<boolean> {
  if (!/^sha256=[a-f0-9]{64}$/u.test(signature)) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const copiedBody = new Uint8Array(new ArrayBuffer(body.byteLength));
  copiedBody.set(body);
  return crypto.subtle.verify("HMAC", key, hexToBuffer(signature.slice(7)), copiedBody.buffer);
}

export function readGitHubRepository(body: Uint8Array): { installationId: number; repositoryId: number } | null {
  try {
    const value = JSON.parse(new TextDecoder().decode(body));
    if (!isRecord(value) || !isRecord(value.installation) || !isRecord(value.repository)) return null;
    const installationId = value.installation.id;
    const repositoryId = value.repository.id;
    return typeof installationId === "number" &&
      typeof repositoryId === "number" &&
      installationId > 0 &&
      repositoryId > 0
      ? { installationId, repositoryId }
      : null;
  } catch {
    return null;
  }
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function hexToBuffer(value: string): ArrayBuffer {
  const bytes = new Uint8Array(new ArrayBuffer(value.length / 2));
  for (let index = 0; index < bytes.length; index += 1)
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return bytes.buffer;
}

function isRecord(value: unknown): value is { [key: string]: unknown } {
  return typeof value === "object" && value !== null;
}
