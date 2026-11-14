import type { RemoteAuthEvent } from "@openbot/contracts/signal-protocol/auth-events";
import { SignalRoom } from "./signal-room";

export { SignalRoom };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/internal/auth-events" && request.method === "POST") {
      const body = await request.text();
      const valid = await verifyWebhookSignature(
        body,
        request.headers.get("OpenBot-Timestamp"),
        request.headers.get("OpenBot-Signature"),
        env.REMOTE_AUTH_WEBHOOK_SECRET,
      );
      if (!valid)
        return Response.json(
          { error: { code: "invalid_signature", message: "The auth event signature is invalid." } },
          { status: 401 },
        );
      try {
        readAuthEvent(JSON.parse(body));
      } catch {
        return Response.json(
          { error: { code: "invalid_event", message: "The auth event is invalid." } },
          { status: 400 },
        );
      }
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/auth-events", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        }),
      );
    }
    if (url.pathname !== "/v1/signal") return new Response("Not found.", { status: 404 });
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
      return new Response("WebSocket upgrade required.", { status: 426 });
    const id = env.SIGNAL_ROOM.idFromName("global");
    return env.SIGNAL_ROOM.get(id).fetch(request);
  },
};

export async function verifyWebhookSignature(
  body: string,
  timestamp: string | null,
  signature: string | null,
  secret: string,
): Promise<boolean> {
  if (!timestamp || !signature || !/^\d+$/u.test(timestamp)) return false;
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
    decodeBase64Url(signature),
    new TextEncoder().encode(`${timestamp}.${body}`),
  );
}

function decodeBase64Url(value: string): ArrayBuffer {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const bytes = atob(base64);
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(Uint8Array.from(bytes, (character) => character.charCodeAt(0)));
  return buffer;
}

function readAuthEvent(value: unknown): RemoteAuthEvent {
  if (!isRecord(value) || typeof value.type !== "string") throw new Error("invalid event");
  if (value.type === "remote-auth-changed" && typeof value.hostId === "string" && typeof value.authEpoch === "number")
    return { type: value.type, hostId: value.hostId, authEpoch: value.authEpoch };
  if (value.type === "remote-session-ended" && typeof value.hostId === "string" && typeof value.sessionId === "string")
    return { type: value.type, hostId: value.hostId, sessionId: value.sessionId };
  if (
    (value.type === "account-profile-changed" || value.type === "account-servers-changed") &&
    typeof value.userId === "string"
  )
    return { type: value.type, userId: value.userId };
  if (
    value.type === "slack-route-revoked" &&
    typeof value.appId === "string" &&
    typeof value.teamId === "string" &&
    typeof value.through === "number"
  )
    return { type: value.type, appId: value.appId, teamId: value.teamId, through: value.through };
  if (
    value.type === "telegram-route-revoked" &&
    typeof value.botId === "string" &&
    typeof value.chatId === "string" &&
    typeof value.through === "number"
  )
    return { type: value.type, botId: value.botId, chatId: value.chatId, through: value.through };
  if (value.type === "discord-route-revoked" && typeof value.guildId === "string" && typeof value.through === "number")
    return { type: value.type, guildId: value.guildId, through: value.through };
  if (value.type === "webhook-route-revoked" && typeof value.routeId === "string" && typeof value.through === "number")
    return { type: value.type, routeId: value.routeId, through: value.through };
  throw new Error("invalid event");
}

function isRecord(value: unknown): value is { [key: string]: unknown } {
  return typeof value === "object" && value !== null;
}
