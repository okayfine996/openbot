import type { RemoteAuthEvent } from "@openbot/contracts/signal-protocol/auth-events";
import { DISCORD_API_PATH } from "@openbot/contracts/signal-protocol/discord-route";
import {
  GITHUB_DELIVERY_BODY_BYTES_LIMIT,
  GITHUB_DELIVERY_HEADER,
  GITHUB_DELIVERY_ID_PATTERN,
  GITHUB_EVENT_HEADER,
  GITHUB_EVENT_PATTERN,
  GITHUB_EVENTS_PATH,
  GITHUB_SIGNATURE_HEADER,
  GITHUB_SIGNATURE_PATTERN,
} from "@openbot/contracts/signal-protocol/github-route";
import {
  TELEGRAM_BOT_ID_PATTERN,
  TELEGRAM_FILE_BYTES_LIMIT,
  TELEGRAM_FILES_PATH,
  TELEGRAM_UPDATE_BYTES_LIMIT,
  TELEGRAM_UPDATES_PATH,
  TELEGRAM_UPLOADS_PATH,
} from "@openbot/contracts/signal-protocol/telegram-route";
import {
  STANDARD_WEBHOOK_HEADER_SETS,
  WEBHOOK_DELIVERY_ID_HEADER,
  WEBHOOK_ROUTE_ID_PATTERN,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_TIMESTAMP_HEADER,
} from "@openbot/contracts/signal-protocol/webhook-route";
import {
  readGitHubRepository,
  readSlackRequest,
  readTelegramUpdate,
  verifyGitHubSignature,
  verifySlackSignature,
  verifyTelegramWebhookSecret,
} from "./ingress";
import { SignalRoom } from "./signal-room";

export { SignalRoom };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/internal/auth-events" && request.method === "POST") {
      const contentLength = Number(request.headers.get("Content-Length") ?? "0");
      if (contentLength > 64 * 1024)
        return Response.json(
          { error: { code: "body_too_large", message: "The auth event body is too large." } },
          { status: 413 },
        );
      const body = await request.text();
      if (new TextEncoder().encode(body).byteLength > 64 * 1024)
        return Response.json(
          { error: { code: "body_too_large", message: "The auth event body is too large." } },
          { status: 413 },
        );
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
    const webhookPrefix = "/v1/webhooks/";
    if (request.method === "POST" && url.pathname.startsWith(webhookPrefix)) {
      const routeId = url.pathname.slice(webhookPrefix.length);
      if (!WEBHOOK_ROUTE_ID_PATTERN.test(routeId)) return new Response("Not found.", { status: 404 });
      const body = await request.arrayBuffer();
      if (body.byteLength > 64 * 1024) return new Response("Webhook body is too large.", { status: 413 });
      const standard = STANDARD_WEBHOOK_HEADER_SETS.some(
        (headers) =>
          request.headers.has(headers.deliveryId) &&
          request.headers.has(headers.timestamp) &&
          request.headers.has(headers.signature),
      );
      const delivery = {
        requestId: crypto.randomUUID(),
        routeId,
        timestamp: request.headers.get(standard ? "webhook-timestamp" : WEBHOOK_TIMESTAMP_HEADER) ?? "",
        deliveryId: request.headers.get(standard ? "webhook-id" : WEBHOOK_DELIVERY_ID_HEADER) ?? "",
        signature: request.headers.get(standard ? "webhook-signature" : WEBHOOK_SIGNATURE_HEADER) ?? "",
        bodyBase64: encodeBase64(new Uint8Array(body)),
        ...(standard ? { format: "standard-webhooks" as const } : {}),
      };
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/webhook-delivery", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(delivery),
        }),
      );
    }
    if (url.pathname === "/v1/slack/events" && request.method === "POST") {
      const body = await request.arrayBuffer();
      if (body.byteLength > 64 * 1024) return new Response(null, { status: 413 });
      const timestamp = request.headers.get("x-slack-request-timestamp") ?? "";
      const signature = request.headers.get("x-slack-signature") ?? "";
      const parsed = readSlackRequest(new Uint8Array(body));
      const signer = parsed?.appId
        ? (env.SLACK_SIGNING_SECRET ?? "")
            .split(",")
            .map((entry) => entry.trim().split(":", 2))
            .find(
              ([appId, secret]) =>
                appId === parsed.appId &&
                secret &&
                verifySlackSignature(new Uint8Array(body), timestamp, signature, secret),
            )
        : undefined;
      if (!parsed || !signer) return new Response(null, { status: 401 });
      if (parsed.challenge)
        return new Response(parsed.challenge, { status: 200, headers: { "Content-Type": "text/plain" } });
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/slack-delivery", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            requestId: crypto.randomUUID(),
            appId: parsed.appId,
            teamId: parsed.teamId,
            kind: parsed.kind,
            retryNum: Number.isInteger(Number(request.headers.get("x-slack-retry-num")))
              ? Number(request.headers.get("x-slack-retry-num"))
              : null,
            retryReason: request.headers.get("x-slack-retry-reason"),
            bodyBase64: encodeBase64(new Uint8Array(body)),
          }),
        }),
      );
    }
    if (url.pathname === GITHUB_EVENTS_PATH && request.method === "POST") {
      const body = await request.arrayBuffer();
      if (body.byteLength > GITHUB_DELIVERY_BODY_BYTES_LIMIT) return new Response(null, { status: 413 });
      const event = request.headers.get(GITHUB_EVENT_HEADER) ?? "";
      const deliveryId = request.headers.get(GITHUB_DELIVERY_HEADER) ?? "";
      const signature = request.headers.get(GITHUB_SIGNATURE_HEADER) ?? "";
      if (
        !GITHUB_EVENT_PATTERN.test(event) ||
        !GITHUB_DELIVERY_ID_PATTERN.test(deliveryId) ||
        !GITHUB_SIGNATURE_PATTERN.test(signature)
      )
        return new Response(null, { status: 400 });
      if (
        !env.GITHUB_WEBHOOK_SECRET ||
        !(await verifyGitHubSignature(new Uint8Array(body), signature, env.GITHUB_WEBHOOK_SECRET))
      )
        return new Response(null, { status: 401 });
      const repository = readGitHubRepository(new Uint8Array(body));
      if (!repository) return new Response(null, { status: 204 });
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/github-delivery", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            requestId: crypto.randomUUID(),
            event,
            deliveryId,
            repositoryKey: `${repository.installationId}:${repository.repositoryId}`,
            bodyBase64: encodeBase64(new Uint8Array(body)),
          }),
        }),
      );
    }
    if (request.method === "POST" && url.pathname.startsWith(`${TELEGRAM_UPDATES_PATH}/`)) {
      const botId = url.pathname.slice(`${TELEGRAM_UPDATES_PATH}/`.length);
      if (!TELEGRAM_BOT_ID_PATTERN.test(botId)) return new Response(null, { status: 404 });
      const body = await request.arrayBuffer();
      if (body.byteLength > TELEGRAM_UPDATE_BYTES_LIMIT) return new Response(null, { status: 413 });
      const secret = env.TELEGRAM_WEBHOOK_SECRET ?? "";
      if (
        !secret ||
        !(await verifyTelegramWebhookSecret(
          request.headers.get("x-telegram-bot-api-secret-token") ?? "",
          secret,
          botId,
        ))
      )
        return new Response(null, { status: 401 });
      const update = readTelegramUpdate(new Uint8Array(body));
      if (!update) return new Response(null, { status: 200 });
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/telegram-delivery", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            botId,
            chatId: update.chatId,
            ...(update.linkCode ? { linkCode: update.linkCode } : {}),
            bodyBase64: encodeBase64(new Uint8Array(body)),
          }),
        }),
      );
    }
    if (
      (request.method === "GET" && url.pathname.startsWith(`${TELEGRAM_FILES_PATH}/`)) ||
      (request.method === "POST" && url.pathname.startsWith(`${TELEGRAM_UPLOADS_PATH}/`))
    ) {
      const body = request.method === "POST" ? await request.arrayBuffer() : undefined;
      if (body && body.byteLength > TELEGRAM_FILE_BYTES_LIMIT) return new Response(null, { status: 413 });
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request(`https://signal-room.internal${url.pathname}`, {
          method: request.method,
          headers: request.headers,
          ...(body ? { body } : {}),
        }),
      );
    }
    if (request.method === "POST" && url.pathname === DISCORD_API_PATH) {
      const authorization = request.headers.get("authorization") ?? "";
      if (!/^Bearer [A-Za-z0-9_-]{43}$/u.test(authorization))
        return Response.json({ error: { code: "unauthorized" } }, { status: 401 });
      const body = await request.arrayBuffer();
      if (body.byteLength > 512 * 1024) return Response.json({ error: { code: "invalid_request" } }, { status: 413 });
      const id = env.SIGNAL_ROOM.idFromName("global");
      return env.SIGNAL_ROOM.get(id).fetch(
        new Request("https://signal-room.internal/internal/discord-api", {
          method: "POST",
          headers: {
            Authorization: authorization,
            "Content-Type": request.headers.get("Content-Type") ?? "application/json",
          },
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

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
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
