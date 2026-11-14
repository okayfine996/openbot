import type { RemoteAuthEvent } from "@openbot/contracts/signal-protocol/auth-events";
import { DISCORD_ROUTE_AUDIENCE } from "@openbot/contracts/signal-protocol/discord-route";
import { GITHUB_ROUTE_AUDIENCE } from "@openbot/contracts/signal-protocol/github-route";
import type { IceServer, SignalChannel, SignalProtocolVersion } from "@openbot/contracts/signal-protocol/messages";
import { SIGNAL_MESSAGE_BYTES_LIMIT, SIGNAL_PROTOCOL_VERSION } from "@openbot/contracts/signal-protocol/messages";
import { SLACK_ROUTE_AUDIENCE } from "@openbot/contracts/signal-protocol/slack-route";
import {
  TELEGRAM_BOT_ID_PATTERN,
  TELEGRAM_CHAT_ID_PATTERN,
  TELEGRAM_FILE_BYTES_LIMIT,
  TELEGRAM_FILE_TOKEN_TTL_SECONDS,
  TELEGRAM_FILES_PATH,
  TELEGRAM_ROUTE_AUDIENCE,
  TELEGRAM_UPLOADS_PATH,
  type TelegramCallMethod,
} from "@openbot/contracts/signal-protocol/telegram-route";
import type { RemoteTicketClaims } from "@openbot/contracts/signal-protocol/ticket";
import type { WebhookSignatureFormat } from "@openbot/contracts/signal-protocol/webhook-route";
import { WEBHOOK_ROUTE_AUDIENCE, WEBHOOK_ROUTE_ID_PATTERN } from "@openbot/contracts/signal-protocol/webhook-route";
import { type AuthenticatedTicket, SignalAuthError, SignalAuthenticator } from "./auth";

const RECONNECT_GRACE_MS = 30_000;
const MAX_CONNECTIONS_PER_HOST = 32;
const MAX_MESSAGES_PER_MINUTE = 600;

type PeerKind = "host" | "client" | "ingress";
type Peer = {
  socket: WebSocket;
  kind: PeerKind;
  claims: RemoteTicketClaims;
  resumeToken: string;
  connectionId: string | null;
  multiplex: boolean;
  webhookRoutes: Map<string, number>;
  slackRoutes: Map<string, number>;
  githubRepositories: Set<string>;
  telegramRoutes: Map<string, number>;
  discordGuilds: Map<string, number>;
  webhookFormats: Set<WebhookSignatureFormat>;
  messageWindow: { startedAt: number; count: number };
};
type Connection = { id: string; host: Peer; client: Peer };
type ReadyFrame = {
  type: "ready";
  version: SignalProtocolVersion;
  connectionId: string | null;
  resumeToken: string;
  iceServers: IceServer[];
  reconnectGraceMs?: number;
};
type Hello = {
  type: "hello";
  version: SignalProtocolVersion;
  peer: PeerKind;
  token: string;
  multiplex?: boolean;
  waitForHost?: boolean;
  webhookRoute?: string;
  slackRoute?: string;
  githubRoute?: string;
  telegramRoute?: string;
  discordRoute?: string;
  webhookFormats?: string[];
};
type Relay = {
  type: "offer" | "answer" | "ice-candidate" | "ice-restart" | "disconnect";
  version: SignalProtocolVersion;
  connectionId: string;
  channel?: SignalChannel;
  sdp?: string;
  candidate?: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
};
type WebhookResult = {
  type: "webhook-delivery-result";
  version: SignalProtocolVersion;
  requestId: string;
  status: number;
};
type WebhookDelivery = {
  requestId: string;
  routeId: string;
  timestamp: string;
  deliveryId: string;
  signature: string;
  bodyBase64: string;
  format?: WebhookSignatureFormat;
};
type SlackDelivery = {
  requestId: string;
  appId: string;
  teamId: string;
  kind: "events" | "interactivity";
  retryNum: number | null;
  retryReason: string | null;
  bodyBase64: string;
};
type GitHubDelivery = {
  requestId: string;
  event: string;
  deliveryId: string;
  repositoryKey: string;
  bodyBase64: string;
};
type TelegramDelivery = { botId: string; chatId: string; bodyBase64: string; linkCode?: string; linked?: true };
type TelegramCall = {
  type: "telegram-call";
  version: 1;
  requestId: string;
  botId: string;
  method: TelegramCallMethod;
  params: object;
};
type TelegramGrantInput =
  | { botId: string; filePath: string }
  | { botId: string; chatId: number; fileName: string; messageThreadId?: number; replyParameters?: object };
type TelegramGrant = TelegramGrantInput & { exp: number; nonce?: string };
const TELEGRAM_METHODS = new Set<TelegramCallMethod>([
  "getMe",
  "sendMessage",
  "editMessageText",
  "deleteMessage",
  "setMessageReaction",
  "answerCallbackQuery",
  "leaveChat",
]);

export class SignalRoom {
  readonly #state: DurableObjectState;
  readonly #env: Env;
  readonly #auth: SignalAuthenticator;
  readonly #peers = new Map<WebSocket, Peer>();
  readonly #hosts = new Map<string, Set<Peer>>();
  readonly #webhookRoutes = new Map<string, { peer: Peer; linkedAt: number }>();
  readonly #slackRoutes = new Map<string, { peer: Peer; linkedAt: number }>();
  readonly #githubRepositories = new Map<string, Set<Peer>>();
  readonly #telegramRoutes = new Map<string, { peer: Peer; linkedAt: number }>();
  readonly #discordSessions = new Map<string, Peer>();
  readonly #connections = new Map<string, Connection>();
  readonly #pendingWebhooks = new Map<string, { peer: Peer; resolve: (status: number) => void }>();
  readonly #pendingDeliveries = new Map<string, { peer: Peer; resolve: (status: number) => void }>();
  readonly #helloTimers = new Map<WebSocket, ReturnType<typeof setTimeout>>();
  readonly #iceServers = new Map<string, { expiresAt: number; value: IceServer[] }>();

  constructor(state: DurableObjectState, env: Env) {
    this.#state = state;
    this.#env = env;
    this.#auth = new SignalAuthenticator(env.REMOTE_TICKET_JWKS_URL, env.REMOTE_SESSION_SECRET);
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/internal/auth-events" && request.method === "POST") {
      const value = await request.json();
      if (!isAuthEvent(value))
        return Response.json(
          { error: { code: "unsupported_event", message: "Unsupported auth event." } },
          { status: 501 },
        );
      return (await this.authEvent(value))
        ? new Response(null, { status: 204 })
        : Response.json({ error: { code: "unsupported_event", message: "Unsupported auth event." } }, { status: 501 });
    }
    if (path === "/internal/webhook-delivery" && request.method === "POST") {
      const value = await request.json();
      if (!isWebhookDelivery(value))
        return Response.json(
          { error: { code: "invalid_delivery", message: "Invalid webhook delivery." } },
          { status: 400 },
        );
      return new Response(null, { status: await this.#deliverWebhook(value) });
    }
    if (path === "/internal/slack-delivery" && request.method === "POST") {
      const value = await request.json();
      if (!isSlackDelivery(value)) return Response.json({ error: { code: "invalid_delivery" } }, { status: 400 });
      return new Response(null, { status: await this.#deliverSlack(value) });
    }
    if (path === "/internal/github-delivery" && request.method === "POST") {
      const value = await request.json();
      if (!isGitHubDelivery(value)) return Response.json({ error: { code: "invalid_delivery" } }, { status: 400 });
      return new Response(null, { status: await this.#deliverGitHub(value) });
    }
    if (path === "/internal/telegram-delivery" && request.method === "POST") {
      const value = await request.json();
      if (!isTelegramDelivery(value)) return Response.json({ error: { code: "invalid_delivery" } }, { status: 400 });
      return new Response(null, { status: await this.#deliverTelegram(value) });
    }
    if (request.method === "GET" && path.startsWith(`${TELEGRAM_FILES_PATH}/`))
      return this.#downloadTelegramFile(path.slice(`${TELEGRAM_FILES_PATH}/`.length));
    if (request.method === "POST" && path.startsWith(`${TELEGRAM_UPLOADS_PATH}/`))
      return this.#uploadTelegramFile(path.slice(`${TELEGRAM_UPLOADS_PATH}/`.length), request);
    if (path === "/internal/discord-api" && request.method === "POST") return this.#discordApi(request);
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
      return new Response("WebSocket upgrade required.", { status: 426 });
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.#registerSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async authEvent(event: RemoteAuthEvent): Promise<boolean> {
    if (event.type === "remote-auth-changed") {
      await this.#state.storage.put(`revoke:host:${event.hostId}`, event.authEpoch);
      for (const peer of this.#peersForHost(event.hostId)) this.#revokePeer(peer);
      return true;
    }
    if (event.type === "remote-session-ended") {
      await this.#state.storage.put(`revoke:session:${event.sessionId}`, Date.now());
      for (const peer of [...this.#peers.values()]) {
        if (peer.claims.sessionId === event.sessionId) this.#revokePeer(peer);
      }
      return true;
    }
    if (event.type === "account-profile-changed" || event.type === "account-servers-changed") {
      for (const peer of this.#peers.values()) {
        if (peer.claims.userId === event.userId)
          this.#send(peer.socket, { type: event.type, version: SIGNAL_PROTOCOL_VERSION });
      }
      return true;
    }
    if (event.type === "webhook-route-revoked") {
      const route = this.#webhookRoutes.get(event.routeId);
      if (route && route.linkedAt <= event.through) {
        const peer = route.peer;
        peer.webhookRoutes.delete(event.routeId);
        this.#webhookRoutes.delete(event.routeId);
      }
      return true;
    }
    if (event.type === "slack-route-revoked") {
      const key = `${event.appId}:${event.teamId}`;
      const route = this.#slackRoutes.get(key);
      if (route && route.linkedAt <= event.through) {
        route.peer.slackRoutes.delete(key);
        this.#slackRoutes.delete(key);
      }
      return true;
    }
    if (event.type === "telegram-route-revoked") {
      const key = `${event.botId}:${event.chatId}`;
      const route = this.#telegramRoutes.get(key);
      if (route && route.linkedAt <= event.through) {
        route.peer.telegramRoutes.delete(key);
        this.#telegramRoutes.delete(key);
      }
      return true;
    }
    if (event.type === "discord-route-revoked") {
      for (const [token, peer] of this.#discordSessions) {
        const linkedAt = peer.discordGuilds.get(event.guildId);
        if (linkedAt !== undefined && linkedAt <= event.through) {
          peer.discordGuilds.delete(event.guildId);
          const guilds = [...peer.discordGuilds.keys()];
          this.#send(peer.socket, { type: "discord-session", version: SIGNAL_PROTOCOL_VERSION, token, guilds });
        }
      }
      return true;
    }
    return false;
  }

  async #deliverWebhook(delivery: WebhookDelivery): Promise<number> {
    const peer = this.#webhookRoutes.get(delivery.routeId)?.peer;
    if (!peer || peer.socket.readyState !== WebSocket.OPEN) return 503;
    const response = new Promise<number>((resolve) => {
      this.#pendingWebhooks.set(delivery.requestId, { peer, resolve });
      const { format: requestedFormat, ...deliveryFrame } = delivery;
      const format = requestedFormat && peer.webhookFormats.has(requestedFormat) ? requestedFormat : undefined;
      this.#send(peer.socket, {
        type: "webhook-delivery",
        version: SIGNAL_PROTOCOL_VERSION,
        ...deliveryFrame,
        ...(format ? { format } : {}),
      });
    });
    const timeout = new Promise<number>((resolve) => setTimeout(() => resolve(503), 10_000));
    const status = await Promise.race([response, timeout]);
    this.#pendingWebhooks.delete(delivery.requestId);
    return status;
  }

  async #deliverSlack(delivery: SlackDelivery): Promise<number> {
    const peer = this.#slackRoutes.get(`${delivery.appId}:${delivery.teamId}`)?.peer;
    if (!peer || peer.socket.readyState !== WebSocket.OPEN) return 503;
    return this.#waitForDelivery(peer, delivery.requestId, {
      type: "slack-delivery",
      version: SIGNAL_PROTOCOL_VERSION,
      requestId: delivery.requestId,
      teamId: delivery.teamId,
      kind: delivery.kind,
      retryNum: delivery.retryNum,
      retryReason: delivery.retryReason,
      bodyBase64: delivery.bodyBase64,
    });
  }

  async #deliverGitHub(delivery: GitHubDelivery): Promise<number> {
    const peers = this.#githubRepositories.get(delivery.repositoryKey);
    if (!peers || peers.size === 0) return 204;
    const statuses = await Promise.all(
      [...peers].map((peer) => {
        const requestId = `${delivery.requestId}:${crypto.randomUUID()}`;
        return this.#waitForDelivery(peer, requestId, {
          type: "github-delivery",
          version: SIGNAL_PROTOCOL_VERSION,
          requestId,
          event: delivery.event,
          deliveryId: delivery.deliveryId,
          bodyBase64: delivery.bodyBase64,
        });
      }),
    );
    if (statuses.includes(202)) return 202;
    return statuses.every((status) => status === 404) ? 204 : 503;
  }

  async #deliverTelegram(delivery: TelegramDelivery): Promise<number> {
    let peer = this.#telegramRoutes.get(`${delivery.botId}:${delivery.chatId}`)?.peer;
    let linked = false;
    if (!peer && delivery.linkCode) {
      const hostId = await this.#linkTelegramChat(delivery.botId, delivery.chatId, delivery.linkCode);
      peer = hostId ? this.#peersForHost(hostId).find((candidate) => candidate.kind === "ingress") : undefined;
      if (peer) {
        const key = `${delivery.botId}:${delivery.chatId}`;
        const linkedAt = Date.now();
        peer.telegramRoutes.set(key, linkedAt);
        this.#telegramRoutes.set(key, { peer, linkedAt });
        linked = true;
      }
    }
    if (!peer || peer.socket.readyState !== WebSocket.OPEN) return 200;
    this.#send(peer.socket, {
      type: "telegram-delivery",
      version: SIGNAL_PROTOCOL_VERSION,
      botId: delivery.botId,
      chatId: delivery.chatId,
      bodyBase64: delivery.bodyBase64,
      ...(delivery.linked || linked ? { linked: true } : {}),
    });
    return 204;
  }

  async #linkTelegramChat(botId: string, chatId: string, code: string): Promise<string | null> {
    const origin = this.#env.REMOTE_CONTROL_PLANE_URL?.trim();
    if (!origin || !this.#env.REMOTE_AUTH_WEBHOOK_SECRET) return null;
    const body = JSON.stringify({ botId, chatId, code });
    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(this.#env.REMOTE_AUTH_WEBHOOK_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = encodeBase64Url(
      new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${body}`))),
    );
    try {
      const response = await fetch(new URL("/v2/remote/telegram-route/link", origin), {
        method: "POST",
        headers: { "Content-Type": "application/json", "OpenBot-Timestamp": timestamp, "OpenBot-Signature": signature },
        body,
      });
      if (!response.ok) return null;
      const value = await response.json();
      return isRecord(value) && typeof value.hostId === "string" ? value.hostId : null;
    } catch {
      return null;
    }
  }

  async #discordApi(request: Request): Promise<Response> {
    const authorization = request.headers.get("Authorization") ?? "";
    const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    const peer = this.#discordSessions.get(token);
    if (!peer || peer.socket.readyState !== WebSocket.OPEN)
      return Response.json({ error: { code: "unauthorized" } }, { status: 401 });
    const input = await request.json().catch(() => null);
    if (!isRecord(input) || typeof input.op !== "string" || typeof input.guildId !== "string")
      return Response.json({ error: { code: "invalid_request" } }, { status: 400 });
    if (!peer.discordGuilds.has(input.guildId))
      return Response.json({ error: { code: "unknown_guild" } }, { status: 404 });
    const botToken = this.#env.DISCORD_BOT_TOKEN;
    if (!botToken) return Response.json({ error: { code: "unavailable" } }, { status: 503 });
    const mapped = discordRestRequest(input);
    if (!mapped) return Response.json({ error: { code: "invalid_request" } }, { status: 400 });
    try {
      const response = await fetch(
        `https://discord.com/api/v10${mapped.path}${mapped.query ? `?${mapped.query}` : ""}`,
        {
          method: mapped.method,
          headers: { Authorization: `Bot ${botToken}`, ...(mapped.body ? { "Content-Type": "application/json" } : {}) },
          ...(mapped.body ? { body: JSON.stringify(mapped.body) } : {}),
        },
      );
      const value = await response.json().catch(() => null);
      if (!response.ok)
        return Response.json({ error: { code: discordErrorCode(response.status) } }, { status: response.status });
      return Response.json(discordRestResult(input, value), { status: 200 });
    } catch {
      return Response.json({ error: { code: "unavailable" } }, { status: 503 });
    }
  }

  async #telegramCall(peer: Peer, call: TelegramCall): Promise<void> {
    const chatId = telegramCallChatId(call);
    if (
      call.method !== "getMe" &&
      (chatId === null || this.#telegramRoutes.get(`${call.botId}:${chatId}`)?.peer !== peer)
    ) {
      this.#send(peer.socket, {
        type: "telegram-call-result",
        version: SIGNAL_PROTOCOL_VERSION,
        requestId: call.requestId,
        ok: false,
        status: 403,
        code: "forbidden",
        message: "The Telegram route is not owned by this host.",
      });
      return;
    }
    const token = this.#telegramTokens().get(call.botId);
    if (!token || !TELEGRAM_METHODS.has(call.method)) {
      this.#send(peer.socket, {
        type: "telegram-call-result",
        version: SIGNAL_PROTOCOL_VERSION,
        requestId: call.requestId,
        ok: false,
        status: 503,
        code: "unavailable",
        message: "Telegram is not configured.",
      });
      return;
    }
    try {
      const response = await fetch(`https://api.telegram.org/bot${token}/${call.method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(call.params),
      });
      const value = await response.json();
      const result = isRecord(value) && value.ok === true ? await this.#telegramCallResult(call, value.result) : null;
      if (result === null) {
        this.#send(peer.socket, {
          type: "telegram-call-result",
          version: SIGNAL_PROTOCOL_VERSION,
          requestId: call.requestId,
          ok: false,
          status: response.status,
          code: "telegram_error",
          message: "The Telegram API rejected the call.",
        });
        return;
      }
      this.#send(peer.socket, {
        type: "telegram-call-result",
        version: SIGNAL_PROTOCOL_VERSION,
        requestId: call.requestId,
        ok: true,
        result,
      });
    } catch {
      this.#send(peer.socket, {
        type: "telegram-call-result",
        version: SIGNAL_PROTOCOL_VERSION,
        requestId: call.requestId,
        ok: false,
        status: 502,
        code: "unavailable",
        message: "The Telegram API did not answer.",
      });
    }
  }

  #telegramTokens(): Map<string, string> {
    const tokens = new Map<string, string>();
    for (const value of (this.#env.TELEGRAM_BOT_TOKENS ?? "").split(",")) {
      const separator = value.indexOf(":");
      const botId = value.slice(0, separator);
      if (separator > 0 && TELEGRAM_BOT_ID_PATTERN.test(botId)) tokens.set(botId, value.slice(separator + 1));
    }
    return tokens;
  }

  async #telegramCallResult(call: TelegramCall, value: unknown): Promise<TelegramResult | null> {
    if (call.method === "getFile" && isRecord(value) && typeof value.file_path === "string") {
      if (typeof value.file_size === "number" && value.file_size > TELEGRAM_FILE_BYTES_LIMIT) return null;
      return {
        ...(typeof value.file_size === "number" ? { fileSize: value.file_size } : {}),
        fileToken: await this.#issueTelegramGrant("openbot-telegram-file-token", {
          botId: call.botId,
          filePath: value.file_path,
        }),
      };
    }
    if (call.method === "sendDocument") {
      if (
        !isRecord(call.params) ||
        typeof call.params.file_name !== "string" ||
        typeof call.params.chat_id !== "number"
      )
        return null;
      return {
        uploadToken: await this.#issueTelegramGrant("openbot-telegram-upload-token", {
          botId: call.botId,
          chatId: call.params.chat_id,
          fileName: call.params.file_name,
          ...(typeof call.params.message_thread_id === "number"
            ? { messageThreadId: call.params.message_thread_id }
            : {}),
          ...(isRecord(call.params.reply_parameters) ? { replyParameters: call.params.reply_parameters } : {}),
        }),
      };
    }
    return telegramCallResult(call.method, value);
  }

  async #issueTelegramGrant(label: string, claims: TelegramGrantInput): Promise<string> {
    const payload = {
      ...claims,
      exp: Math.floor(Date.now() / 1_000) + TELEGRAM_FILE_TOKEN_TTL_SECONDS,
      ...(label.endsWith("upload-token") ? { nonce: crypto.randomUUID() } : {}),
    };
    const encoded = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
    return `${encoded}.${await this.#grantSignature(label, encoded)}`;
  }

  async #verifyTelegramGrant(label: string, token: string): Promise<TelegramGrant | null> {
    const [payload, signature, extra] = token.split(".");
    if (
      !payload ||
      !signature ||
      extra !== undefined ||
      (await this.#grantSignature(label, payload)).localeCompare(signature) !== 0
    )
      return null;
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)));
    } catch {
      return null;
    }
    if (
      !isRecord(value) ||
      typeof value.exp !== "number" ||
      value.exp <= Math.floor(Date.now() / 1_000) ||
      typeof value.botId !== "string"
    )
      return null;
    if (label.endsWith("file-token") && typeof value.filePath === "string")
      return { botId: value.botId, filePath: value.filePath, exp: value.exp };
    if (
      label.endsWith("upload-token") &&
      typeof value.chatId === "number" &&
      typeof value.fileName === "string" &&
      typeof value.nonce === "string"
    )
      return {
        botId: value.botId,
        chatId: value.chatId,
        fileName: value.fileName,
        exp: value.exp,
        nonce: value.nonce,
        ...(typeof value.messageThreadId === "number" ? { messageThreadId: value.messageThreadId } : {}),
        ...(isRecord(value.replyParameters) ? { replyParameters: value.replyParameters } : {}),
      };
    return null;
  }

  async #grantSignature(label: string, payload: string): Promise<string> {
    const master = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(this.#env.REMOTE_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const derived = await crypto.subtle.sign("HMAC", master, new TextEncoder().encode(label));
    const key = await crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return encodeBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))));
  }

  async #downloadTelegramFile(token: string): Promise<Response> {
    const grant = await this.#verifyTelegramGrant("openbot-telegram-file-token", token);
    if (!grant || !("filePath" in grant) || typeof grant.botId !== "string" || typeof grant.filePath !== "string")
      return new Response(null, { status: 404 });
    const botToken = this.#telegramTokens().get(grant.botId);
    if (!botToken || grant.filePath.includes("..") || grant.filePath.startsWith("/"))
      return new Response(null, { status: 404 });
    const response = await fetch(`https://api.telegram.org/file/bot${botToken}/${grant.filePath}`);
    const length = Number(response.headers.get("content-length") ?? "0");
    if (!response.ok || !response.body || (length > 0 && length > TELEGRAM_FILE_BYTES_LIMIT))
      return new Response(null, { status: 502 });
    return new Response(response.body, {
      status: 200,
      headers: { "Cache-Control": "no-store", "Content-Type": "application/octet-stream" },
    });
  }

  async #uploadTelegramFile(token: string, request: Request): Promise<Response> {
    const grant = await this.#verifyTelegramGrant("openbot-telegram-upload-token", token);
    if (
      !grant ||
      !("chatId" in grant) ||
      typeof grant.botId !== "string" ||
      typeof grant.chatId !== "number" ||
      typeof grant.fileName !== "string" ||
      typeof grant.nonce !== "string"
    )
      return Response.json({ errorCode: 404, description: "upload_failed" }, { status: 404 });
    const used = await this.#state.storage.get<number>(`telegram-upload:${grant.nonce}`);
    if (used !== undefined) return Response.json({ errorCode: 404, description: "upload_failed" }, { status: 404 });
    const body = await request.arrayBuffer();
    if (body.byteLength === 0 || body.byteLength > TELEGRAM_FILE_BYTES_LIMIT)
      return Response.json({ errorCode: 413, description: "file_too_large" }, { status: 413 });
    const botToken = this.#telegramTokens().get(grant.botId);
    if (!botToken) return Response.json({ errorCode: 503, description: "upload_failed" }, { status: 503 });
    await this.#state.storage.put(`telegram-upload:${grant.nonce}`, grant.exp);
    const form = new FormData();
    form.set("chat_id", String(grant.chatId));
    form.set("document", new Blob([body]), grant.fileName);
    if (typeof grant.messageThreadId === "number") form.set("message_thread_id", String(grant.messageThreadId));
    if (isRecord(grant.replyParameters)) form.set("reply_parameters", JSON.stringify(grant.replyParameters));
    const response = await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, {
      method: "POST",
      body: form,
    });
    const value = await response.json();
    if (isRecord(value) && value.ok === true && isRecord(value.result) && typeof value.result.message_id === "number")
      return Response.json({ ok: true, messageId: value.result.message_id });
    return Response.json({ errorCode: response.status, description: "upload_failed" }, { status: response.status });
  }

  async #waitForDelivery(peer: Peer, requestId: string, frame: unknown): Promise<number> {
    if (peer.socket.readyState !== WebSocket.OPEN) return 503;
    const response = new Promise<number>((resolve) => this.#pendingDeliveries.set(requestId, { peer, resolve }));
    this.#send(peer.socket, frame);
    const timeout = new Promise<number>((resolve) => setTimeout(() => resolve(503), 10_000));
    const status = await Promise.race([response, timeout]);
    this.#pendingDeliveries.delete(requestId);
    return status;
  }

  async alarm(): Promise<void> {
    const now = Math.floor(Date.now() / 1_000);
    const tickets = await this.#state.storage.list<number>({ prefix: "ticket:" });
    for (const [key, expiresAt] of tickets) {
      if (expiresAt <= now) await this.#state.storage.delete(key);
    }
    const remaining = await this.#state.storage.list<number>({ prefix: "ticket:", limit: 1 });
    if (remaining.size > 0) await this.#state.storage.setAlarm(Date.now() + 60_000);
  }

  #registerSocket(socket: WebSocket): void {
    const timer = setTimeout(() => this.#fail(socket, "authentication_required", "Hello required.", 1008), 30_000);
    this.#helloTimers.set(socket, timer);
    socket.addEventListener("message", (event) => void this.#receive(socket, event.data));
    socket.addEventListener("close", () => this.#disconnect(socket));
    socket.addEventListener("error", () => this.#disconnect(socket));
  }

  async #receive(socket: WebSocket, data: unknown): Promise<void> {
    const peer = this.#peers.get(socket);
    if (peer && !this.#withinRate(peer)) return this.#fail(socket, "rate_limited", "Too many messages.", 1008);
    const text = typeof data === "string" ? data : data instanceof ArrayBuffer ? new TextDecoder().decode(data) : null;
    if (text === null) return this.#fail(socket, "invalid_message", "Only text or binary frames are supported.", 1008);
    if (new TextEncoder().encode(text).byteLength > SIGNAL_MESSAGE_BYTES_LIMIT)
      return this.#fail(socket, "invalid_message", "Message is too large.", 1009);
    let message: unknown;
    try {
      message = JSON.parse(text);
    } catch {
      return this.#fail(socket, "invalid_message", "Invalid JSON.", 1008);
    }
    if (!peer) {
      if (!isHello(message)) return this.#fail(socket, "authentication_required", "Hello required.", 1008);
      return this.#authenticate(socket, message);
    }
    if (isTurnRefresh(message)) return this.#refresh(peer, message.connectionId);
    if (isWebhookResult(message)) {
      const pending = this.#pendingWebhooks.get(message.requestId);
      if (pending?.peer === peer) pending.resolve(message.status);
      return;
    }
    if (isSlackResult(message) || isGitHubResult(message)) {
      const pending = this.#pendingDeliveries.get(message.requestId);
      if (pending?.peer === peer) pending.resolve(message.status);
      return;
    }
    if (isTelegramCall(message)) return this.#telegramCall(peer, message);
    if (isRelay(message)) return this.#relay(peer, message);
    return this.#fail(socket, "invalid_message", "Unsupported message.", 1008);
  }

  async #authenticate(socket: WebSocket, hello: Hello): Promise<void> {
    clearTimeout(this.#helloTimers.get(socket));
    this.#helloTimers.delete(socket);
    let authenticated: AuthenticatedTicket;
    try {
      authenticated = await this.#auth.authenticate(hello.token, this.#state);
    } catch (error) {
      if (error instanceof SignalAuthError)
        return this.#fail(socket, "authentication_required", "Remote ticket is invalid or expired.", 1008);
      return this.#fail(socket, "authentication_required", "Authentication failed.", 1008);
    }
    const { claims, resumed } = authenticated;
    if ((hello.peer === "host" || hello.peer === "ingress") !== (claims.role === "host"))
      return this.#fail(socket, "permission_denied", "Peer role is not allowed.", 1008);
    const resumeToken = await this.#auth.issueResumeToken(claims);
    const peer: Peer = {
      socket,
      kind: hello.peer,
      claims,
      resumeToken,
      connectionId: null,
      multiplex: hello.peer === "host" && hello.multiplex === true,
      webhookRoutes: new Map(),
      slackRoutes: new Map(),
      githubRepositories: new Set(),
      telegramRoutes: new Map(),
      discordGuilds: new Map(),
      webhookFormats: new Set(
        hello.webhookFormats?.filter((format): format is WebhookSignatureFormat => format === "standard-webhooks"),
      ),
      messageWindow: { startedAt: Date.now(), count: 0 },
    };
    this.#peers.set(socket, peer);
    try {
      if (hello.peer === "host") return await this.#admitHost(peer, resumed);
      if (hello.peer === "ingress") return await this.#admitIngress(peer, hello);
      return await this.#admitClient(peer, hello, resumed);
    } catch {
      this.#fail(socket, "protocol_error", "Signal setup failed.", 1013);
    }
  }

  async #admitHost(peer: Peer, resumed: boolean): Promise<void> {
    const hosts = this.#hosts.get(peer.claims.hostId) ?? new Set<Peer>();
    if (hosts.size >= MAX_CONNECTIONS_PER_HOST)
      return this.#fail(peer.socket, "rate_limited", "Too many host connections.", 1008);
    hosts.add(peer);
    this.#hosts.set(peer.claims.hostId, hosts);
    this.#send(peer.socket, await this.#ready(peer, null));
    for (const client of this.#peersForHost(peer.claims.hostId)) {
      if (client.kind !== "client" || client.connectionId !== null) continue;
      this.#connect(peer, client, resumed);
    }
  }

  async #admitClient(peer: Peer, hello: Hello, resumed: boolean): Promise<void> {
    const host = this.#currentHost(peer.claims.hostId);
    if (!host) {
      if (hello.waitForHost) {
        this.#send(peer.socket, {
          type: "host-waiting",
          version: SIGNAL_PROTOCOL_VERSION,
          resumeToken: peer.resumeToken,
        });
        return;
      }
      return this.#fail(peer.socket, "host_unavailable", "The host is offline.", 1013);
    }
    if (!host.multiplex && this.#activeForHost(peer.claims.hostId).length > 0)
      return this.#fail(peer.socket, "host_busy", "The host already has an active remote session.", 1013);
    this.#connect(host, peer, resumed);
  }

  async #admitIngress(peer: Peer, hello: Hello): Promise<void> {
    if (!hello.webhookRoute && !hello.slackRoute && !hello.githubRoute && !hello.telegramRoute && !hello.discordRoute)
      return this.#fail(peer.socket, "permission_denied", "An ingress route is required.", 1008);
    if (hello.webhookRoute) {
      const routePayload = await this.#auth.verifyRoute(hello.webhookRoute, WEBHOOK_ROUTE_AUDIENCE);
      if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.routes))
        return this.#fail(peer.socket, "permission_denied", "The webhook route belongs to another host.", 1008);
      for (const route of routePayload.routes) {
        if (
          !isRecord(route) ||
          typeof route.id !== "string" ||
          !WEBHOOK_ROUTE_ID_PATTERN.test(route.id) ||
          typeof route.linkedAt !== "number"
        )
          return this.#fail(peer.socket, "authentication_required", "The webhook route is invalid.", 1008);
        peer.webhookRoutes.set(route.id, route.linkedAt);
        this.#webhookRoutes.set(route.id, { peer, linkedAt: route.linkedAt });
      }
    }
    if (hello.slackRoute) {
      const routePayload = await this.#auth.verifyRoute(hello.slackRoute, SLACK_ROUTE_AUDIENCE);
      if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.teams))
        return this.#fail(peer.socket, "permission_denied", "The Slack route belongs to another host.", 1008);
      for (const team of routePayload.teams) {
        if (
          !isRecord(team) ||
          typeof team.appId !== "string" ||
          typeof team.id !== "string" ||
          typeof team.linkedAt !== "number"
        )
          return this.#fail(peer.socket, "authentication_required", "The Slack route is invalid.", 1008);
        const key = `${team.appId}:${team.id}`;
        peer.slackRoutes.set(key, team.linkedAt);
        this.#slackRoutes.set(key, { peer, linkedAt: team.linkedAt });
      }
    }
    if (hello.githubRoute) {
      const routePayload = await this.#auth.verifyRoute(hello.githubRoute, GITHUB_ROUTE_AUDIENCE);
      if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.repositories))
        return this.#fail(peer.socket, "permission_denied", "The GitHub route belongs to another host.", 1008);
      for (const repository of routePayload.repositories) {
        if (!isRecord(repository) || typeof repository.id !== "number" || typeof repository.installationId !== "number")
          return this.#fail(peer.socket, "authentication_required", "The GitHub route is invalid.", 1008);
        const key = `${repository.installationId}:${repository.id}`;
        peer.githubRepositories.add(key);
        const peers = this.#githubRepositories.get(key) ?? new Set<Peer>();
        peers.add(peer);
        this.#githubRepositories.set(key, peers);
      }
    }
    if (hello.telegramRoute) {
      const routePayload = await this.#auth.verifyRoute(hello.telegramRoute, TELEGRAM_ROUTE_AUDIENCE);
      if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.chats))
        return this.#fail(peer.socket, "permission_denied", "The Telegram route belongs to another host.", 1008);
      for (const chat of routePayload.chats) {
        if (
          !isRecord(chat) ||
          typeof chat.botId !== "string" ||
          !TELEGRAM_BOT_ID_PATTERN.test(chat.botId) ||
          typeof chat.id !== "string" ||
          !TELEGRAM_CHAT_ID_PATTERN.test(chat.id) ||
          typeof chat.linkedAt !== "number"
        )
          return this.#fail(peer.socket, "authentication_required", "The Telegram route is invalid.", 1008);
        const key = `${chat.botId}:${chat.id}`;
        peer.telegramRoutes.set(key, chat.linkedAt);
        this.#telegramRoutes.set(key, { peer, linkedAt: chat.linkedAt });
      }
    }
    if (hello.discordRoute) {
      const routePayload = await this.#auth.verifyRoute(hello.discordRoute, DISCORD_ROUTE_AUDIENCE);
      if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.guilds))
        return this.#fail(peer.socket, "permission_denied", "The Discord route belongs to another host.", 1008);
      for (const guild of routePayload.guilds) {
        if (!isRecord(guild) || typeof guild.id !== "string" || typeof guild.linkedAt !== "number")
          return this.#fail(peer.socket, "authentication_required", "The Discord route is invalid.", 1008);
        peer.discordGuilds.set(guild.id, guild.linkedAt);
      }
      if (this.#env.DISCORD_BOT_TOKEN) {
        const session = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        this.#discordSessions.set(session, peer);
        this.#send(peer.socket, {
          type: "discord-session",
          version: SIGNAL_PROTOCOL_VERSION,
          token: session,
          guilds: [...peer.discordGuilds.keys()],
        });
      }
    }
    this.#send(peer.socket, await this.#ready(peer, null));
    if (hello.webhookRoute) this.#send(peer.socket, { type: "webhook-ready", version: SIGNAL_PROTOCOL_VERSION });
    if (hello.githubRoute) this.#send(peer.socket, { type: "github-ready", version: SIGNAL_PROTOCOL_VERSION });
  }

  #connect(host: Peer, client: Peer, resumed: boolean): void {
    const id = crypto.randomUUID();
    client.connectionId = id;
    const connection = { id, host, client } satisfies Connection;
    this.#connections.set(id, connection);
    void this.#ready(client, id)
      .then((ready) => this.#send(client.socket, { ...ready, reconnectGraceMs: RECONNECT_GRACE_MS }))
      .catch(() => this.#fail(client.socket, "protocol_error", "TURN credentials are unavailable.", 1013));
    this.#send(host.socket, {
      type: "peer-ready",
      version: SIGNAL_PROTOCOL_VERSION,
      connectionId: id,
      sessionId: client.claims.sessionId,
      userId: client.claims.userId,
      membershipId: client.claims.membershipId,
      role: client.claims.role === "host" ? "member" : client.claims.role,
      sessionExpiresAt: client.claims.sessionExpiresAt,
      resumed,
    });
  }

  async #refresh(peer: Peer, connectionId: string | null): Promise<void> {
    if (connectionId !== null && peer.connectionId !== connectionId)
      return this.#fail(peer.socket, "permission_denied", "Connection is not owned by this peer.", 1008);
    try {
      this.#send(peer.socket, await this.#ready(peer, connectionId));
    } catch {
      this.#fail(peer.socket, "protocol_error", "TURN credentials are unavailable.", 1013);
    }
  }

  #relay(peer: Peer, message: Relay): void {
    const connection = this.#connections.get(message.connectionId);
    if (!connection || (connection.client !== peer && connection.host !== peer)) {
      this.#fail(peer.socket, "permission_denied", "Connection is not owned by this peer.", 1008);
      return;
    }
    const target = connection.host === peer ? connection.client : connection.host;
    this.#send(target.socket, message);
    if (message.type === "disconnect") this.#dropConnection(connection);
  }

  async #ready(peer: Peer, connectionId: string | null): Promise<ReadyFrame> {
    return {
      type: "ready",
      version: SIGNAL_PROTOCOL_VERSION,
      connectionId,
      resumeToken: peer.resumeToken,
      iceServers: await this.#getIceServers(peer.claims.sessionId, peer.claims.sessionExpiresAt),
      ...(this.#telegramTokens().size > 0 ? { capabilities: ["telegram"] } : {}),
    };
  }

  async #getIceServers(sessionId: string, sessionExpiresAt: number): Promise<IceServer[]> {
    if (this.#env.TURN_PROVIDER === "disabled") return [];
    const now = Math.floor(Date.now() / 1_000);
    const cached = this.#iceServers.get(sessionId);
    if (cached && cached.expiresAt > now + 60) return cached.value;
    const keyId = this.#env.CLOUDFLARE_TURN_KEY_ID;
    const apiToken = this.#env.CLOUDFLARE_TURN_API_TOKEN;
    if (!keyId || !apiToken) throw new Error("TURN is not configured.");
    const ttl = Math.max(60, Math.min(3_600, sessionExpiresAt - now));
    const response = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ ttl }),
      },
    );
    if (!response.ok) throw new Error("TURN credential request failed.");
    const value = await response.json();
    if (!isIceServersPayload(value)) throw new Error("TURN response is invalid.");
    this.#iceServers.set(sessionId, { expiresAt: now + ttl, value: value.iceServers });
    return value.iceServers;
  }

  #disconnect(socket: WebSocket): void {
    clearTimeout(this.#helloTimers.get(socket));
    this.#helloTimers.delete(socket);
    const peer = this.#peers.get(socket);
    if (!peer) return;
    this.#peers.delete(socket);
    if (peer.kind === "host") {
      const hosts = this.#hosts.get(peer.claims.hostId);
      hosts?.delete(peer);
      if (hosts?.size === 0) this.#hosts.delete(peer.claims.hostId);
    }
    for (const routeId of peer.webhookRoutes.keys()) {
      if (this.#webhookRoutes.get(routeId)?.peer === peer) this.#webhookRoutes.delete(routeId);
    }
    for (const route of peer.slackRoutes.keys()) {
      if (this.#slackRoutes.get(route)?.peer === peer) this.#slackRoutes.delete(route);
    }
    for (const route of peer.githubRepositories) {
      const peers = this.#githubRepositories.get(route);
      peers?.delete(peer);
      if (peers?.size === 0) this.#githubRepositories.delete(route);
    }
    for (const route of peer.telegramRoutes.keys()) {
      if (this.#telegramRoutes.get(route)?.peer === peer) this.#telegramRoutes.delete(route);
    }
    for (const [token, sessionPeer] of this.#discordSessions) {
      if (sessionPeer === peer) this.#discordSessions.delete(token);
    }
    for (const [requestId, pending] of this.#pendingWebhooks) {
      if (pending.peer === peer) {
        pending.resolve(503);
        this.#pendingWebhooks.delete(requestId);
      }
    }
    for (const [requestId, pending] of this.#pendingDeliveries) {
      if (pending.peer === peer) {
        pending.resolve(503);
        this.#pendingDeliveries.delete(requestId);
      }
    }
    for (const connection of [...this.#connections.values()]) {
      if (connection.host !== peer && connection.client !== peer) continue;
      if (connection) {
        const other = connection.host === peer ? connection.client : connection.host;
        this.#send(other.socket, { type: "disconnect", version: SIGNAL_PROTOCOL_VERSION, connectionId: connection.id });
        this.#dropConnection(connection);
      }
    }
  }

  #revokePeer(peer: Peer): void {
    this.#send(peer.socket, {
      type: "error",
      version: SIGNAL_PROTOCOL_VERSION,
      code: "session_revoked",
      message: "The remote session is no longer active.",
    });
    peer.socket.close(1008, "Remote session revoked.");
  }

  #dropConnection(connection: Connection): void {
    this.#connections.delete(connection.id);
    connection.host.connectionId = null;
    connection.client.connectionId = null;
  }

  #currentHost(hostId: string): Peer | null {
    return [...(this.#hosts.get(hostId) ?? [])][0] ?? null;
  }

  #peersForHost(hostId: string): Peer[] {
    return [...this.#peers.values()].filter((peer) => peer.claims.hostId === hostId);
  }

  #activeForHost(hostId: string): Connection[] {
    return [...this.#connections.values()].filter((connection) => connection.host.claims.hostId === hostId);
  }

  #withinRate(peer: Peer): boolean {
    const now = Date.now();
    if (now - peer.messageWindow.startedAt >= 60_000) peer.messageWindow = { startedAt: now, count: 0 };
    peer.messageWindow.count += 1;
    return peer.messageWindow.count <= MAX_MESSAGES_PER_MINUTE;
  }

  #send(socket: WebSocket, value: unknown): void {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
  }

  #fail(socket: WebSocket, code: string, message: string, closeCode: number): void {
    this.#send(socket, { type: "error", version: SIGNAL_PROTOCOL_VERSION, code, message });
    socket.close(closeCode, message);
  }
}

function isHello(value: unknown): value is Hello {
  if (!isRecord(value) || value.type !== "hello" || value.version !== SIGNAL_PROTOCOL_VERSION) return false;
  return (
    (value.peer === "host" || value.peer === "client" || value.peer === "ingress") &&
    typeof value.token === "string" &&
    value.token.length > 0 &&
    (value.webhookRoute === undefined || typeof value.webhookRoute === "string") &&
    (value.slackRoute === undefined || typeof value.slackRoute === "string") &&
    (value.githubRoute === undefined || typeof value.githubRoute === "string") &&
    (value.telegramRoute === undefined || typeof value.telegramRoute === "string") &&
    (value.discordRoute === undefined || typeof value.discordRoute === "string") &&
    (value.webhookFormats === undefined ||
      (Array.isArray(value.webhookFormats) && value.webhookFormats.every((format) => typeof format === "string")))
  );
}

function isSlackDelivery(value: unknown): value is SlackDelivery {
  return (
    isRecord(value) &&
    typeof value.requestId === "string" &&
    typeof value.appId === "string" &&
    typeof value.teamId === "string" &&
    (value.kind === "events" || value.kind === "interactivity") &&
    (value.retryNum === null || typeof value.retryNum === "number") &&
    (value.retryReason === null || typeof value.retryReason === "string") &&
    typeof value.bodyBase64 === "string"
  );
}

function isGitHubDelivery(value: unknown): value is GitHubDelivery {
  return (
    isRecord(value) &&
    typeof value.requestId === "string" &&
    typeof value.event === "string" &&
    typeof value.deliveryId === "string" &&
    typeof value.repositoryKey === "string" &&
    typeof value.bodyBase64 === "string"
  );
}

function isSlackResult(value: unknown): value is { requestId: string; status: number } {
  return (
    isRecord(value) &&
    value.type === "slack-delivery-result" &&
    typeof value.requestId === "string" &&
    typeof value.status === "number"
  );
}

function isGitHubResult(value: unknown): value is { requestId: string; status: number } {
  return (
    isRecord(value) &&
    value.type === "github-delivery-result" &&
    typeof value.requestId === "string" &&
    typeof value.status === "number"
  );
}

function isTelegramCall(value: unknown): value is TelegramCall {
  return (
    isRecord(value) &&
    value.type === "telegram-call" &&
    value.version === SIGNAL_PROTOCOL_VERSION &&
    typeof value.requestId === "string" &&
    typeof value.botId === "string" &&
    isTelegramCallMethod(value.method) &&
    isRecord(value.params)
  );
}

function isTelegramDelivery(value: unknown): value is TelegramDelivery {
  return (
    isRecord(value) &&
    typeof value.botId === "string" &&
    typeof value.chatId === "string" &&
    TELEGRAM_CHAT_ID_PATTERN.test(value.chatId) &&
    typeof value.bodyBase64 === "string" &&
    (value.linkCode === undefined ||
      (typeof value.linkCode === "string" && /^[A-Za-z0-9_-]{32,64}$/u.test(value.linkCode))) &&
    (value.linked === undefined || value.linked === true)
  );
}

function telegramCallChatId(call: TelegramCall): string | null {
  if (call.method === "getMe") return "-0";
  if (call.method === "answerCallbackQuery") return null;
  if (!isRecord(call.params)) return null;
  const chatId = call.params.chat_id;
  return typeof chatId === "number" && Number.isSafeInteger(chatId) ? String(chatId) : null;
}

function telegramCallResult(method: TelegramCallMethod, value: unknown): TelegramResult | null {
  if (method === "getMe" && isRecord(value) && typeof value.id === "number" && typeof value.username === "string")
    return { botId: String(value.id), username: value.username };
  if (method === "sendMessage" && isRecord(value) && typeof value.message_id === "number")
    return { messageId: value.message_id };
  if (isRecord(value) || value === true) return {};
  return null;
}

interface TelegramResult {
  messageId?: number;
  botId?: string;
  username?: string;
  fileToken?: string;
  fileSize?: number;
  uploadToken?: string;
}

function isTelegramCallMethod(value: unknown): value is TelegramCallMethod {
  return (
    value === "getMe" ||
    value === "sendMessage" ||
    value === "editMessageText" ||
    value === "deleteMessage" ||
    value === "setMessageReaction" ||
    value === "answerCallbackQuery" ||
    value === "leaveChat"
  );
}

function isTurnRefresh(value: unknown): value is { type: "turn-refresh"; connectionId: string | null } {
  return (
    isRecord(value) &&
    value.type === "turn-refresh" &&
    (value.connectionId === null || typeof value.connectionId === "string")
  );
}

function isRelay(value: unknown): value is Relay {
  return (
    isRecord(value) &&
    (value.type === "offer" ||
      value.type === "answer" ||
      value.type === "ice-candidate" ||
      value.type === "ice-restart" ||
      value.type === "disconnect") &&
    value.version === SIGNAL_PROTOCOL_VERSION &&
    typeof value.connectionId === "string"
  );
}

function isWebhookResult(value: unknown): value is WebhookResult {
  return (
    isRecord(value) &&
    value.type === "webhook-delivery-result" &&
    value.version === SIGNAL_PROTOCOL_VERSION &&
    typeof value.requestId === "string" &&
    typeof value.status === "number"
  );
}

function isRecord(value: unknown): value is { [key: string]: unknown } {
  return typeof value === "object" && value !== null;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function isIceServersPayload(value: unknown): value is { iceServers: IceServer[] } {
  if (!isRecord(value) || !Array.isArray(value.iceServers) || value.iceServers.length === 0) return false;
  return value.iceServers.every((server) => {
    if (!isRecord(server)) return false;
    const urls = server.urls;
    return typeof urls === "string" || (Array.isArray(urls) && urls.every((url) => typeof url === "string"));
  });
}

type DiscordMappedRequest = {
  method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  path: string;
  query?: string;
  body?: unknown;
};

function discordRestRequest(input: { [key: string]: unknown }): DiscordMappedRequest | null {
  const guildId = typeof input.guildId === "string" ? input.guildId : null;
  if (!guildId) return null;
  const channelId = typeof input.channelId === "string" ? input.channelId : null;
  const messageId = typeof input.messageId === "string" ? input.messageId : null;
  switch (input.op) {
    case "createMessage":
      if (!channelId || typeof input.content !== "string" || !Array.isArray(input.buttons)) return null;
      return {
        method: "POST",
        path: `/channels/${channelId}/messages`,
        body: {
          ...(input.content ? { content: input.content } : {}),
          allowed_mentions: { parse: ["users"], replied_user: false },
          ...(typeof input.replyTo === "string"
            ? { message_reference: { message_id: input.replyTo, fail_if_not_exists: false } }
            : {}),
          components: input.buttons.map(discordButton),
          ...(Array.isArray(input.embeds) ? { embeds: input.embeds } : {}),
        },
      };
    case "editMessage":
      if (!channelId || !messageId || typeof input.content !== "string" || !Array.isArray(input.buttons)) return null;
      return {
        method: "PATCH",
        path: `/channels/${channelId}/messages/${messageId}`,
        body: {
          content: input.content,
          allowed_mentions: { parse: [], replied_user: false },
          components: input.buttons.map(discordButton),
        },
      };
    case "deleteMessage":
      return channelId && messageId ? { method: "DELETE", path: `/channels/${channelId}/messages/${messageId}` } : null;
    case "react":
      return channelId && messageId && typeof input.emoji === "string" && typeof input.on === "boolean"
        ? {
            method: input.on ? "PUT" : "DELETE",
            path: `/channels/${channelId}/messages/${messageId}/reactions/${encodeURIComponent(input.emoji)}/@me`,
          }
        : null;
    case "listMessages":
      return channelId && typeof input.after === "string" && typeof input.limit === "number"
        ? {
            method: "GET",
            path: `/channels/${channelId}/messages`,
            query: new URLSearchParams({ after: input.after, limit: String(input.limit) }).toString(),
          }
        : null;
    case "member":
      return typeof input.userId === "string"
        ? { method: "GET", path: `/guilds/${guildId}/members/${input.userId}` }
        : null;
    case "channel":
      return channelId ? { method: "GET", path: `/channels/${channelId}` } : null;
    case "listChannels":
      return { method: "GET", path: `/guilds/${guildId}/channels` };
    case "listRoles":
      return { method: "GET", path: `/guilds/${guildId}/roles` };
    default:
      return null;
  }
}

function discordButton(value: unknown): { type: 2; custom_id: string; label: string; style: number } {
  const button = isRecord(value) ? value : {};
  const styles: { [key: string]: number } = { primary: 1, secondary: 2, success: 3, danger: 4 };
  const style = typeof button.style === "string" ? (styles[button.style] ?? 2) : 2;
  return { type: 2, custom_id: String(button.customId ?? ""), label: String(button.label ?? ""), style };
}

type DiscordRestResult =
  | { messageId: string }
  | { name: string }
  | { messages: DiscordRestHistory[] }
  | { channels: DiscordRestChannel[] }
  | { roles: DiscordRestRole[] }
  | Record<never, never>;
type DiscordRestHistory = {
  id: string;
  authorId: string;
  authorName: string;
  authorIsBot: boolean;
  content: string;
  replyToId: string | null;
  sentAt: string;
  attachments: DiscordRestAttachment[];
  embeds: string[];
  forwarded: boolean;
};
type DiscordRestAttachment = { id: string; filename: string; contentType: string | null; size: number; url: string };
type DiscordRestChannel = { id: string; name: string; kind: "channel" | "thread" };
type DiscordRestRole = { id: string; name: string };

function discordRestResult(input: { [key: string]: unknown }, value: unknown): DiscordRestResult {
  if (input.op === "createMessage" && isRecord(value) && typeof value.id === "string") return { messageId: value.id };
  if (input.op === "member" && isRecord(value) && isRecord(value.user))
    return { name: String(value.nick ?? value.user.global_name ?? value.user.username ?? "") };
  if (input.op === "channel" && isRecord(value)) return { name: typeof value.name === "string" ? value.name : "" };
  if (input.op === "listMessages" && Array.isArray(value))
    return {
      messages: value.map((message) => {
        const item = isRecord(message) ? message : {};
        const author = isRecord(item.author) ? item.author : {};
        return {
          id: String(item.id ?? "0"),
          authorId: String(author.id ?? "0"),
          authorName: String(author.global_name ?? author.username ?? ""),
          authorIsBot: author.bot === true,
          content: String(item.content ?? ""),
          replyToId:
            isRecord(item.message_reference) && typeof item.message_reference.message_id === "string"
              ? item.message_reference.message_id
              : null,
          sentAt: String(item.timestamp ?? ""),
          attachments: Array.isArray(item.attachments) ? item.attachments.map(discordAttachment) : [],
          embeds: Array.isArray(item.embeds) ? item.embeds.map((embed) => JSON.stringify(embed)) : [],
          forwarded: false,
        };
      }),
    };
  if (input.op === "listChannels" && Array.isArray(value))
    return {
      channels: value.map((channel) => ({
        id: String(isRecord(channel) ? channel.id : "0"),
        name: String(isRecord(channel) ? (channel.name ?? "") : ""),
        kind: isRecord(channel) && (channel.type === 12 || channel.type === 11) ? "thread" : "channel",
      })),
    };
  if (input.op === "listRoles" && Array.isArray(value))
    return {
      roles: value
        .filter(isRecord)
        .filter((role) => role.id !== input.guildId && role.managed !== true)
        .map((role) => ({ id: String(role.id), name: String(role.name ?? "") })),
    };
  return {};
}

function discordAttachment(value: unknown): DiscordRestAttachment {
  const item = isRecord(value) ? value : {};
  return {
    id: String(item.id ?? "0"),
    filename: String(item.filename ?? ""),
    contentType: typeof item.content_type === "string" ? item.content_type : null,
    size: typeof item.size === "number" ? item.size : 0,
    url: String(item.url ?? ""),
  };
}

function discordErrorCode(
  status: number,
): "unauthorized" | "forbidden" | "not_found" | "rate_limited" | "invalid_request" | "discord_failed" {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  if (status === 400) return "invalid_request";
  return "discord_failed";
}

function isWebhookDelivery(value: unknown): value is WebhookDelivery {
  return (
    isRecord(value) &&
    typeof value.requestId === "string" &&
    typeof value.routeId === "string" &&
    WEBHOOK_ROUTE_ID_PATTERN.test(value.routeId) &&
    typeof value.timestamp === "string" &&
    typeof value.deliveryId === "string" &&
    typeof value.signature === "string" &&
    typeof value.bodyBase64 === "string" &&
    (value.format === undefined || value.format === "standard-webhooks")
  );
}

function isAuthEvent(value: unknown): value is RemoteAuthEvent {
  if (!isRecord(value) || typeof value.type !== "string") return false;
  if (value.type === "remote-auth-changed")
    return typeof value.hostId === "string" && typeof value.authEpoch === "number";
  if (value.type === "remote-session-ended")
    return typeof value.hostId === "string" && typeof value.sessionId === "string";
  if (value.type === "account-profile-changed" || value.type === "account-servers-changed")
    return typeof value.userId === "string";
  if (value.type === "slack-route-revoked")
    return typeof value.appId === "string" && typeof value.teamId === "string" && typeof value.through === "number";
  if (value.type === "telegram-route-revoked")
    return typeof value.botId === "string" && typeof value.chatId === "string" && typeof value.through === "number";
  if (value.type === "discord-route-revoked")
    return typeof value.guildId === "string" && typeof value.through === "number";
  if (value.type === "webhook-route-revoked")
    return typeof value.routeId === "string" && typeof value.through === "number";
  return false;
}
