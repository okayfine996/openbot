import type { RemoteAuthEvent } from "@openbot/contracts/signal-protocol/auth-events";
import type { IceServer, SignalChannel, SignalProtocolVersion } from "@openbot/contracts/signal-protocol/messages";
import { SIGNAL_MESSAGE_BYTES_LIMIT, SIGNAL_PROTOCOL_VERSION } from "@openbot/contracts/signal-protocol/messages";
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
  webhookRoutes: Set<string>;
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

export class SignalRoom {
  readonly #state: DurableObjectState;
  readonly #env: Env;
  readonly #auth: SignalAuthenticator;
  readonly #peers = new Map<WebSocket, Peer>();
  readonly #hosts = new Map<string, Set<Peer>>();
  readonly #webhookRoutes = new Map<string, Peer>();
  readonly #connections = new Map<string, Connection>();
  readonly #pendingWebhooks = new Map<string, { peer: Peer; resolve: (status: number) => void }>();
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
    return false;
  }

  async #deliverWebhook(delivery: WebhookDelivery): Promise<number> {
    const peer = this.#webhookRoutes.get(delivery.routeId);
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
      webhookRoutes: new Set(),
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
    if (!hello.webhookRoute) return this.#fail(peer.socket, "permission_denied", "A webhook route is required.", 1008);
    const routePayload = await this.#auth.verifyRoute(hello.webhookRoute, WEBHOOK_ROUTE_AUDIENCE);
    if (routePayload.hid !== peer.claims.hostId || !Array.isArray(routePayload.routes))
      return this.#fail(peer.socket, "permission_denied", "The webhook route belongs to another host.", 1008);
    for (const route of routePayload.routes) {
      if (!isRecord(route) || typeof route.id !== "string" || !WEBHOOK_ROUTE_ID_PATTERN.test(route.id))
        return this.#fail(peer.socket, "authentication_required", "The webhook route is invalid.", 1008);
      peer.webhookRoutes.add(route.id);
      this.#webhookRoutes.set(route.id, peer);
    }
    this.#send(peer.socket, await this.#ready(peer, null));
    this.#send(peer.socket, { type: "webhook-ready", version: SIGNAL_PROTOCOL_VERSION });
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
    for (const routeId of peer.webhookRoutes) {
      if (this.#webhookRoutes.get(routeId) === peer) this.#webhookRoutes.delete(routeId);
    }
    for (const [requestId, pending] of this.#pendingWebhooks) {
      if (pending.peer === peer) {
        pending.resolve(503);
        this.#pendingWebhooks.delete(requestId);
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
    (value.webhookFormats === undefined ||
      (Array.isArray(value.webhookFormats) && value.webhookFormats.every((format) => typeof format === "string")))
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

function isIceServersPayload(value: unknown): value is { iceServers: IceServer[] } {
  if (!isRecord(value) || !Array.isArray(value.iceServers) || value.iceServers.length === 0) return false;
  return value.iceServers.every((server) => {
    if (!isRecord(server)) return false;
    const urls = server.urls;
    return typeof urls === "string" || (Array.isArray(urls) && urls.every((url) => typeof url === "string"));
  });
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
