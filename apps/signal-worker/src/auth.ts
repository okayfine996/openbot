import {
  REMOTE_TICKET_AUDIENCE,
  REMOTE_TICKET_PROTOCOL_VERSION,
  type RemoteRole,
  type RemoteTicketClaims,
} from "@openbot/contracts/signal-protocol/ticket";
import { createRemoteJWKSet, type JWTPayload, jwtVerify, SignJWT } from "jose";

const RESUME_AUDIENCE = "openbot-remote-resume";
const RESUME_TTL_SECONDS = 10 * 60;

export type AuthenticatedTicket = {
  claims: RemoteTicketClaims;
  resumed: boolean;
};

export class SignalAuthError extends Error {}

export class SignalAuthenticator {
  readonly #jwks: ReturnType<typeof createRemoteJWKSet>;
  readonly #secret: Uint8Array;

  constructor(jwksUrl: string, sessionSecret: string) {
    this.#jwks = createRemoteJWKSet(new URL(jwksUrl));
    this.#secret = new TextEncoder().encode(sessionSecret);
  }

  async authenticate(token: string, state: DurableObjectState): Promise<AuthenticatedTicket> {
    let ticket: RemoteTicketClaims | null = null;
    try {
      ticket = await this.#verifyTicket(token);
      const used = await state.storage.get<number>(`ticket:${ticket.jti}`);
      if (used !== undefined && used > Math.floor(Date.now() / 1_000)) throw new SignalAuthError("ticket replay");
      const revokedEpoch = await state.storage.get<number>(`revoke:host:${ticket.hostId}`);
      const revokedSession = await state.storage.get<number>(`revoke:session:${ticket.sessionId}`);
      if ((revokedEpoch !== undefined && ticket.authEpoch <= revokedEpoch) || revokedSession !== undefined)
        throw new SignalAuthError("session revoked");
      await state.storage.put(`ticket:${ticket.jti}`, ticket.exp);
      await state.storage.setAlarm(Date.now() + 60_000);
      return { claims: ticket, resumed: false };
    } catch (error) {
      if (ticket !== null) throw error;
    }
    try {
      const { payload } = await jwtVerify(token, this.#secret, {
        audience: RESUME_AUDIENCE,
        algorithms: ["HS256"],
      });
      const claims = readClaims(payload);
      await this.#assertActive(claims, state);
      return { claims, resumed: true };
    } catch {
      throw new SignalAuthError("invalid token");
    }
  }

  async issueResumeToken(claims: RemoteTicketClaims): Promise<string> {
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setAudience(RESUME_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(Math.min(claims.exp, Math.floor(Date.now() / 1_000) + RESUME_TTL_SECONDS))
      .sign(this.#secret);
  }

  async #verifyTicket(token: string): Promise<RemoteTicketClaims> {
    try {
      const { payload } = await jwtVerify(token, this.#jwks, {
        audience: REMOTE_TICKET_AUDIENCE,
        algorithms: ["ES256"],
      });
      return readClaims(payload);
    } catch {
      throw new SignalAuthError("invalid ticket");
    }
  }

  async #assertActive(claims: RemoteTicketClaims, state: DurableObjectState): Promise<void> {
    const revokedEpoch = await state.storage.get<number>(`revoke:host:${claims.hostId}`);
    const revokedSession = await state.storage.get<number>(`revoke:session:${claims.sessionId}`);
    if ((revokedEpoch !== undefined && claims.authEpoch <= revokedEpoch) || revokedSession !== undefined)
      throw new SignalAuthError("session revoked");
  }
}

function readClaims(payload: JWTPayload): RemoteTicketClaims {
  const value = payload;
  const role = value.role;
  if (
    value.aud !== REMOTE_TICKET_AUDIENCE ||
    typeof value.jti !== "string" ||
    typeof value.sessionId !== "string" ||
    typeof value.hostId !== "string" ||
    typeof value.userId !== "string" ||
    typeof value.membershipId !== "string" ||
    !isRole(role) ||
    !isNumber(value.authEpoch) ||
    !isNumber(value.protocolMinimum) ||
    !isNumber(value.protocolMaximum) ||
    value.protocolMinimum > REMOTE_TICKET_PROTOCOL_VERSION ||
    value.protocolMaximum < REMOTE_TICKET_PROTOCOL_VERSION ||
    !isNumber(value.sessionExpiresAt) ||
    !isNumber(value.iat) ||
    !isNumber(value.exp) ||
    value.sessionExpiresAt <= Math.floor(Date.now() / 1_000) ||
    value.exp <= Math.floor(Date.now() / 1_000)
  )
    throw new SignalAuthError("invalid claims");
  return {
    aud: REMOTE_TICKET_AUDIENCE,
    jti: value.jti,
    sessionId: value.sessionId,
    hostId: value.hostId,
    userId: value.userId,
    membershipId: value.membershipId,
    role,
    authEpoch: value.authEpoch,
    protocolMinimum: value.protocolMinimum,
    protocolMaximum: value.protocolMaximum,
    sessionExpiresAt: value.sessionExpiresAt,
    ...(typeof value.clientPublicKey === "string" ? { clientPublicKey: value.clientPublicKey } : {}),
    ...(typeof value.signal === "string" ? { signal: value.signal } : {}),
    iat: value.iat,
    exp: value.exp,
  };
}

function isRole(value: unknown): value is RemoteRole {
  return value === "host" || value === "owner" || value === "admin" || value === "member";
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
