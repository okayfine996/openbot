import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { readRemoteApiConfig } from "../remote/api/src/config";
import type { RemoteTicketClaims } from "../remote/api/src/protocol";
import { RemoteTokenService } from "../remote/api/src/tokens";

const baseEnvironment = {
  REMOTE_TLS_DISABLED: "true",
  REMOTE_TICKET_PUBLIC_KEYS: JSON.stringify({ keys: [{ kty: "EC", kid: "test" }] }),
  REMOTE_CONTROL_PLANE_URL: "https://api.example.test",
  REMOTE_SESSION_SECRET: "s".repeat(32),
  REMOTE_AUTH_WEBHOOK_SECRET: "a".repeat(32),
};

describe("readRemoteApiConfig", () => {
  it("keeps coturn as the default provider", () => {
    const config = readRemoteApiConfig({
      ...baseEnvironment,
      TURN_HOST: "turn.example.test",
      TURN_SHARED_SECRET: "t".repeat(32),
    });

    expect(config.turnProvider).toBe("coturn");
    expect(config.turnHosts).toEqual(["turn.example.test"]);
    expect(config.turnSecret).toBe("t".repeat(32));
  });

  it("accepts Cloudflare Realtime TURN without coturn settings", () => {
    const config = readRemoteApiConfig({
      ...baseEnvironment,
      TURN_PROVIDER: "cloudflare-realtime",
      CLOUDFLARE_TURN_KEY_ID: "turn-key",
      CLOUDFLARE_TURN_API_TOKEN: "turn-token",
    });

    expect(config.turnProvider).toBe("cloudflare-realtime");
    expect(config.turnHosts).toEqual([]);
    expect(config.turnSecret).toBeNull();
    expect(config.cloudflareTurnKeyId).toBe("turn-key");
    expect(config.cloudflareTurnApiToken).toBe("turn-token");
  });

  it("rejects an incomplete Cloudflare TURN configuration", () => {
    expect(() =>
      readRemoteApiConfig({
        ...baseEnvironment,
        TURN_PROVIDER: "cloudflare-realtime",
        CLOUDFLARE_TURN_KEY_ID: "turn-key",
      }),
    ).toThrow("CLOUDFLARE_TURN_KEY_ID and CLOUDFLARE_TURN_API_TOKEN are required.");
  });

  it("requests and caches Cloudflare ICE servers with a bounded TTL", async () => {
    const config = readRemoteApiConfig({
      ...baseEnvironment,
      TURN_PROVIDER: "cloudflare-realtime",
      CLOUDFLARE_TURN_KEY_ID: "turn-key",
      CLOUDFLARE_TURN_API_TOKEN: "turn-token",
    });
    const requests: Request[] = [];
    const service = new RemoteTokenService(config, undefined, {
      fetch: async (input, init) => {
        requests.push(new Request(input, init));
        return Response.json({ iceServers: [{ urls: "turn:relay.example.test", username: "u", credential: "c" }] });
      },
    });
    const claims = {
      aud: "openbot-remote",
      jti: "ticket",
      sessionId: "session",
      hostId: "host",
      userId: "user",
      membershipId: "membership",
      role: "member" as const,
      authEpoch: 0,
      protocolMinimum: 1,
      protocolMaximum: 1,
      sessionExpiresAt: 4_000,
      iat: 900,
      exp: 4_000,
    } satisfies RemoteTicketClaims;

    const first = await Effect.runPromise(service.iceServers(claims, 1_000));
    const second = await Effect.runPromise(service.iceServers(claims, 1_100));
    expect(first).toEqual(second);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe(
      "https://rtc.live.cloudflare.com/v1/turn/keys/turn-key/credentials/generate-ice-servers",
    );
    expect(requests[0]?.headers.get("authorization")).toBe("Bearer turn-token");
    expect(await requests[0]?.json()).toEqual({ ttl: 3_000 });
  });
});
