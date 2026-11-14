import { describe, expect, it } from "vitest";
import { readRemoteApiConfig } from "../remote/api/src/config";

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
});
