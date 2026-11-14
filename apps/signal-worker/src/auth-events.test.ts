import { describe, expect, it } from "vitest";
import { verifyWebhookSignature } from "./index";

describe("Signal Worker auth event signature", () => {
  it("accepts a current HMAC signature", async () => {
    const body = JSON.stringify({ type: "remote-session-ended", hostId: "host", sessionId: "session" });
    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const secret = "s".repeat(32);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signatureBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${body}`));
    const signature = encodeBase64Url(new Uint8Array(signatureBytes));

    await expect(verifyWebhookSignature(body, timestamp, signature, secret)).resolves.toBe(true);
  });

  it("rejects a stale timestamp", async () => {
    await expect(verifyWebhookSignature("{}", "1", "invalid", "s".repeat(32))).resolves.toBe(false);
  });
});

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
