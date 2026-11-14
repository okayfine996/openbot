import { describe, expect, it } from "vitest";
import { readGitHubRepository, readSlackRequest, verifyGitHubSignature, verifySlackSignature } from "./ingress";

describe("Signal Worker connector ingress", () => {
  it("parses Slack events and interactivity envelopes without retaining their body", () => {
    expect(readSlackRequest(new TextEncoder().encode(JSON.stringify({ api_app_id: "A123", team_id: "T123" })))).toEqual(
      {
        appId: "A123",
        teamId: "T123",
        kind: "events",
      },
    );
    expect(
      readSlackRequest(
        new TextEncoder().encode(
          `payload=${encodeURIComponent(JSON.stringify({ api_app_id: "A123", team: { id: "T123" } }))}`,
        ),
      ),
    ).toEqual({ appId: "A123", teamId: "T123", kind: "interactivity" });
  });

  it("verifies Slack and GitHub signatures over the exact request bytes", async () => {
    const slackBody = new TextEncoder().encode('{"api_app_id":"A123","team_id":"T123"}');
    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const slackSignature = `v0=${await hmacHex("slack-secret", `v0:${timestamp}:${new TextDecoder().decode(slackBody)}`)}`;
    await expect(verifySlackSignature(slackBody, timestamp, slackSignature, "slack-secret")).resolves.toBe(true);

    const githubBody = new TextEncoder().encode('{"installation":{"id":1},"repository":{"id":2}}');
    const githubSignature = `sha256=${await hmacHex("github-secret", githubBody)}`;
    await expect(verifyGitHubSignature(githubBody, githubSignature, "github-secret")).resolves.toBe(true);
    expect(readGitHubRepository(githubBody)).toEqual({ installationId: 1, repositoryId: 2 });
  });
});

async function hmacHex(secret: string, value: string | Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(new Uint8Array(value));
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  return [...signature].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
