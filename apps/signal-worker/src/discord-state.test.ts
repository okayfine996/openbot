import { describe, expect, it } from "vitest";
import { DiscordState } from "./discord-state";

describe("Signal Worker Discord state", () => {
  it("normalizes a mentioned guild message using the shared OpenBot state", () => {
    const state = new DiscordState("app-1");
    dispatch(state, {
      t: "READY",
      d: { user: { id: "bot-1" }, application: { id: "app-1" }, guilds: [{ id: "guild-1", name: "Test" }] },
    });
    const [action] = dispatch(state, {
      t: "MESSAGE_CREATE",
      d: {
        id: "message-1",
        channel_id: "channel-1",
        guild_id: "guild-1",
        content: "<@bot-1> hello",
        timestamp: "2026-11-15T00:00:00.000Z",
        author: { id: "user-1", username: "user" },
        mentions: [{ id: "bot-1" }],
        attachments: [],
      },
    });
    expect(action).toMatchObject({
      type: "deliver",
      guildId: "guild-1",
      delivery: { kind: "message", message: { content: "hello", authorId: "user-1" } },
    });
  });

  it("stores an interaction token while emitting the immediate acknowledgement", () => {
    const state = new DiscordState("app-1");
    dispatch(state, {
      t: "READY",
      d: { user: { id: "bot-1" }, application: { id: "app-1" }, guilds: [{ id: "guild-1", name: "Test" }] },
    });
    const actions = dispatch(state, {
      t: "INTERACTION_CREATE",
      d: {
        id: "interaction-1",
        type: 3,
        token: "interaction-token",
        guild_id: "guild-1",
        channel_id: "channel-1",
        member: { user: { id: "user-1" } },
        data: { custom_id: "openbot:approve:1" },
        message: { id: "message-1", message_reference: null },
      },
    });
    expect(actions[0]).toMatchObject({ type: "acknowledge", interactionId: "interaction-1" });
    expect(state.interactionToken("interaction-1", "guild-1")).toBe("interaction-token");
  });
});

function dispatch(state: DiscordState, value: { t: string; d: unknown }) {
  // The real Gateway transport validates the envelope before handing it to the shared normalizer.
  // biome-ignore lint/nursery/noUnsafeTypeAssertion: test payloads exercise the runtime normalizer boundary.
  return state.handle(value as Parameters<DiscordState["handle"]>[0]);
}
