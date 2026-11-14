// The Worker reuses the repository's pure Discord event normalizer. It has no Bun or Node
// dependency; the Worker supplies the Gateway transport and action executor.
export {
  DISCORD_DIRECT_MESSAGE_REPLY,
  type DiscordAction,
  type DiscordMessageData,
  DiscordState,
} from "../../../remote/api/src/discord-events";
