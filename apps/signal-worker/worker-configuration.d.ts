interface Env {
  SIGNAL_ROOM: DurableObjectNamespace;
  REMOTE_TICKET_JWKS_URL: string;
  REMOTE_SESSION_SECRET: string;
  REMOTE_AUTH_WEBHOOK_SECRET: string;
  SLACK_SIGNING_SECRET?: string;
  GITHUB_WEBHOOK_SECRET?: string;
  TELEGRAM_BOT_TOKENS?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
  REMOTE_CONTROL_PLANE_URL?: string;
  DISCORD_BOT_TOKEN?: string;
  DISCORD_APPLICATION_ID?: string;
  DISCORD_MESSAGE_CONTENT?: string;
  TURN_PROVIDER: "cloudflare-realtime" | "disabled";
  CLOUDFLARE_TURN_KEY_ID?: string;
  CLOUDFLARE_TURN_API_TOKEN?: string;
}
