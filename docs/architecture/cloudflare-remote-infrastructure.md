# Cloudflare remote infrastructure

## Current implementation boundary

The repository now has a separate `apps/signal-worker` Cloudflare Worker. Its Durable Object keeps
the Team WebRTC signaling path in one global `SignalRoom` object. It verifies the existing ES256
remote ticket through the Auth Worker JWKS, issues compatible HS256 resume tokens, relays SDP/ICE,
enforces host/client ownership, and obtains Cloudflare Realtime TURN credentials without exposing
the TURN API token to clients.

The released Team API is unchanged. Chats, files, commands and events remain on the WebRTC data
channels and do not enter Cloudflare storage.

The Bun Signal service remains active for platform ingress: Slack, Telegram, Discord, GitHub and
generic webhooks. A production cutover must keep those routes on Bun until their Worker adapters
are implemented and tested.

## Dependency order

1. Durable Object team signaling and TURN credentials.
2. Persistent revocation and auth-event handling.
3. Webhook delivery and sealed queue routing.
4. Telegram and Discord adapters.
5. Auth API URL cutover and removal of machine-specific Signal homes.

Each phase must pass the existing client protocol and security checks before the next phase is
enabled. No phase deploys Cloudflare resources automatically.

## Cost boundary

The Worker and Durable Object path uses request and duration quotas. TURN egress remains subject to
Cloudflare Realtime pricing and its shared monthly allowance. The Worker must never assume that a
free quota is unlimited or that it covers non-TURN traffic.
