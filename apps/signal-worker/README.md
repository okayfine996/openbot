# OpenBot Signal Worker

This Worker is the Cloudflare Durable Objects implementation of the Team WebRTC Signal path.

It keeps the released Signal frame contract. A single `SignalRoom` object currently owns host and
client sockets, ingress webhook sockets, SDP/ICE relay, resume tokens, ticket replay records and
Cloudflare Realtime TURN credential refresh. Team data still stays on the WebRTC `rpc`, `events`,
`files` and `desktop` channels.

`POST /v1/webhooks/:routeId` forwards the exact body and signed headers to the host. The host remains
the trust boundary for webhook HMAC verification. The Worker stores neither the body nor the headers.

The existing Bun Signal service remains the migration path for Slack, Telegram, Discord, GitHub and
generic webhook ingress until those routes are moved into the Worker. Do not point production
ingress at this Worker until that migration is complete.

## Local checks

```sh
bun run --cwd apps/signal-worker typecheck
bun run --cwd apps/signal-worker dev
```

## Required secrets

- `REMOTE_SESSION_SECRET`: the resume-token signing secret shared with the control plane policy.
- `CLOUDFLARE_TURN_KEY_ID`: the Realtime TURN key ID.
- `CLOUDFLARE_TURN_API_TOKEN`: a token that can generate TURN credentials for that key.

The Wrangler migration and deploy commands are intentionally not run by repository checks.
