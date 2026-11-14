# Cloudflare remote infrastructure handoff

Status: code and dry-run verification complete on the fork branch; no Cloudflare resource has been
created or deployed by this work.

## Repository state

- Fork: `https://github.com/okayfine996/openbot`
- Branch: `codex/cloudflare-turn`
- Current head: `bb00bfe`
- PolyForm Noncommercial 1.0.0 remains the repository license. Personal, noncommercial use is the
  intended safe boundary; commercial hosting or resale needs separate permission review.

## Core path

The core remote path does not require Discord:

1. Auth Worker + D1 keep users, devices, host registration, memberships, invitations and sessions.
2. Signal Worker + one Durable Object validate tickets, pair Team clients, relay SDP/ICE and issue
   bounded Cloudflare Realtime TURN credentials.
3. Existing Team API remains on the host's WebRTC `rpc`, `events` and `files` data channels.
4. Slack, Telegram, GitHub and generic webhooks are optional connector ingress paths. Discord is an
   optional connector; its Gateway migration is isolated from Team access.

## Operator inputs before any deployment

Provide through a secret manager or Cloudflare dashboard, never through chat or git:

- Cloudflare account and intended Workers/Durable Objects plan.
- A narrowly scoped Realtime TURN credential-generation token and TURN key ID.
- `REMOTE_SESSION_SECRET`, `REMOTE_AUTH_WEBHOOK_SECRET`, ticket private/public keys and the Auth
  Worker JWKS URL.
- The intended Signal Worker hostname and DNS/custom-domain ownership.
- Optional `REMOTE_SIGNAL_WORKER_URL` and `REMOTE_SIGNAL_INGRESS_WORKER_URL` values.
- Optional connector secrets: Slack signing secret, GitHub webhook secret, Telegram bot values, and
  Discord bot/application values.
- A quota/egress alert destination and a rollback owner.

## Dry-run verification

Run from the repository root before enabling any URL:

```sh
bun run --cwd apps/signal-worker typecheck
bun run --cwd apps/signal-worker test
bunx wrangler deploy --dry-run --config apps/signal-worker/wrangler.jsonc --env=""
bun run --cwd apps/auth-api typecheck
```

The Wrangler command must end with `--dry-run: exiting now.` It must not be replaced with `deploy` as
part of a code review or local verification.

## Cutover order

1. Deploy Auth Worker changes and confirm existing Auth/D1 tests and health checks.
2. Deploy Signal Worker with production secrets and no connector URL changes.
3. Set only `REMOTE_SIGNAL_WORKER_URL` for a Team canary; confirm direct ICE, TURN fallback,
   reconnect, session revocation and Team `rpc/events/files` behavior.
4. Enable `REMOTE_SIGNAL_INGRESS_WORKER_URL` for one connector canary, then verify route wake,
   host-side signature validation, queue flush/ACK, retries and revocation.
5. Monitor DO duration/request quotas, TURN egress and connector error rates before expanding.
6. Roll back by clearing the optional Worker URLs; Bun remains the fallback path.

## Hard stop conditions

Stop the canary and clear the Worker URLs if any of these occur:

- Ticket, session or route revocation is delayed or accepted incorrectly.
- Team API frames, files or chat payloads leave the existing WebRTC data channels.
- A queued connector event is delivered without host decryption/ACK, is duplicated beyond the
  documented retry behavior, or is persisted as plaintext.
- TURN or outbound Discord Gateway duration/egress approaches the alert threshold.
- Any Cloudflare pricing or free-allowance condition differs from the current official terms.

## Current non-deployment evidence

- Worker typecheck passes.
- Worker focused tests pass, including ingress and shared Discord normalization tests.
- Auth API typecheck passes for the changed routing files.
- Wrangler package dry-run passes with Durable Object and TURN bindings and performs no deployment.
