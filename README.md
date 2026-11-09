# litterbox-local-relay

The push relay for Litterbox Local (the `whisker-local` repository).

Litterbox Local servers are self-hosted, but the published iOS app is signed by the maintainer.
Only the maintainer's Apple push key can deliver to it, so a self-hoster cannot send push themselves, and the key cannot be handed out because it can push to every install of the app.

The maintainer runs one instance of this relay and it holds that key.
A self-hosted server registers once, gets a scoped, revocable key, and from then on sends its alerts to the relay instead of to Apple.
Servers that never set a relay URL send nothing and need no account of any kind.

iOS goes straight to APNs with a `.p8` token key, with no Firebase involved.
Android needs Firebase, so it is not offered yet: an Android token is answered `unsupported`.
The FCM sender is still in the code behind `RELAY_FCM_CREDENTIALS_FILE`, so adding Android later is configuration and not a rewrite.

This is `check-in-relay` and `slim-m-relay` combined, with the same layout, Docker image and CI.
Read either of them first if you want to run a relay for your own build of the app.
From `slim-m-relay` it takes the APNs sender, the registration ceiling and the trusted-proxy setting, and adapts its token binding so that a token can have a few owners.
From `check-in-relay` it takes the visible title and body, where `slim-m-relay` sends encrypted wake-ups.

## What the relay sees

A short title and body, the device tokens to send to, a few data fields, and an optional collapse id.
It stores no notification content, only hashed keys and the token-to-key bindings, and it logs counts and the key id, never tokens or text.
The alert text is the same one-line message the app shows in its own alert history.
It contains no cat names or robot serial.

## Safeguards

- Each key is stored as a SHA-256 hash, so a leaked database yields nothing usable.
- The relay never stores or logs a server's public URL, since it has no use for one. `POST /v1/register` ignores its body.
- A device token has up to 3 owning servers. A phone's token only reaches servers that phone paired with, so a few is normal, and one server must not be able to lock a phone out of another: a fourth owner evicts the one that sent least recently. A token a key has not sent to for `RELAY_TOKEN_RETENTION_DAYS` is pruned.
- Revoking a key releases every token it held, and frees its registration slot, because the ceiling counts unrevoked keys only.
- A token APNs reports as `Unregistered`, `BadDeviceToken` or `ExpiredToken` comes back `unregistered` and all its bindings are released.
- A key whose recent results are mostly `unregistered` is revoked automatically, since it is guessing at tokens.
- iOS tokens must be hex of 64 to 200 characters, so junk never reaches Apple.
- Title, body and data are capped to fit APNs' 4 KB payload, and a data key named `aps` is refused.
- Limits, all in memory: per address (IPv6 counts as a /64) on registration, a global registration limit on top of it, per address on `/v1/send` ahead of the key lookup, per key counted in messages, per device token, and one relay-wide APNs budget. Requests to APNs run with bounded concurrency under a deadline.
- The client address is the first address in `X-Forwarded-For`, walking from the right, that is not a trusted proxy. The default trusted list is Cloudflare's published ranges plus private ranges, because Traefik sits behind Cloudflare. Every header line is read, and the header is believed only when the connection itself came from a trusted proxy.
- `/admin` is excluded from the public Traefik router and the container port is bound to loopback, so it is reachable from the host only. The admin token must be at least 32 bytes, and failed attempts are rate limited per address.
- The container is read-only apart from its data volume, drops every capability and cannot gain privileges.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/register` | none (rate limited) | Mint a key. The body is ignored. |
| `POST` | `/v1/send` | `Authorization: Bearer <key>` | Send `{"messages": [{"platform","token","title","body","data","collapseId"}]}`. `platform` is `ios` or `android`. Returns `{"results": [{"token","status"}]}` where status is `delivered`, `unregistered`, `rate_limited`, `unsupported` or `error`. |
| `GET` | `/healthz` | none | Liveness. |
| `GET` | `/admin/keys` | `Authorization: Bearer <admin token>` | List issued keys (metadata only). Host only. |
| `POST` | `/admin/keys/{id}/revoke` | `Authorization: Bearer <admin token>` | Revoke a key. Host only. |

Admin endpoints are only mounted when `RELAY_ADMIN_TOKEN` is set.
From the host, for example: `curl -H "Authorization: Bearer $RELAY_ADMIN_TOKEN" http://127.0.0.1:8090/admin/keys`.

## Running it

You need an APNs authentication key (`.p8`) from the Apple developer portal, its key id, your team id, and the app's bundle id.

```bash
cp .env.example .env          # fill in the RELAY_APNS_* values and RELAY_ADMIN_TOKEN
cp /path/to/AuthKey_XXXX.p8 ./apns-auth-key.p8
docker compose up -d
```

The compose file runs the relay behind Traefik on the `traefik_proxy` network, at `litterbox-relay.${DOMAIN:-npc-server.top}`, with Watchtower enabled.
It sets `RELAY_TRUST_PROXY=true`, which is only safe because Traefik is the only way in.
Without a proxy in front, leave it off, or any caller could choose its own rate-limit identity.
Behind Cloudflare the nearest hop is a Cloudflare edge address, so the default trusted list includes Cloudflare's ranges, which change rarely but do change.
Refresh `RELAY_TRUSTED_PROXIES` from `https://www.cloudflare.com/ips/` when they do.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_HTTP_ADDR` | `:8090` | Listen address. |
| `RELAY_DB_PATH` | `/data/relay.db` | SQLite store path. |
| `RELAY_ADMIN_TOKEN` | *(empty)* | Guards `/admin`, at least 32 bytes. Empty disables those endpoints. |
| `RELAY_APNS_KEY_PATH` | *(empty)* | Path to the `.p8` key inside the container. Compose sets `/run/secrets/apns-auth-key.p8`. |
| `RELAY_APNS_KEY_ID` | *(empty)* | The key's 10-character id. |
| `RELAY_APNS_TEAM_ID` | *(empty)* | Your 10-character Apple team id. |
| `RELAY_APNS_BUNDLE_ID` | *(empty)* | The app's bundle id, used as the APNs topic. |
| `RELAY_APNS_PRODUCTION` | `true` | `true` for the production gateway, `false` for the sandbox that debug builds use. |
| `RELAY_APNS_CONCURRENCY` | `8` | Simultaneous requests to APNs. |
| `RELAY_APNS_PER_MINUTE` | `600` | Relay-wide APNs message budget. |
| `RELAY_APNS_BURST` | `200` | Burst for that budget. |
| `RELAY_FCM_CREDENTIALS_FILE` | *(empty)* | Firebase service-account JSON. Optional, and Android sends only work with it. |
| `RELAY_TRUST_PROXY` | `false` | Read `X-Forwarded-For` at all. Compose sets `true`. |
| `RELAY_TRUSTED_PROXIES` | Cloudflare ranges + private ranges | Comma-separated CIDRs whose forwarding headers are believed. |
| `RELAY_REGISTER_PER_HOUR` | `5` | Per-address registration rate. |
| `RELAY_REGISTER_BURST` | `3` | Per-address registration burst. |
| `RELAY_REGISTER_GLOBAL_PER_HOUR` | `60` | Registrations from everywhere together. |
| `RELAY_REGISTER_GLOBAL_BURST` | `20` | Burst for that. |
| `RELAY_MAX_REGISTRATIONS` | `10000` | Unrevoked keys at any time. |
| `RELAY_SEND_IP_PER_MINUTE` | `120` | Per-address `/v1/send` requests, before the key lookup. |
| `RELAY_SEND_IP_BURST` | `60` | Burst for that. |
| `RELAY_SEND_PER_MINUTE` | `120` | Per-key send rate, counted in messages. |
| `RELAY_SEND_BURST` | `200` | Per-key send burst, in messages. |
| `RELAY_TOKEN_PER_MINUTE` | `6` | Messages to one device token. |
| `RELAY_TOKEN_BURST` | `10` | Burst for that. |
| `RELAY_MAX_MESSAGES` | `100` | Messages allowed in one `/v1/send`. |
| `RELAY_MAX_TOKENS_PER_KEY` | `50` | Device tokens one server may hold. |
| `RELAY_TOKEN_RETENTION_DAYS` | `90` | Unused token bindings are pruned after this. |
| `RELAY_ADMIN_FAIL_PER_MINUTE` | `5` | Failed admin attempts per address. |

The four `RELAY_APNS_KEY_PATH`, `_KEY_ID`, `_TEAM_ID` and `_BUNDLE_ID` values must be set together, and the relay refuses to start with only some of them.
It also refuses to start with no provider at all.

## Development

```bash
go test ./... -race
go build ./cmd/relay
```
