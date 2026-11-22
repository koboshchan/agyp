<div align="center">

<strong>agyp</strong>

A self-hosted Antigravity gateway, with a web dashboard and terminal client.

[![CI](https://github.com/koboshchan/agyp/actions/workflows/ci.yml/badge.svg)](https://github.com/koboshchan/agyp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/koboshchan/agyp)](https://github.com/koboshchan/agyp/releases)
[![License](https://img.shields.io/github/license/koboshchan/agyp)](LICENSE)

[Get started](#get-started) · [Host a server](#host-a-server) · [Quotas](#quotas-and-usage) · [Development](#development)

</div>

Keep Google account credentials on your server and give clients separate access keys. The Go CLI runs `agy` through an authenticated WebSocket connection; the React dashboard manages the account pool, access keys, and usage history.

The gateway supports streaming responses, per-key model restrictions, token caps, and never-resetting, five-hour, or weekly accounting periods. Administrators can inspect usage by key and model, including deleted-key history. Regular users see only their own usage.

<a id="get-started"></a>
**Get started**

You need access to an agyp server, a user key issued by its administrator, and an installed `agy` executable. Download your platform archive from [Releases](https://github.com/koboshchan/agyp/releases/latest), verify it against `checksums.txt`, extract it, and place `agyp` or `agyp.exe` on PATH.

| Platform | Archive |
| --- | --- |
| Linux x64 / ARM64 | `agyp-linux-amd64.tar.gz` / `agyp-linux-arm64.tar.gz` |
| macOS Apple Silicon | `agyp-darwin-arm64.tar.gz` |
| Windows x64 / ARM64 | `agyp-windows-amd64.zip` / `agyp-windows-arm64.zip` |

Set `AGYP_BASE` to your server's HTTPS origin and provide `AGYP_TOKEN` privately through your shell environment or secret manager. Do not paste the key into commands saved in shell history.

```sh
export AGYP_BASE=https://agyp.example.com
# Supply AGYP_TOKEN privately before running.
agyp --version
agyp -- agy
agyp -- agy --conversation=EXISTING_ID
```

PowerShell uses `$env:AGYP_BASE = 'https://agyp.example.com'`; supply `AGYP_TOKEN` through the same private mechanism you use for other credentials. The CLI does not save environment variables or edit shell profiles. Building it from source requires Go 1.23 or newer.

```sh
git clone https://github.com/koboshchan/agyp.git
cd agyp
(cd cli && go build -trimpath -o ../agyp .)
```

<a id="host-a-server"></a>
**Host a server**

The supplied [Compose configuration](compose.yaml) expects Docker Compose, an existing external network named `oneserver_bridge`, and an HTTPS reverse proxy on that network. It exposes port 54873 inside Docker only, not on the host.

```sh
git clone https://github.com/koboshchan/agyp.git
cd agyp
cp .env.example .env
# Edit .env for your own deployment before starting.
docker compose up -d --build
docker compose logs agyp
```

| Setting | Purpose |
| --- | --- |
| `PUBLIC_ORIGIN` | Your public HTTPS origin, such as `https://agyp.example.com` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Credentials for your Google OAuth application |
| `OAUTH_REDIRECT_URI` | Registered OAuth callback; default `http://localhost:54874/oauth/callback` |
| `TRUSTED_PROXIES` | Exact proxy addresses or a narrowly scoped proxy subnet; empty trusts none |

Change the example origin in `.env`; it is not a shared service configuration. Configure your own OAuth application for the callback URI. The dashboard's account flow asks you to paste the full callback URL after Google redirects to localhost.

Route HTTPS traffic to `agyp:54873`. The reverse proxy must preserve streaming and forward WebSocket upgrades on `/transport`. Use an idle timeout longer than 45 seconds; the transport sends heartbeats every 15 seconds.

The server prints a new admin token at every startup. Use it to sign into the dashboard, add Google pool accounts, and create ordinary user keys for clients.

> [!WARNING]
> Startup logs contain the admin token. Restrict log access, protect `.env`, and never distribute the admin token as a client key.

<a id="quotas-and-usage"></a>
**Quotas and usage**

Each key can restrict models and set token caps. A null cap is unlimited; a zero cap denies usage. The period controls when usage resets, not whether the key has a cap.

| Period | Reset behavior |
| --- | --- |
| `never` | Usage accumulates without a scheduled reset |
| `5h` | First admitted generation anchors a five-hour window; control requests do not start it |
| `weekly` | Monday at 00:00 UTC |

Admission checks already-recorded usage. After a response, agyp charges the actual Google-reported usage to the request's admission window. It does not reserve an estimate in advance, so concurrent requests or a single large response can exceed the remaining cap. Missing usage metadata contributes zero recorded tokens. Media requests are allowed on capped keys.

Explicit `maxOutputTokens` must be an integer from 1 to 1,000,000; upstream model limits still apply. Omitting it is supported. Finite-cap keys reject unclassified actions rather than treating them as free.

The dashboard separates control traffic from generation usage and shows input, output, cached, and noncached totals. Soft-deleting a key preserves its history.

**Transport and storage**

The client authenticates with HMAC-SHA256 using a connection-specific challenge, then multiplexes requests over WSS at `/transport`. Reconnection performs authentication again. Dispatched requests and partial streams are not automatically replayed. The browser and legacy REST path use challenge-based login, HttpOnly session cookies, and CSRF protection.

The CLI starts an authenticated loopback bridge and supplies `CLOUD_CODE_URL` and proxy settings to its child. It removes `AGYP_TOKEN` from the child environment. HTTP is allowed only for loopback server origins.

> [!IMPORTANT]
> This is an application gateway, not a transparent TLS interception proxy. CONNECT tunnels are not decrypted. A client that ignores `CLOUD_CODE_URL` may bypass gateway routing.

The Node.js/Express server stores data in SQLite; the React UI is built separately, and the Go client lives in [cli/](cli). Google credentials are encrypted with AES-256-GCM using the adjacent `seal.key`. Permanent access keys remain plaintext in the private database. Protect the entire data directory and its backups.

Compose persists state in `agyp_data`. For a consistent backup, stop the service and back up the whole volume, including `seal.key`; the database alone cannot restore encrypted credentials.

<a id="development"></a>
**Development**

Use Node.js 24+ and Go 1.23+. These commands build and test locally; they do not deploy a server.

```sh
npm ci
npm run build
npm run build:web
npm test
npm run test:browser
npm run test:integration
npm run test:cli
(cd cli && go test -race ./... && go vet ./...)
```

See [CI](.github/workflows/ci.yml) for platform builds and test setup. Tagged releases publish five client archives and checksums; releasing a client does not deploy the server or update existing installations.

Code is [MIT licensed](LICENSE); dependency notices are in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Google account access and upstream service terms are separate.
