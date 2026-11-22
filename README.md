agyp keeps a shared Google account pool on one server and connects local agy processes to it. The server is TypeScript on Node.js 24 with SQLite, a browser dashboard, and a Go CLI wrapper. This repository stays private until publication is explicitly approved.

The deployment target is https://agy.kjt.lol. The dashboard, authentication, and inference endpoints share one public HTTPS port. Docker listens internally on 54873; the supplied Compose file exposes it only to the existing `oneserver_bridge` network and does not publish a host port. Configure the HTTPS reverse proxy separately to forward to `agyp:54873`, preserving streaming responses, WebSocket upgrade headers on `/transport`, and long requests. Set its WebSocket idle timeout above 45 seconds; the server sends heartbeats every 15 seconds. The private dashboard is deployed. Native Google OAuth and compatibility with the actual agy client still need separate verification.

With Docker Compose installed and the external proxy network already present, prepare the server from the repository root.

```sh
cp .env.example .env
chmod 600 .env
# Fill in the Google OAuth client settings and public origin in .env.
# Set TRUSTED_PROXIES only to the exact proxy address or a narrow proxy subnet.
docker compose up -d --build
docker compose logs agyp
```

The administrator token is printed on EVERY server startup, including restarts. Treat Docker logs as credentials. Open the public origin and log in with that token. Add Google accounts through the dashboard. With the example loopback OAuth redirect, finish Google consent locally and paste the complete callback URL into the dashboard; no second public port is needed. The redirect must match the Google OAuth client configuration.

Create named user keys in the dashboard. Keys support total, input, and output token allowances, optional expiry, and never/daily/weekly/monthly reset periods. Calendar resets use UTC, with weeks starting Monday. Administrators can manage accounts and keys and inspect per-key/model input, output, cached, and noncached usage. Ordinary keys can view only their own usage. Save a newly created key when it is shown; normal API responses do not reveal it again.

Quotas use the admission window. A request admitted before a UTC reset is charged to that prior window even if it finishes after the reset. In-flight reservations count toward that window's allowance, so concurrent requests cannot spend the same remaining budget.

Keys with any finite token allowance are text-only for generation. Media and `cachedContent` are rejected until count-safe support exists, and `candidateCount` must be 1. Admission reserves a conservative input upper bound of request-body bytes plus 1024 tokens, along with `maxOutputTokens` for output. A request can be rejected when that upper bound does not fit, even if its eventual token usage would have fit. Reported usage replaces the reservation on completion; if generation usage is missing, the reservation is charged instead of treating the request as free.

Build the CLI with Go 1.23 or later, or use a release archive for Linux amd64/arm64, macOS arm64, or Windows amd64/arm64. Windows archives are ZIP files containing agyp.exe.

```sh
(cd cli && go build -trimpath -o ../agyp .)
export AGYP_BASE=https://agy.kjt.lol
read -r -s AGYP_TOKEN
export AGYP_TOKEN
./agyp -- agy
```

On Windows, extract the ZIP and run `agyp.exe -- agy` from PowerShell or Git Bash. Set `AGYP_BASE` and `AGYP_TOKEN` only in the current shell process; the CLI does not modify profiles or persist credentials. It shares the caller's console for Ctrl-C/Ctrl-Break, restores console modes, and places its child tree in a private kill-on-close job. Windows ARM64 builds require separate native validation on ARM64 hardware.

The CLI binds an ephemeral loopback listener, authenticates to the server, and launches the supplied command. It sets a per-launch capability-prefixed `CLOUD_CODE_URL` plus authenticated Basic forward-proxy variables, and removes `AGYP_TOKEN` from the child environment. The child must honor those settings. HTTPS CONNECT traffic is tunneled, not decrypted or rewritten; clients that ignore `CLOUD_CODE_URL` and use HTTPS directly may bypass inference routing. Test the actual agy version before relying on this integration.

Browser and legacy REST login send a key ID, a one-time 60-second nonce, and `HMAC-SHA256(key, nonce)`, never the permanent raw key. REST sessions last at most 15 minutes and are stored hashed in the database. The browser uses an HttpOnly cookie with CSRF checks. The current source CLI instead opens one WebSocket with subprotocol `agyp.v1` at `/transport` and authenticates using a fresh connection-specific salt and nonce: `HMAC-SHA256(key, "agyp-ws-v1\\n" + salt + "\\n" + nonce)`. No REST session or bearer token is created for that connection. Use HTTPS/WSS outside loopback. Key creation is the deliberate exception where the administrator receives the new raw key once.

The WebSocket multiplexes bounded request streams through the existing admission, quota, rotation and usage-accounting pipeline. Each connection supports at most eight active requests, a 64 KiB frame limit, 16 MiB per body, 32 MiB aggregate in-flight bodies per connection (64 MiB server-wide), and a ten-minute request deadline. Responses stream in 32 KiB chunks; a stalled reader is canceled rather than holding up unrelated requests. Revocation and expiry are checked before each new request. After a disconnect, only a new caller-initiated request reconnects and reauthenticates. Dispatched requests, including partial output, are never automatically replayed. A transport failure can therefore return an error even if the provider already performed billable work; retrying is the caller's explicit decision.

Permanent API keys are stored in plaintext in the private, mode-600 SQLite database, by design. Google account credentials are AES-256-GCM encrypted with `seal.key`, also mode 600, beside the database. The data directory is mode 700. Filesystem or volume access therefore exposes both API keys and the account decryption key. Restrict host access and protect backups, `.env`, and logs. Back up the entire `agyp_data` volume consistently while the service is stopped, including `seal.key`; losing that file loses access to saved account credentials. Never commit runtime data or credentials.

For local checks, use Node.js 24 and Go 1.23 or later.

```sh
npm ci
npm run build
npm run build:web
npm test
npx playwright install --with-deps chromium
npm run test:browser
npm run test:integration
npm run test:cli
(cd cli && go vet ./... && go test -race ./...)
```

`CHROME_BIN` can select an existing Chromium executable. `test:browser` exercises the mocked UI contract. `test:integration` runs Chromium against the real Express server and SQLite database, and `test:cli` runs the real Go CLI against a fake Google upstream. Both integration suites pass locally; real Google OAuth and the actual agy client remain untested. CI runs these suites, Go vet and race checks, and cross-compiles the CLI. Pushing an approved `v*` tag runs those checks again and publishes three CLI tarballs and two Windows ZIPs with SHA-256 checksums to a GitHub release. Creating a tag or release does not deploy the server.

### Google request compatibility

The Google routing layer tracks switcher commit `b48b163`: forced refresh and same-account retry on 401, structured verification exclusion and direct quota rechecks, Argon Ultra promotion and Pro weekly-trial fallback, provider-family exhaustion, early cooldown recovery after a healthy quota poll, and reactive Gemini thought-signature repair. Ordinary generation bodies retain their original JSON bytes and user agent. Only a routed model change or a provider-requested signature repair changes the body. The authenticated response header `x-agyp-upstream-model` identifies the selected model without exposing the underlying account.

There is deliberately no default output-token injection. A key with any finite allowance must supply an explicit canonical `generationConfig.maxOutputTokens`; missing bounds return 422 before admission. Unlimited keys may omit it. Bounded keys remain text-only, single-candidate and subject to conservative byte-based input reservation, including any reactive repair. A reset period of `never` means the allowance does not reset, **not** unlimited access. Unlimited allowances are represented by omitted/null caps; a cap of zero allows no spending.

The Cloud Code surface follows the switcher's unrestricted method forwarding inside `/v1internal:` and `/v1internal/` service namespaces, plus the existing `/v1` and `/v1beta` model actions. GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS are supported through authenticated REST and multiplexed WebSocket transport. The CLI uses the same path/method matrix. Request bytes, response bytes and unknown response fields are preserved, including `loadCodeAssist`, `onboardUser`, model discovery, quota, experiments and metrics. Account routing, model fallback and thought-signature repair retain the previously documented behavior.

This is not an arbitrary-host tunnel. Fixed upstream origin, localhost capability authentication, WebSocket HMAC proof, administrative/credential-management denial, canonical path validation, private header filtering, 16 MB requests, ten-minute deadlines and sanitized provider failures remain security boundaries. CONNECT and TRACE are not proxied as Cloud Code operations. Provider redirects are not followed. Native OAuth and actual agy-client compatibility require separate real-client checks; fake-upstream tests do not establish either.

Normal unlimited keys may invoke the full service surface, including unknown future operations, with ordinary concurrency admission and usage accounting. Bounded keys may invoke recognized generation with conservative reservation and known read-only/telemetry controls; unclassified actions return 422 before dispatch because their maximum token cost cannot be established. This restriction does not apply to unlimited normal keys. Bounded-key `POST /v1internal:loadCodeAssist` retains the strict read-only bootstrap, accepting only `metadata.ideType` equal to `ANTIGRAVITY`, with fixed server-owned body and tier-only response. Unlimited keys receive the actual upstream response instead. A failed or usage-less known generation retains its conservative charge, not zero.

The shared fixture `test/fixtures/cloudcode-paths.json` is exercised at the Go CLI boundary, REST adapter, authenticated WebSocket adapter, and actual Go-to-Node transport. It covers named operations, future namespace actions, all supported methods, query fidelity, bounded-key denial, administrative denial and SSRF/path ambiguity rejection.
