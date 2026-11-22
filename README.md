agyp keeps a shared Google account pool on one server and connects local agy processes to it. The server is TypeScript on Node.js 24 with SQLite, a browser dashboard, and a Go CLI wrapper. This repository stays private until publication is explicitly approved.

The deployment target is https://agy.kjt.lol. The dashboard, authentication, and inference endpoints share one public HTTPS port. Docker listens internally on 54873; the supplied Compose file exposes it only to the existing `oneserver_bridge` network and does not publish a host port. Configure the HTTPS reverse proxy separately to forward to `agyp:54873`, preserving streaming responses and allowing long requests. Private deployment is pending. Real Google OAuth and compatibility with the actual agy client remain untested.

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

Build the CLI with Go 1.23 or later, or use a release archive for Linux amd64/arm64 or macOS arm64 once a release exists.

```sh
(cd cli && go build -trimpath -o ../agyp .)
export AGYP_BASE=https://agy.kjt.lol
read -r -s AGYP_TOKEN
export AGYP_TOKEN
./agyp -- agy
```

The CLI binds an ephemeral loopback listener, authenticates to the server, and launches the supplied command. It sets a per-launch capability-prefixed `CLOUD_CODE_URL` plus authenticated Basic forward-proxy variables, and removes `AGYP_TOKEN` from the child environment. The child must honor those settings. HTTPS CONNECT traffic is tunneled, not decrypted or rewritten; clients that ignore `CLOUD_CODE_URL` and use HTTPS directly may bypass inference routing. Test the actual agy version before relying on this integration.

Login sends a key ID, a one-time 60-second nonce, and `HMAC-SHA256(key, nonce)`, never the permanent raw key. Sessions last at most 15 minutes and are stored hashed in the database. The browser uses an HttpOnly cookie with CSRF checks; the CLI uses a short-lived bearer session. Key creation is the deliberate exception where the administrator receives the new raw key once.

Permanent API keys are stored in plaintext in the private, mode-600 SQLite database, by design. Google account credentials are AES-256-GCM encrypted with `seal.key`, also mode 600, beside the database. The data directory is mode 700. Filesystem or volume access therefore exposes both API keys and the account decryption key. Restrict host access and protect backups, `.env`, and logs. Back up the entire `agyp_data` volume consistently while the service is stopped, including `seal.key`; losing that file loses access to saved account credentials. Never commit runtime data or credentials.

For local checks, use Node.js 24 and Go 1.23 or later.

```sh
npm ci
npm run build
npm test
npx playwright install --with-deps chromium
npm run test:browser
npm run test:integration
npm run test:cli
(cd cli && go vet ./... && go test -race ./...)
```

`CHROME_BIN` can select an existing Chromium executable. `test:browser` exercises the mocked UI contract. `test:integration` runs Chromium against the real Express server and SQLite database, and `test:cli` runs the real Go CLI against a fake Google upstream. Both integration suites pass locally; real Google OAuth and the actual agy client remain untested. CI runs these suites, Go vet and race checks, and cross-compiles the CLI. Pushing an approved `v*` tag runs those checks again and publishes three CLI tarballs with SHA-256 checksums to a GitHub release. Creating a tag or release does not deploy the server.
