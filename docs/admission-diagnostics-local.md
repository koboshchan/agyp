# Local admission investigation, not a diagnosed compatibility fix

The two client ErrorIDs are absent from the existing sanitized server logs. The
server did not emit those IDs. An unrelated successful usage row cannot establish
that either request reached Google. No actual failing request shape was obtained.

## Concrete boundary evidence

The Go local shim has three explicit 400s: invalid absolute proxy target, malformed
CONNECT authority, and failed body spool read. Each has a different plain-text
message. Transport JSON/schema/auth/path/frame violations close WSS with 1008,
not HTTP 400. The dispatched WSS promise catch emits JSON `Request rejected` for
pre-response admission 400/Zod errors. Upstream 400s instead emit `Upstream request
rejected` after a reservation and record zero usage. OAuth callback/state/token
400s are admin/auth flows, not Cloud Code generation. None is a proven attribution
of either reported client error.

All ten generation admission reasons and bounded-bootstrap JSON/schema failures
are exercised through authenticated loopback WSS with a fake upstream. Invalid
requests cause no upstream call, reservation or charge. A synthetic same-connection
first and history-shaped second turn succeed and account usage normally. This
shows that follow-up history alone is not sufficient to reproduce the report.

## Unproven compatibility candidates

A missing/nonobject internal `request`, mixed outer/inner config, nested public
request envelope, snake_case config, conflicting model sources, or noninteger /
out-of-range explicit output bound can all produce the reported generic boundary.
These are hypotheses only. No validator has been removed or widened. No thought
signature workaround is justified by the available evidence.

Matching official Linux agy 1.5.14 was checksum-verified against its published
archive SHA256 d58386322d2073e96b33f7cc32b4e9ae2db6228f58440369725967b2de48c7b5.
A bubblewrap test with isolated network/PID/mount namespaces, empty home/config,
minimal read-only runtime mounts, no host credentials and zero capabilities
verified external IPv4/IPv6 TCP/UDP and DNS blocked while loopback worked. Fixture
acp_token configuration was rejected before any loopback request. Static binary
inspection found zero `acp_token` occurrences but did find `AGY_ADC_AUTH` and
`AGY_LLM_GATEWAY_CLIENT_KEY` names. Those names do not establish a supported fixture
authentication format. No real authentication or credential extraction was tried.

## Local-only diagnostics design

`LocalAdmissionDiagnostics` is a memory-only collector. Runtime wiring is default
off and controlled by the bounded absolute deadline described below. There is no
HTTP/admin route or disk/stdout collection sink. It must not be deployed or enabled
without independent review and fresh user approval. The complete proposed operator
access and cleanup procedure is specified below, not authorized by this document.

Only admission 400s are collected, with enum reason, fresh random correlation ID,
enum HTTP method and exact fixed allowlisted Cloud Code path (or `other`). Queries
and model-bearing path segments never appear. The optional correlation ID is
returned in the error response as a field and a fixed message suffix. No raw error message is collected.

Shape summaries contain only position-specific fixed schema names and primitive
JSON types. Contents, parts, prompt text, declarations, headers and values are not
walked or retained. Unknown names are counted, never recorded or hashed. There
are no string lengths. Parsing is capped at 512 MiB, traversal at depth 3 / 32
fields, output records at 8 KiB and retention at 32 records. Snapshots are copies.
Known-key summaries may not identify a renamed unknown key; that is an intentional
privacy limitation, not permission to log arbitrary names. Canary tests cover
unknown keys, values, error strings, URLs, queries and snapshot mutation.

## Next evidence and approval gates

Independent review should examine privacy canaries, all admission reason paths,
unchanged auth/SSRF/allowances, bounded memory and default-off behavior. Existing
production metadata cannot recover a historical exact rejection. If no offline
fixture auth mechanism is established, any future runtime instrumentation needs a
separate reviewed activation plan, bounded retention/access control and explicit
user approval. Do not send another prompt or deploy this patch to obtain evidence.
Once a precise branch and sanitized shape are available, write a narrow synthetic
reproducer and only then propose the compatibility fix.

## Complete proposed activation scope, pending approval

This preparation now includes runtime wiring, a server-local helper and automatic
disablement. It is still local source only, not deployed or enabled. This section
supersedes the earlier no-wiring design above. Independent review must examine the
exact final commit, followed by fresh user approval of this entire finite scope.
Approval would permit only deployment of that reviewed image and one diagnostic
window as described here, not autonomous prompts, retries, releases or Mac changes.

The runtime remains off unless `AGYP_ADMISSION_DIAGNOSTICS_UNTIL` is explicitly set
to a 13-digit absolute Unix millisecond deadline no more than ten minutes ahead.
Malformed or excessively distant deadlines fail startup closed. A past deadline
means off, including after restart: restarting cannot extend the approved window.
No configuration, DNS, proxy, account, credential, model routing, request mutation,
validation relaxation, CLI installation or other container changes are in scope.
No upstream request is created by activation or retrieval.

Only the existing authenticated WSS dispatched-request admission catch collects.
It sees the already-buffered request, maximum 512 MiB. It does not read the socket a
second time. An admitted pre-upstream 400 is classified by a typed enum reason;
bounded eligibility JSON/schema failures have `invalid_bootstrap`. Records identify
source as `proxy_admission` or `bootstrap_admission`. Frame/auth/protocol closes,
OAuth/admin API failures, success and upstream rejections are deliberately omitted.
No existing logs are extended. The collector never inspects error message values.

Each retained record contains exactly version 1, a fresh UUID correlation ID,
allowlisted HTTP method or `other`, one of four fixed paths or `other`, a fixed
reason and source, and the bounded schema summary. The four paths are
`/v1internal:generateContent`, `/v1internal:streamGenerateContent`,
`/v1internal:loadCodeAssist`, `/v1internal:countTokens`. Public model paths become
`other`; model names, query parameters, client ErrorIDs, identities, timestamps,
headers, payload values, content and arbitrary key names are never recorded.
Schema names are fixed by position in `server/diagnostics.ts`. Unknown-key counts
saturate at 65535; root/known-field types and truncation are the remaining metadata.
A newly generated diagnostic ID is included as `error.correlationId` and in the
fixed error-message suffix `[agyp diagnostic <UUID>]` of that 400 response, and in
the corresponding record. Only the generated UUID is interpolated, never input. It is not derived from user input,
credentials, session IDs or upstream IDs. Default-off/expired/exhausted collectors
add no correlation ID. Ordinary client-generated ErrorIDs remain separate; Lucas
may need to provide the new correlation ID if his CLI displays or preserves it.

Records live only in process memory. At most 64 admission samples are processed
per activation, at most 32 records retained, each at most 8192 serialized bytes
(256 KiB record payload maximum). This also bounds diagnostic reparsing work.
Records become inaccessible after 120 seconds; a one-second sweep clears expired
memory entries, so physical retention is at most approximately 121 seconds while
the event loop runs. No content is written to disk/stdout by collection. Snapshot
retrieval intentionally emits only sanitized metadata to the trusted operator's
terminal; the operator must not redirect it to general logs. Activation expiry,
explicit stop and SIGTERM/SIGINT clear all records and disable collection. Expiry
closes control connections and unlinks the socket. Crashes lose all record memory;
a leftover socket is inert and causes the next activation to fail closed rather
than overwrite it. Host root controls memory/swap/core-dump policy; this feature
does not claim to defend against a host administrator.

Access is server-local OS access, not an API token. There is no HTTP retrieval or
activation route, no TCP listener and no browser/admin-panel UI. The control socket
is `$DATA_DIR/admission-diagnostics.sock` in the existing owned mode-0700 data
directory, socket mode 0600. Only the service UID or host/container root with OS
access may retrieve or stop. Possession of an agyp user/admin token alone grants
no access. Unsafe directories, symlinks and pre-existing socket paths are refused.
Two control connections maximum, a one-second idle limit, and fixed commands of
at most 16 bytes bound access. Commands are `snapshot` and `stop` only. The helper
validates directory/socket ownership and modes and bounds its response to 270000
bytes with a two-second timeout. It never reads account/key data.

For a reviewed, approved deployment, the operator sets the single absolute
activation deadline on ONLY the agyp container through its existing deployment
configuration and starts/recreates ONLY that service. Use the same reviewed image
for the whole diagnostic window. From that container's `/app` directory, the
server-local commands are `node scripts/admission-diagnostics.mjs snapshot` and
`node scripts/admission-diagnostics.mjs stop`, normally via the established local
container-exec access as the service UID/root. These commands accept no path or
metadata arguments. Stop is irreversible for that process's collector; subsequent
rearming would require a new future deadline and another separately approved
window. Never extend the deadline or retry a prompt automatically.

Historical evidence is unavailable. To observe an actual rejection, Lucas likely
must make ONE manual request during the approved window himself. Activation does
not authorize Kat/test workers to send any prompt. Request timing and choosing to
send it belong to Lucas. Retrieve once promptly after his reported failure, within
two minutes, then stop immediately, even if no useful record was captured. If the
client hides the correlation ID, a unique single manual rejection in that bounded
window is a lead, not a cryptographically proven join to the CLI ErrorID. Do not
claim exact attribution without the returned diagnostic correlation ID. This is
an explicit limitation of the current unmodified CLI.

Cleanup after retrieval or window expiry is to run the helper stop if it is still
available, remove the deadline environment override from ONLY agyp's deployment
configuration, and restart/recreate ONLY agyp with the SAME reviewed image. Verify
there is no diagnostic socket and the deadline override is absent/expired. No DB
restore or account changes are needed. A normal shutdown removes the socket; an
inert stale socket after a crash may be deleted only by the same trusted operator
after verifying the agyp process is stopped. No general directory cleanup.

Rollback is immediate helper stop (or ordinary agyp stop if unavailable), remove
the one deadline override, and restore ONLY agyp's pre-change image using the
existing preserved deployment configuration/data mounts. Never restore an old
SQLite database over live traffic. Verify service health, default-off control
absence and unchanged other services. Records are in-memory and disappear on
stop/restart, so rollback requires no record-file deletion. An independent reviewer
must sign off on the exact SHA before this proposal is presented for fresh user
approval; neither review nor this document authorizes deployment or activation.
