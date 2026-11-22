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

`LocalAdmissionDiagnostics` is an explicitly injected memory-only test collector.
No entrypoint, config, environment variable, network/admin route or disk/stdout
sink enables/exposes it. Default production behavior is unchanged. It must not be
deployed or wired into a running service without independent review and fresh user
approval. There is intentionally no operational collection step in this patch.

Only admission 400s are collected, with enum reason, fresh random correlation ID,
enum HTTP method and exact fixed allowlisted Cloud Code path (or `other`). Queries
and model-bearing path segments never appear. The optional correlation ID is
returned in that local fixture's error response. No raw error message is collected.

Shape summaries contain only position-specific fixed schema names and primitive
JSON types. Contents, parts, prompt text, declarations, headers and values are not
walked or retained. Unknown names are counted, never recorded or hashed. There
are no string lengths. Parsing is capped at 16 MiB, traversal at depth 3 / 32
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
