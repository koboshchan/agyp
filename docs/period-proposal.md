# Offline period implementation and deployment packet

Production remains c596037. No deployment, database migration, restart, config change,
or model request is authorized by the offline implementation/push approval.
Read repo instructions and standing workflows before executing any later packet.

Creation choices are never / 5h / weekly. Legacy daily/monthly keys remain readable
with their existing UTC accounting/reset semantics; creation UI/API no longer offer them.
Weekly is unchanged, Monday midnight UTC. Never uses lifetime actual recorded usage,
no reset. Cached tokens remain a subset of input, not an additional debit.

Five-hour windows start on the first admitted generation request, not key creation,
control requests, logins or quota reads. They are fixed, not sliding. Reads after
expiry show a fresh balance with no invented reset. The next generation request
anchors a new five-hour window at its actual request time, even after long inactivity.
SQLite IMMEDIATE transactions serialize anchoring/admission. Concurrent requests may
overshoot; only recorded provider usage is charged once. No reservation estimates,
output clamps or stream interruption. An exhausted migrated first request commits
its anchor before returning 429, so its carried balance can eventually expire.
Weekly keys show weekly own remaining/reset and 5h full; 5h keys show 5h own
remaining/reset and weekly full. Existing provider-family restrictions remain intact.

## Fresh read-only inventory

Queried 2026-11-22T05:44:14.687Z, not a reused usage snapshot. 17 total keys.
makieify daily total cap 10,000,000, input 25,489 / output 63 / cached 0 /
total 25,552, 26 recorded requests. Window Nov22 00:00Z to Nov23 00:00Z.
At that snapshot test-usage-half daily 1,000,000 had one synthetic 500,000-token
request. It has since been explicitly revoked and soft-deleted via normal admin
DELETE, exact id 03a3a493f0f87b7d. Verified old-session and fresh login 401.
Its synthetic request plus ten zero-token control records remain in history.
No monthly/weekly keys; other 15 were never, none active capped lifetime.
Fresh inventory and accounting MUST be taken again at migration execution time.

## Sole migration target and reviewable cutover mapping

Only makieify DAILY 10,000,000 to 5h 2,000,000. Never resurrect or migrate the old
test key. No blanket conversion. The isolated module has NO production imports or
CLI entrypoint. Test-only execution against temporary databases is not live approval.

Before any execution obtain fresh approval for the exact reviewed deployment packet,
verify a consistent backup and restore path, capture exact target id/name/old caps,
fresh actual current-day usage and its UTC-day start. Require exactly one target,
active nonadmin, old daily/10M, null split caps, no existing five-hour window.
The transaction compares the full expected proposal, including cutoff and usage,
then updates only that exact key and inserts its window. Fail closed on discrepancy.

Carry current daily usage by retaining its original rows and using that UTC-day
start as initial accounting_start. Anchor is NULL pending the first generation
request. That request fixes anchor to its own time, leaving accounting_start
unchanged until expiry. Nothing is copied or synthetic-debited for migration, so
usage is not counted twice and history is never rewritten/deleted. Subsequent expiry
sets both anchor and accounting_start to the next request time. In-flight responses
keep original request timestamps and are recorded once. Packet review must explicitly
approve this cutoff mapping, including delayed responses and migration across midnight.
At the fresh inventory example 25,552 carries into the 2M counter, not a reset to zero.
Execution uses a newly captured reviewable snapshot, not these documentary numbers.
A retry verifies exact migrated config/window and returns already-applied without
changing anchor, history or usage. Partial or mismatched state refuses execution.

## Separately gated postdeploy test steps

ONLY after fresh explicit deployment approval, successful period deployment and
verification, execute the authorized postdeploy test step. Do not create now.
Create normal nonadmin test-5h-half (5h, 1M) and test-weekly-half (weekly, 1M).
Per key, atomic transaction creates key plus exactly one explicitly TEST synthetic
usage row, model test-synthetic-usage, input/total 500,000, output/cached 0, status 200.
For 5h that synthetic first recorded request starts its fixed window exactly once.
Weekly uses the existing Monday UTC window. No provider/model calls.
Refuse any duplicate exact name, including revoked entries, with no silent retry.
Do not recreate test-usage-half. Verify actual admission usage and ordinary own-key
API display 50%, own reset, opposite bar 100%, one synthetic request and preserved
history. Normal-key requests must not access another key's usage.
Store returned tokens ONLY in mode-600 private files on default, never stdout/logs,
messages, repo, screenshots or command arguments. Use exclusive private-file creation
and verify paths before mutation. Private paths are
/home/kit/secrets/agyp-test-5h-half.key and
/home/kit/secrets/agyp-test-weekly-half.key. Relay paths plus sanitized proofs only.

## Usage UI

Overview aggregates all keys by exact model. Access-key Usage opens only that key's
model rows, including deleted-key history. High/medium/low variants stay separate.
Normal users receive only their own rows. Control fallback is not generation: model
is mandatory for generation. Label control records separately, preserve their counts
and tokens rather than silently dropping history. Fresh read-only investigation at
05:42:48Z saw 713 control records, zero tokens, 711 status200 and two502; do not infer
specific endpoint identities from this sentinel. Tests use fake upstreams only.
