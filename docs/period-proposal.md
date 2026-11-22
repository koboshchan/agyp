# Period proposal, inactive

No production imports, endpoint/UI changes, schema changes, or migrations are included.
The pure helper is intentionally disconnected. Do not wire it into admission, storage,
or REST/WSS quota responses until the outstanding decisions are resolved.

New creation choices will be never / 5h / weekly. Existing daily/monthly records must
remain readable and retain their existing accounting and reset semantics. Removing
creation choices must not prevent unrelated edits to a legacy key or reset its usage.

The helper requires an explicit fixed five-hour anchor. Key creation time is proposed,
not selected. Sliding windows are different semantics and are not implemented here.
Weekly windows remain Monday midnight UTC. In display, weekly keys use their own
weekly fraction/reset with 5h full; 5h keys use their own 5h fraction/reset with weekly
full. The other bar has no invented reset. This helper does not change provider-family
allow/deny rules or synthesize an underlying account quota.

Before activation decide the five-hour anchor, whether/how to treat the existing
legacy daily key (default action here is no action), and how to display lifetime-capped
never keys. A distinct lifetime balance without recurring reset is proposed, not wired.
No allowance may be discarded or key automatically converted. No active capped never
key was present in the read-only inventory, but compatibility must still cover them.

Keep actual Google usage accounting, concurrent overshoot, denylist, and REST/WSS
presentation parity unchanged. Future integration must use one key-specific window
for both recorded-usage queries and display reset; never infer it from provider buckets.
No model calls or production migration are needed to test these proposals.
