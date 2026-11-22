# Uniform exact-integer output-bound policy

This is the explicitly requested uniform 1..1000000 admission policy, NOT a proven fix for Lucas's
request. No deployment, activation, prompts, session access or upstream generation
is part of this change. Independent exact-SHA review and fresh communicated
approval are required before deployment or a real manual verification request.

## Exact observed boundary

The sole production observer matched correlation UUID
34c8891f-62bb-4757-a5b4-bbd95a266516 to proxy_admission, POST,
 /v1internal:streamGenerateContent, invalid_output_bound. The known field was
request.generationConfig.maxOutputTokens and its JSON type was number.
The rejection occurred before reservation, account routing or upstream dispatch.
No numeric value was retained. Fractional, nonpositive and above-policy-ceiling
subconditions cannot be distinguished retrospectively. Diagnostics were disabled
and cleared by the observer. Neither historic uncorrelated Google error ID proves
a matching request or any successful generation.

## Primary schema evidence and its limits

Google's own source defines GenerationConfig.max_output_tokens as optional int32,
with default varying by model via Model.output_token_limit:

https://github.com/googleapis/googleapis/blob/master/google/ai/generativelanguage/v1beta/generative_service.proto

Google's published REST reference likewise calls maxOutputTokens an integer,
the maximum number of response tokens, with model-dependent default:

https://docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1beta1/GenerationConfig

These sources establish signed int32 representation, not a universal legal model
maximum. They do NOT document a universal negative sentinel, fractional value, or
a universal positive minimum. The existing positive-only local policy remains
unchanged. The requested local maximum is now uniformly 1000000, not signed-int32 max.
Admitting a bound at this ceiling does NOT claim that every model accepts it. Google remains the authority on
model-specific validation. No positive-minimum claim is inferred from int32.

## Offline matching-version construction evidence

Only the published-checksum-verified official agy 1.5.14 Linux x64 binary was
inspected. Archive SHA256:
d58386322d2073e96b33f7cc32b4e9ae2db6228f58440369725967b2de48c7b5.
It matches the installed Mac version, not the Mac binary's architecture.
No real credentials, history, config, prompts or network execution were used.
Original archive URL:
https://github.com/google-antigravity/antigravity-cli/releases/download/1.5.14/agy_cli_linux_x64.tar.gz

Read-only Go pclntab entries in functions.json are relative offsets, not ELF
virtual addresses. Adding the ELF Go text base 0x72a5080 yields the addresses
below; each address is cross-checked against its saved disassembly.

Verified relative entry / symbol / ELF address:

* 0x11a1200 / model_config.DefaultChatModelConfig / 0x8446280
* 0x11a1ae0 / model_config.GetModelInfoFromKeyWithFallback / 0x8446b60
* 0x1b1f0c0 / ccpa.BuildRequest / 0x8dc4140
* 0x1af5c00 / v1main_prediction_service_go_proto.GenerationConfig.GetMaxOutputTokens / 0x8d9ac80
* 0x1b2db80 / ccpahttp.MarshalRequest / 0x8dd2c00

Observed instructions:

* DefaultChatModelConfig at 0x8446280 loads 0x138 at 0x844628e and
  0x84462a3, then calls GetModelInfoFromKeyWithFallback at 0x8446299 and
  0x84462ae. It does not directly supply a literal maxOutputTokens constant.
  The earlier attribution to 0x95d04c0 was incorrect: that address maps to
  CodeAssistClient.generateContentFromCCPA.deferwrap1 and its saved disassembly
  contains an indirect closure call, not model-key/fallback construction.
* ccpa.BuildRequest at 0x8dc4140 reads a model-derived value from the object's
  offset 0x88 at 0x8dc535e. A model-derived flag gates whether an override is
  consulted. At 0x8dc5374..0x8dc5394 a nonzero ChatNodeConfig
  signed-32-bit maxOutputTokens field (offset 0x14) overrides that model value.
  At 0x8dc53a0 a nonzero result is allocated into a 32-bit pointer value and
  stored in the GenerationConfig field (offset 0x28). If the result is zero,
  this allocation branch is skipped. This is omission, not proof of a zero
  output sentinel on the wire.
* The generated GenerationConfig.GetMaxOutputTokens at 0x8d9ac80 loads that
  pointer at offset 0x28 and reads its 32-bit value.
* ccpahttp.MarshalRequest at 0x8dd2c00 marshals the constructed request using the
  protobuf JSON encoder.

Thus construction supports model/config-derived signed int32 values, not a
fractional numeric sentinel. This is static dataflow evidence, not a captured
request. No universal exact default, no legitimate negative sentinel, and no
specific value used in Lucas's request was proven. Continuing without his config
or a newly approved observation cannot resolve that unknown by guessing.

Reproducible local evidence (outside the repo, not a production mount):
/home/kit/agyp-offline-shape/functions.json
/home/kit/agyp-offline-shape/ccpa-build.txt
/home/kit/agyp-offline-shape/disasm-0x8446280.txt
/home/kit/agyp-offline-shape/disasm-0x95d04c0.txt (incorrect prior attribution, retained for audit)
/home/kit/agyp-offline-shape/convert-0x8dd2c00.txt
/home/kit/agyp-offline-shape/model-fallback.txt

## Exact code scope

Every explicit canonical generationConfig.maxOutputTokens must be a mathematical
positive integer in 1..1000000, regardless of key type or reset period. This
supersedes the earlier proposed uncapped-int32 exception and the old bounded
131072 ceiling. Neither exception remains in the code.

All allowance, inputCap and outputCap admission/reservation checks remain active.
Store.Key and SQL have no separate totalCap: allowance is the input+output cap.
Non-null zero counts as a cap. Bounded keys still require an explicit output
bound, one candidate and text-only requests; the thinking budget still cannot
exceed the reserved output. A valid 1000000 bound can still receive quota rejection
when its key lacks sufficient remaining budget. Missing bounds retain existing
behavior for unlimited keys. The raw request is never rewritten or clamped.

A pinned lossless-json 4.3.4 parse inspects the same canonical output field without
conversion. Its exact decimal comparison must equal the already range-checked
JavaScript integer. Thus exponent/fraction forms that are mathematical integers
remain valid, but rounded near-integers cannot pass. The parser rejects conflicting
duplicate members, including escaped names and envelope/config duplicates;
identical duplicate members are unambiguous and remain accepted. Parser errors
are mapped to a fixed admission error, never its value-bearing error text.
Unrelated fields retain their original raw spelling.

Library research used the maintained upstream README/API and installed source,
since chub searches had no matching documentation entry:
https://github.com/josdejong/lossless-json

Zero, negatives, mathematically fractional numbers, values over 1000000, overflow,
strings and other JSON types are rejected. All other auth/host/SSRF/media/
candidate/thinking admission and reservation rules remain unchanged.

Upstream model rejection remains a sanitized upstream rejection. Successful
usage remains accounted normally; missing upstream usage conservatively falls
back to the already-validated explicit output bound. Reservations are released.
No bypass of bounded-key accounting or any collection controls is introduced.

## Verification and remaining decision

Authenticated synthetic WSS regressions exercise all four canonical internal/
model generate/stream paths. The cap matrix covers all 27 combinations of absent,
zero and positive allowance/inputCap/outputCap across never/daily/weekly/monthly
periods. They verify 1/1000000 admission as budgets permit, quota exhaustion,
1000001 rejection, exact byte preservation, actual usage and conservative
missing-usage fallback, upstream 400 sanitization, and zero charges/reservations
after rejected requests.

Raw-literal cases include the review's 2147483647.0000001,
2147483646.99999999, 131073.000000000001, former-ceiling
131072.000000000001, new-ceiling 1000000.00000000001,
999999.99999999999 and lower-bound 0.99999999999999999. Exponents,
huge exponents, long fractional tails, escaped member names, duplicate
output/config/envelope keys, numeric-object impersonation, prototype keys and
unrelated nested numbers/strings are covered too.

Next, obtain independent review of this exact commit. Present it explicitly as a
candidate, including the unresolved actual numeric subcondition. After fresh
deployment approval, deploy only the reviewed SHA with diagnostics off, verify
health and rollback readiness without generation, and only after explicit prompt
approval have Lucas make his own one manual request. No automated retry.
If it still rejects, stop; use a separately approved short-lived diagnostic window
with fixed boolean classification counters for each output predicate (not values)
and one explicitly approved manual request. That would require a further reviewed
instrumentation change; it is not secretly enabled here. If Google rejects the
forwarded positive bound, do not clamp it: report the upstream boundary and stop.
Rollback is the previously deployed c72da8d09d0000f7d4186c84c871f74876097504
image/config, with diagnostic deadline override absent. No data migration.

Validation on the candidate passed all 54 TypeScript tests, TypeScript check and
build, Go race tests, vet and build, and npm run test:cli (real Go CLI against
synthetic local upstream only). Logs are local under
/home/kit/agyp-offline-shape/output-policy-1m-full.log.
Actual Docker build/smoke and independent exact-SHA review remain required
before the authorized agyp-only deployment. No worker may issue real prompts.
