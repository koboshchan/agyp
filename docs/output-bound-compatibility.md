# Candidate uncapped-key output-bound compatibility change

This is a candidate policy compatibility fix, NOT a proven fix for Lucas's
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
unchanged. Accepting positive int32 values up to 2147483647 at the proxy does NOT
claim that every model accepts that value. Google remains the authority on
model-specific validation. No positive-minimum claim is inferred from int32.

## Offline matching-version construction evidence

Only the published-checksum-verified official agy 1.5.14 Linux x64 binary was
inspected. Archive SHA256:
d58386322d2073e96b33f7cc32b4e9ae2db6228f58440369725967b2de48c7b5.
It matches the installed Mac version, not the Mac binary's architecture.
No real credentials, history, config, prompts or network execution were used.
Original archive URL:
https://github.com/google-antigravity/antigravity-cli/releases/download/1.5.14/agy_cli_linux_x64.tar.gz

Read-only Go pclntab and ELF disassembly identify:

* DefaultChatModelConfig at 0x95d04c0 calls GetModelInfoFromKeyWithFallback
  (0x8446b60) with model key 0x138, then NewChatModelConfig. It does not directly
  supply a literal maxOutputTokens constant.
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
* ccpa.MarshalRequest at 0x8dd2c00 marshals the constructed request using the
  protobuf JSON encoder.

Thus construction supports model/config-derived signed int32 values, not a
fractional numeric sentinel. This is static dataflow evidence, not a captured
request. No universal exact default, no legitimate negative sentinel, and no
specific value used in Lucas's request was proven. Continuing without his config
or a newly approved observation cannot resolve that unknown by guessing.

Reproducible local evidence (outside the repo, not a production mount):
/home/kit/agyp-offline-shape/functions.json
/home/kit/agyp-offline-shape/ccpa-build.txt
/home/kit/agyp-offline-shape/disasm-0x95d04c0.txt
/home/kit/agyp-offline-shape/convert-0x8dd2c00.txt
/home/kit/agyp-offline-shape/model-fallback.txt

## Exact code scope

Only the maximum-output admission ceiling is conditional. A completely uncapped
key has allowance === null AND inputCap === null AND outputCap === null.
Store.Key and the keys SQL schema contain no separate totalCap: allowance is the
total input+output cap, enforced in Store.reserve. Non-null zero counts as a cap.
The period/reset policy does not determine whether a key is capped.

For uncapped keys, explicit output bounds must still be safe positive integers,
now at most 2147483647 (signed int32 maximum). For any capped key, the prior
1..131072 ceiling remains. Raw request bytes are never rewritten, clamped,
rounded, normalized, or given a fabricated sentinel. Missing output bounds retain
existing behavior. Zero, negatives, fractions, overflow, strings and other JSON
types remain rejected. All other shape/envelope/auth/host/SSRF/media/candidate/
thinking/admission and reservation rules are unchanged.

Upstream model rejection remains a sanitized upstream rejection. Successful
usage remains accounted normally; missing upstream usage conservatively falls
back to the already-validated explicit output bound. Reservations are released.
No bypass of bounded-key accounting or any collection controls is introduced.

## Verification and remaining decision

Authenticated synthetic WSS regressions exercise internal nested generate/stream
paths and canonical model generate/stream paths, all three individual caps,
zero caps, pairwise/all cap combinations, reset-period independence, and numeric
edge cases including 2147483647/2147483648 and safe-integer overflow. They verify
unchanged bytes, exact actual usage, conservative missing-usage fallback,
upstream 400 sanitization, rejection before upstream with zero charge, reservation
cleanup, and unchanged quota exhaustion.

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
/home/kit/agyp-offline-shape/output-policy-full.log.
