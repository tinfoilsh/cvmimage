# Attested guest time

`GET /.well-known/tinfoil-attestation?format=v4&nonce=<64 hex characters>`
requests a fresh CPU quote containing guest clock evidence. The existing request
without `format` keeps its legacy or v3 response. An unsupported format, missing
nonce, or duplicate format/nonce is rejected. An unavailable, stale,
unsynchronized, or excessively uncertain clock returns HTTP 503; it never falls
back to a response without clock evidence.

The v4 response retains the v3 envelope shape and
`https://tinfoil.sh/report-data/v1` algorithm. Its document `format` is
`https://tinfoil.sh/predicate/attestation/v4`. The endorsed `device_evidence`
section contains exactly one additional item:

```json
{
  "id": "guest-clock",
  "kind": "guest-clock",
  "vendor": "tinfoil",
  "format": "https://tinfoil.sh/format/guest-clock/v1",
  "evidence": {
    "utc": "2026-10-01T12:00:00.123456789Z",
    "status": "synchronized",
    "uncertainty_ns": 25000000
  }
}
```

This is a clock assertion from the measured guest software. It is not a timestamp
supplied by the CPU's attestation hardware. `utc` is a fresh guest realtime sample,
normalized to UTC, taken after accepting the nonce and collecting collateral and
GPU evidence. `uncertainty_ns` is the trusted-time service's uncertainty estimate
at that sample, in integer nanoseconds. The producer rejects estimates above
`trustedtime.MaxUncertainty` (one second). `synchronized` means the sample passed
the trusted-time service's current quality, freshness, and consistency checks.
The bound remains conditional on that service's authenticated time source,
protected elapsed clock, and documented network-delay assumptions.

The item is serialized inside `device_evidence` before the existing section hash
and REPORT_DATA computation. The exact serialized clock bytes, nonce, TLS key,
and HPKE key are therefore bound by the same hardware quote. Existing GPU items
remain in that same endorsed section. No clock data is placed in unendorsed
collateral. A duplicate `guest-clock` ID is rejected.

## Verifier requirements

Client SDK support is a separate change. The pinned v3-only SDK rejects this v4
response; it does not verify guest time. A client requesting v4 must require v4
and the clock evidence explicitly, with no downgrade to v3 or legacy evidence.
Changing the outer format string is not itself a cryptographic operation: a
verifier must check both the required version and the endorsed clock item.

A v4 verifier must retain v3's strict parsing, challenge equality, exact-byte
section hashing, CPU signature and policy verification, collateral verification,
and TLS/HPKE channel binding. It must additionally require exactly one clock item
with the ID, kind, vendor, and format above; reject malformed, duplicate, missing,
or unknown clock fields/status; and enforce its own maximum uncertainty. It must
not trust the clock claim until the hardware quote and expected measured image
have been authenticated.

For a clock sanity check, record client UTC `C0` and a monotonic start time before
sending a cryptographically random nonce. Measure elapsed time `E` at receipt and
reject requests above a configured maximum round-trip duration. Given client
clock tolerance `B`, require the guest's claimed interval `[utc - uncertainty,
utc + uncertainty]` to lie within `[C0 - B, C0 + E + B]`. Use the client's clock
for collateral validity checks, not the guest's asserted timestamp. A client
without a trustworthy local clock cannot establish UTC correctness this way.

An accepted response describes one sample during that request. Host scheduling
and network delay can postpone the quote or its delivery, which is why clients
must enforce elapsed-time limits. The accepted clock window includes that
round-trip duration; it is not a submillisecond guarantee. This check does not
establish the clock's correctness before sampling or after receipt, validate
earlier authorization decisions, prevent a later pause, or provide anti-rollback
across guest restarts. Continued authorization needs the runtime time-health
gate and an explicit client policy for revalidation.
