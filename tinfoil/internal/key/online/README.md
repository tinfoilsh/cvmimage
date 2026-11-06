# Lazy online authorization checks

A successful validation may include `X-Tinfoil-Auth-Cache-Expiry`, containing
either the key's hard expiration as an RFC 3339 timestamp or `none` for an
eligible key with no hard expiry. The validator remembers a positive allowance
for the SHA-256 digest of the complete validation payload in a bounded LRU.
This header is explicit permission for optimistic admission with revalidation;
it does not establish a time-based revocation grace period.

Unknown keys and contexts validate synchronously. A remembered eligible key can
start a request immediately while the shim rechecks it in the background. At
most one background check runs for a given grant. A denial, transport failure,
timeout, or successful response withdrawing cache permission removes the
allowance; subsequent requests validate synchronously. Already-admitted requests
continue, and a late success cannot restore an allowance invalidated by an
overlapping check.

Remembered allowances can survive idle periods. The first request after a long
idle may therefore start before a revocation is discovered. Hard key expiration
is checked locally before optimistic admission; a synchronous check can establish
whether the key has been renewed. This policy does not promise that revocation
blocks every admission within 30 seconds of an administrative change.

The cache holds at most 10,000 credential/context digests and expiry values,
without retaining raw credentials. At most 128 detached checks run concurrently;
additional keys fall back to synchronous validation when that capacity is busy.
Checks use the existing 10-second HTTP timeout. Concurrent cold misses can each
validate independently, preserving per-request checks for noncacheable keys.

Missing, malformed, ambiguous, and legacy TTL metadata do not grant lazy reuse.
`/metrics` always stays synchronous regardless of metadata. The control plane
withholds permission from free-tier keys and keys with token, cost, or request
quotas. Mixed deployments with an older control plane retain per-request online
validation. Direct and routed calls benefit at the model shim; router admission,
rate limiting, JWT verification, and billing remain separate.
