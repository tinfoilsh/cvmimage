# Online authorization cache

A successful validation may include `X-Tinfoil-Auth-Cache-Ttl-Ms`, a positive
integer duration of at most 30,000 milliseconds. The validator caches that
positive result for the SHA-256 digest of the complete validation payload.
Validity starts when the online request starts, so transit time consumes it;
cache hits never extend the deadline. Expired entries require a new online
check, including during a control-plane outage.

Missing, invalid, excessive, or ambiguous metadata keeps validation online.
Rejections are not cached. `/metrics` always stays online regardless of cache
metadata, preserving its separate admin-only policy and existing server cache.
The cache holds at most 10,000 entries and retains no raw credential values.
Concurrent cold misses can each validate independently.

The control plane supplies durations bounded by hard key expiration and does
not grant cache permission to free-tier keys or keys with token, cost, or
request quotas. Deploying this validator against an older control plane keeps
the existing per-request validation behavior. Both direct and routed inference
calls benefit when their model shim receives cache permission; router admission,
rate limiting, JWT verification, and billing are separate from this cache.
