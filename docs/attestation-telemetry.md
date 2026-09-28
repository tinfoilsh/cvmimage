# Attestation SDK telemetry

Clients may send `Tinfoil-SDK` and `Tinfoil-SDK-Version` on attestation requests. Both headers are optional and self-reported; they do not affect verification or authorization. SDK names are `tinfoil-go`, `tinfoil-js`, `tinfoil-python`, and `@tinfoilsh/verifier`.

The shim exports `tfshim_attestation_requests_total` through `/.well-known/metrics`, using the existing metrics bearer token. Labels identify the endpoint (`unversioned` or `v3`), the served attestation version (`v2`, `v3`, or `none` on errors), the SDK and its version, and the result (`served`, `client_error`, `server_error`, or `other`). The metric also carries the enclave's `id`, `domain`, and `image` labels.

Missing or unrecognized SDK names map to `unknown`. Versions accept semantic versions with an optional `v` prefix, plus `devel` and `unknown`. Invalid versions or values longer than 64 bytes map to `unknown`. The process retains at most 128 distinct SDK/semantic-version pairs, plus the fixed fallback labels; additional versions map to `other` while previously observed versions keep their counters. Counters persist across scrapes.

These are attestation request counts, not unique clients, connections, or successful verifications. No nonce, client address, API key, or client identifier is recorded. Relays should preserve the originating SDK headers; a harness that independently requests attestation should identify its own SDK.
