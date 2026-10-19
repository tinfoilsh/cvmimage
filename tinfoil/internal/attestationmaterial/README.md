# Collateral request protocol

New boots send request `version: 2`, with `repo`, optional `tag`, and `document`.
The document is a standard v3 attestation generated with a random preflight
nonce and empty crypto-material, device-evidence, and collateral arrays. Its
CPU quote binds the crypto-material and device-evidence sections. Collateral
remains outside that binding so ATC can fill it in. The raw boot quote remains
available for legacy boot consumers; it is not wrapped into the v3 document.

ATC derives hardware collection inputs from the document, fills only its
collateral array, and runs the existing SDK verifier before returning the
ordinary collateral response. The preflight nonce is not an ATC challenge and
does not establish liveness or authorize a connection. Clients still obtain
and verify their own fresh documents.

Deploy ATC's version-2 handler before releasing this image. Unknown versions and
verification failures do not trigger a downgrade. Unversioned/version-1 stored
requests remain readable for existing boot artifacts and dummy mode. Protocol
versioning is independent of attestation v3 and the collateral response format.
