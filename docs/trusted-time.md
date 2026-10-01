# Authenticated guest time

The measured kernel requires a protected TSC before starting userspace. TSC
protects elapsed time; it does not establish the UTC date. Provisioning waits for
Chrony to authenticate UTC before creating identities, verifying attestations,
retrieving secrets, or obtaining certificates.

## Authority and bootstrap

The image uses NTS with `ntp-bootstrap.ubuntu.com` and the dedicated certificate
from its pinned Ubuntu Chrony package. This reuses the image's package supply
chain and adds trust in Canonical's time service to report correct UTC. Existing
ATC collateral and keyserver TLS do not supply an authenticated current date.

Only that certificate set is allowed. System CAs, unauthenticated NTP, DHCP time
sources, the host RTC, and persisted clock state are not bootstrap authorities.
Certificate dates are waived before the first clock update; hostname and
certificate authentication remain required. The daemon permits one initial step
and does not restart. Certificate/key rotation requires an image update.

NTS is the standard authenticated NTP protocol. See
[Ubuntu's NTS bootstrap documentation](https://ubuntu.com/server/docs/how-to/networking/chrony-client/#network-time-security-nts)
and [RFC 8915's initial-time discussion](https://www.rfc-editor.org/rfc/rfc8915.html#section-9.3).

## Runtime bounds

PID 1 reads Chrony's private Unix socket every second. Accepted observations
require an external synchronized source, a reference at most five minutes old,
and a total UTC error bound at most one second. The bound includes system
correction, root dispersion, half the root delay, query latency, and clock drift.
Bootstrap is limited to five minutes. Leap-warning states fail closed.

The drift allowance assumes physical oscillator error within 100 ppm. Secure TSC
and TDX do not themselves certify that accuracy. Chrony's configured frequency,
skew, and error limits are consistency checks, not proof of the oscillator's
accuracy or of the authority's honesty. Authenticated packets can still be
delayed; the delay and error limits bound accepted observations under these
assumptions. Withholding packets can deny service.

Checkpoints are local, volatile, and checked against `CLOCK_MONOTONIC_RAW` on each
read. A checkpoint expires after five seconds even if the monitor is paused.
Observed wall-clock correction and elapsed-time drift enlarge its error bound.
Provisioned shim handlers reject requests without usable time. After initial
synchronization, an invalid observation aborts service groups with bounded
shutdown instead of reopening bootstrap or waiting indefinitely for requests.

The host can stop scheduling the whole VM or individual vCPUs. A request check
cannot prevent a pause immediately afterward; existing streams and arbitrary
container operations are not continuously time-verified. Normal shutdown also
retains graceful draining. Clients need a fresh nonce and a local deadline when
using an attested timestamp. Hardware boot, NTS connectivity, and scheduling
fault tests remain required before enabling this image in production.
