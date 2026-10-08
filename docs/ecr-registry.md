# ECR credential refresh

The operator can supply the reserved `ECR_REGISTRY_AUTH` secret in external
configuration. Its JSON contains `host` (the private ECR registry hostname),
`org_id`, and `token` (a refresh credential issued by the controlplane).

Boot stores this configuration in `private/docker-config/ecr-refresh.json` on
the private ramdisk with mode 0600. It is not mounted into ordinary workloads.
The container manager requests a fresh password immediately before each pull
from the matching hostname. Other registries keep their existing Docker auth
behavior. No AWS access key is needed in the guest.

Requests go only to
`https://api.tinfoil.sh/api/internal/registry/ecr/token`, with the refresh
credential in the Authorization header. Redirects are not followed. Responses
must match the configured host, use username `AWS`, contain a password, and
have more than five minutes remaining before expiry. Network failures, 429s,
and 5xx responses receive bounded retries; other errors fail the pull.

The manager does not cache the password or fall back to a saved Docker password
when refresh is configured. This covers reboots, delayed initial boots, and
later pulls using the same saved external configuration. Docker restarts that
use an existing local image do not need a new registry password.

The refresh credential survives same-host AWS key rotation. Deleting the
connection or changing its hostname revokes future refreshes; re-adding it
requires a new managed deployment. Already-issued ECR passwords are governed
by AWS's validity and access policy. Refresh credentials are scoped to the
organization's registry connection, not individually revocable per instance.

Roll out this guest image and rebuild the measured workload release before
relying on automatic refresh. The controlplane must also include its ECR
refresh endpoint. Existing guest images do not gain this behavior automatically;
the controlplane retains initial Docker credentials for their compatibility,
but those images retain the 12-hour recovery limitation.

Validation uses simulated ECR/broker HTTP responses, including expired saved
passwords, revocation, redirects, and wrong-host responses. Before production
rollout, verify a real ECR pull and a subsequent reboot/re-pull using the same
external configuration after the original password expires.
