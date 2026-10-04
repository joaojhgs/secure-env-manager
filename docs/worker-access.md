# Separate-user Docker and restricted SSH

## What the manager now does

New `create`/`recreate` installations select only
`unix:///run/host/run/sem-docker/<environment>/docker.sock`. After the developer
account exists, the manager runs the host bootstrap using normal interactive
sudo. It does not use Docker to bypass sudo or retrieve the user's password.

The bootstrap provisions a locked, non-root `sem-build-<environment>` host user,
separate subordinate UID/GID range, rootless Docker and a private socket proxy.
The builder is not the human host user and is not in host docker/sudo groups.
Docker data is under `/var/lib/sem-builders/<environment>/.local/share/docker`.
The proxy is0660 with a mapped developer group, never0666, and connects only to
that builder's rootless daemon. Host rootful Docker workloads are not stopped.

A private ID-mapped bind view maps the developer home to the builder's identity;
RootlessKit privately binds that view at `/home/developer`. Compose bind paths
therefore match agent paths while new files retain developer ownership. The
installer tests0600 preservation/new-file ownership without recursively changing
the source home's permissions, ownership or ACLs. Unsupported mapping fails;
there is no permission-broadening fallback.

The synthetic mapping fixture is created with named root ownership, then assigned
explicit numeric UID/GID ownership using `chown`. Subordinate IDs do not require
host user accounts; this also supports older uutils `install` versions that reject
numeric owners without passwd entries. Only the tiny backup fixture is changed.

An existing host `/home/developer` is supported: RootlessKit represents it with a
symlink inside its private copy-up tmpfs. The launcher requires an exact private
tmpfs mount at `/home` before unlinking only that copied link and installing the
scoped bind mount. It never follows the link or deletes the original host home.
Unexpected real entries and missing/shared/non-tmpfs mounts fail closed.

Builder user services are enabled persistently with resource bounds (3GiB high,
4GiB maximum,1GiB swap;4096 tasks), bounded Docker logs and a separate user
manager. Only builder-account audio units are masked; human desktop services
are not altered or stopped. Encrypted source storage still needs to be unlocked
after boot. A missing source/builder/socket fails closed.

The manager verifies the developer can reach the API and that it reports
`name=rootless` BEFORE switching shell profiles. It never creates a host-root
Docker proxy. Existing `create` targets are refused rather than silently wiped,
stopped or reprovisioned. Explicit `recreate` remains a maintenance operation.

## Additive setup and deliberate sharing

Run as the regular rootless Podman owner:

```sh
./manage-safe-environement.sh setup-docker personal
./manage-safe-environement.sh setup-ssh personal
```

The existing developer must have no sudo/root-Docker grant. Rootless host tools
must already be installed: rootless Docker/dockerd, RootlessKit, newuidmap/
newgidmap, slirp4netns, socat, systemd user managers and ID-mapped mount support.
For Docker's supported prerequisites see
https://docs.docker.com/engine/security/rootless/ . Different distributions may
package these differently; the installer reports missing tools instead of
running an unpinned curl installer or changing a host's existing Docker engine.

Shared developer UID/GID across boxes is rejected by default. If sharing is
intentional, opt in explicitly:

```sh
./manage-safe-environement.sh setup-docker university --allow-shared-developer
./manage-safe-environement.sh setup-ssh university --allow-shared-developer
SEM_ALLOW_SHARED_DEVELOPER=1 ./manage-safe-environement.sh create university
```

The root bootstrap also exposes independent Docker-only staging:

```sh
sudo bash ./harden-worker-access.sh docker personal --allow-shared-developer
sudo bash ./harden-worker-access.sh stage personal /path/to/jump-key.pub \
    --ssh-port 24625 --allow-shared-developer
```

Docker-only staging does not require an SSH server/key and preserves an existing
approved SSH port. Environment names are1–22 lowercase letters/digits/underscores/
hyphens starting with a letter. Existing non-sem host group collisions are refused.
Per-environment builders remain separate service identities, but boxes sharing
a developer identity can reach one another's files and approved builder APIs.
**They are not separate security tenants.** Shared access never grants host-root
Docker by design, but old proxies must still be deliberately revoked.

## SSH behavior

Inner SSH is key-only developer SSH on a loopback port. It provides PTYs,
commands, file transfer and local forwarding. Optional host transport uses
`orca-jump`: root-controlled authorized key, strict scope dispatcher, exact
sudo command, no outer shell/PTY/forwarding. A valid scope name alone is not
authorization: the root-owned scope configuration AND exact sudo grant must
exist. Docker-only scopes do not receive that sudo transport grant.

Local aliases pin public keys obtained from trusted local host/container files.
Remote clients must pin the outer host's public key through a trusted channel.
The human host SSH credential is NOT needed by an agent controller. Inner SSH
authentication remains separate from the jump key. Nothing enrolls a machine
on Headscale or transfers keys to a VPS automatically.

## What this does not fix

Rootless Docker and restricted SSH reduce specific host privilege paths. They
are not proof of total host isolation. Distrobox explicitly documents its
host-integration/non-sandboxing goals:
https://distrobox.it/#security-implications . Audit the actual container rather
than trusting old security-report or README compliance claims.

On the current desktop personal environment, the following remain:

- Broad writable `/run/host`, host-home/storage, device/sysfs and temporary mounts.
  Host-home0700 denies the current developer but is not a container-root boundary.
- `SYS_ADMIN`/`SYS_PTRACE` and other capabilities; keep-id includes the human host
  identity. Container-root compromise can reach more than normal developer access.
- AppArmor unconfined and no enforced runtime no-new-privileges policy. The
  manager no longer puts every AppArmor profile in complain mode, but Distrobox's
  own defaults are not magically changed by that removal.
- Shared host networking, X11/audio/display/device integration. GUI/GPU utility
  exposes host attack/privacy surfaces and should be explicitly limited for workers.
- Inner SSH local forwarding combined with host networking can reach host-local
  services. Scope forwarding to approved development services or isolate the
  worker network; denying forwarding on the outer jump alone does not fix this.
- Existing storage currently observed as plain ext4 is not encrypted merely
  because optional LUKS/archive encryption is supported.

A stricter worker profile needs allowlisted mounts/devices, removal of unnecessary
capabilities, no human-host identity access, and a tested confinement/network
policy. Those mount/namespace/capability changes are not safely applied by
recursively changing active home permissions or restarting sessions unnoticed.
They require a deliberate maintenance migration or a separately authorized
parallel worker design. Current desktop agent/VNC sessions are not changed by
editing this repository.

On the notebook, personal/university/work sharing is explicitly acceptable to
the user for now, and moving work's endpoint is authorized too. All three remain
privileged: changing Docker/SSH endpoints alone does not fix that broader
boundary. Until deliberate activation, the legacy0666 proxy still exposes
host-root Docker to all three. The earlier work-only group ACL test failed and
was not installed; it is not the migration strategy.

## Existing notebook migration (including work)

Run on the notebook host, as its normal Podman owner, after reviewing the package:

```sh
sudo bash ./stage-notebook-workers.sh /path/to/jump-key.pub
```

This notebook-specific bootstrap stages all three rootless builders and restricted
SSH scopes, but does not change their old Docker endpoint. It backs up the old
proxy unit and records existing host workloads. A separate checkpoint socket
verifies actual peer routing to each private builder before activation. Current
configured inner ports are personal24625, university23389 and work24114; this
is not a generic replacement for detecting another machine's SSH configuration.

For already-running agents, a bounded low-privilege byte relay preserves the old
`/tmp/distrobox-docker.sock` path. Kernel `SO_PEERCRED` and the client's host-visible
Podman cgroup select a fixed rootless backend. Unknown peers are denied; no
client-selected destination, host-root Docker fallback or Docker payload logging
exists. The relay runs under the shared mapped developer identity, not root or
the human host user. Sharing between these boxes is intentional; the relay does
not turn shared identities into separate tenants.

Because systemd resolves both socket and service users through the host account
database, staging registers `sem-docker-relay` for that already-used mapped UID.
It is a locked, non-login system account with `/nonexistent` as its home, no home
creation, no subordinate-range allocation and only the existing mapped share
group. An unrelated UID collision, extra group, login shell or unlocked password
is rejected rather than silently reused or weakened. Relay peer checks still use
the numeric UID and exact container cgroups; the account grants no rootful endpoint.

The relay requires `ProtectProc=default` with `ProcSubset=pid`: its peer's cgroup
metadata must be readable across Podman user namespaces. `ProtectProc=invisible`
hid those peers even with matching mapped UIDs, as verified in the actual running
service namespace. Normal proc file permissions still apply; the relay has zero
capabilities (including no ptrace capability), no-new-privileges, protected homes,
read-only system paths, Unix-only sockets and exact UID/container routing checks.
This visibility exception exposes normally public process metadata, potentially
including secrets wrongly placed in world-readable command-line arguments; it is
not total process-metadata isolation. The relay itself reads only cgroup metadata.
No host-wide proc setting is changed. On staging retries only the old, idle,
unusable CHECKPOINT relay may be refreshed; changed PIDs or active client threads
abort. Primary relay, original Docker proxy, builders and Distroboxes are not
restarted by this compatibility refresh.

Only after testing builds, Compose bind ownership and nested SSH should the owner
run the narrowly granted activation operation:

```sh
sudo /usr/local/libexec/sem-notebook-docker-activate activate
```

It first tests all checkpoint routes, denies new legacy developer connections,
and aborts if the old socat listener has active client children. It retires only
that idle proxy and enables the persistent private relay. It does not stop the
host Docker engine, application containers, Distroboxes or existing terminals;
it does not delete/prune/migrate images or volumes. Failures after cutover are
fail-closed, with the original unit in a root-protected backup, not an automatic
host-root fallback. Existing host-root workloads keep running but are no longer
managed through the developer's new Docker API. Migrate them separately when needed.

OpenSandbox separately bind-mounts the real host Docker socket. That route is
not removed by replacing the distrobox proxy, and must be resolved before
cloud-worker approval. Do not restart/recreate it or claim complete isolation
without assessing its active sessions, data, network compatibility and authorized
maintenance boundary.

## Validation

```sh
bash worker-access/tests/rootless-policy.sh
bash worker-access/tests/relay-identity.sh
bash worker-access/tests/checkpoint-refresh.sh
PYTHONDONTWRITEBYTECODE=1 python3 worker-access/tests/test_docker_compat.py
```

This runs syntax/name validation and mock integration tests for private endpoint
selection, explicit sharing, bootstrap/API/non-rootless failures before profile
activation. It does not need sudo or change running services/containers.
The current desktop's live builder additionally passed Docker build, Compose
bind read/write,0600/new-file identity, kernel host-root Docker connection denial,
and nested SSH PTY/SFTP tests. The revised fresh-install pipeline still needs a
privileged end-to-end run on a disposable environment before claiming every
new installation/image is verified. Existing installed root-owned helpers are
not replaced merely by editing this checkout.

The relay tests cover approved/unknown/ambiguous/wrong-identity peers, fixed
backend validation and byte-stream half-close behavior. A metadata-only live
notebook probe additionally verified actual connections from all three developer
containers select their own scope and the human host identity is denied. That
probe never connects to Docker. The privileged staging checkpoint still needs
to validate production systemd protections and real builder API paths on each
new machine. On 2026-10-04 the existing notebook passed that checkpoint with
the corrected proc policy, then passed real image builds, Compose bind read/write
and developer-owned 0600 files on all three environments. Nested SSH, PTY/SFTP,
root-key denial, outer command/forwarding/PTY denial and an unapproved same-UID
cgroup rejection were also tested. The idle-only guarded activation succeeded;
all three old socket paths now reach rootless builders, with the twelve existing
host application containers and Distrobox start timestamps unchanged. The enabled
compatibility relay was using about 5.6 MiB with zero restarts at validation.

`tests/builder-smoke.sh` consumes the provided Dockerfile/Compose/input fixture tar
on stdin inside an environment and requires an explicit checkpoint or activated
compatibility endpoint. It validates the scope before any Docker writes, uses a
unique image/project and removes only its own fixtures, test image and network.
`tests/notebook-ssh-smoke.sh SSH_KEY_DIRECTORY NOTEBOOK_HOSTNAME` uses separately
pinned outer/inner host keys and the existing distinct client identities; its
SFTP round trip uses only the synthetic input. It does not modify SSH targets.

`tests/select-builder-context.sh SCOPE`, executed as developer through inner SSH,
selects a verified private Docker context without changing credentials or unrelated
selected contexts. The notebook contexts were activated for all three scopes.
Docker contexts fix CLI selection, not Docker SDKs: these still need an explicit
environment or socket configuration. `select-notebook-client-profiles.sh` is an
optional rootless-host-owner deployment for the current notebook's bash/zsh Docker
exports; it backs up only the edited home/system init files and profile and does not restart
the boxes. Connectivity loss proved to be a notebook reboot at 12:56 local time,
not an Orca restart. The newly uploaded helper was zero-filled and never ran.
Restored helper/assets only after hash/zero-fill checks, preserving prior bytes,
and deployed all three profiles successfully after reconnecting. Backup:
`/home/skyron/.local/share/sem-notebook-client-backup.voWgV4`. The persistent
compatibility endpoint and private builders also passed actual API checks after
the reboot; existing host app container IDs were retained and restarted by boot.
The user confirmed this was their intentional reboot, not an agent-issued action.
A second additive pass backed up the system zsh initializer too, at
`/home/skyron/.local/share/sem-notebook-client-backup.HzJs3c`, and sources the private
profile there for developer shells. This covers existing SSH namespaces that do
not see replacement home-init files; a Docker context alone is insufficient for
SDK environment inheritance. Fresh-install `setup-docker` uses the same system
zsh hook and places the home hook before non-interactive early returns.

The desktop's notebook SSH aliases were switched to the tested restricted jump
and pinned keys. Orca's separately saved manual targets still contain the old
proxy commands; they must be edited through the live desktop UI or an authorized
offline maintenance step before retiring its old unrestricted host credential.
Changing ssh_config alone does not override a manual target's explicit proxy.
Existing Orca sessions were left intact, and VPS worker enrollment remains blocked
by these and the broader privileged-container/OpenSandbox/network concerns.
