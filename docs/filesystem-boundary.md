# Filesystem-only Distrobox restriction

This policy removes implicit host root, human home and temporary-directory
mounts, not the desktop integration/capability policy. It deliberately preserves
the requested GPU, audio, display, webcam, devices, capabilities and namespaces.
It is **not** a complete hostile-code sandbox: X11/audio/device access, network
services and retained capabilities still have security implications.

## Future creation

`manage-safe-environement.sh create` uses a private PATH adapter for Podman during
Distrobox creation. The upstream Distrobox entrypoint/export/enter functionality
is retained. `--home` is only the administrative container user's private home,
not a host-home security mask. Broad mounts are removed before creation, not
hidden with a reversible tmpfs mounted on top of the host's home.

The allowlist contains the isolated developer home, administrative home, existing
`/dev` and `/sys` integration, Distrobox helpers, narrow public configuration and
font/theme directories, X11/Wayland/PulseAudio/PipeWire endpoints, `/run/udev`,
and this environment's private Docker socket directory. Neither host SSH/GPG
agent sockets nor arbitrary host runtime directories are forwarded. A broad
unknown bind mount fails closed rather than silently weakening the boundary.

X11 keys are streamed into the container by generated app launchers; they do not
require sharing host `/tmp`. The installer transfers only the Pulse cookie into
the developer's isolated home. Audio bridges use only the explicitly mounted
audio endpoint, not a host-home path.

`verify` examines actual mounts and probes host SSH directory visibility as both
developer and container root when running. Checking `chmod 700` alone is no
longer considered proof of isolation. Existing containers are not modified by a
repository update; use a deliberate, backed-up migration.

## Existing desktop, minimal-change cutover

Never apply this to notebook boxes while their sessions must remain running.
First choose a healthy filesystem with enough free space for the encrypted
backup **and** compressed staging/snapshot. Keep the recovery key protected and
outside the developer home; do not send it to an agent controller.
Pause automatic SSH/on-demand container-start probes during the offline export
and its verification/cutover; they must not restart the source during archiving.
One rootless alternative is a temporary offline name: rename `personal` to
`personal-offline` before export, so existing on-demand connectors cannot start
it by its usual name. Check for connector implementations using stored IDs first.
On failure rename the original back and start it. After successful export use
`restrict-filesystem.py personal-offline ... --target-name personal --apply`.
The policy still uses `personal` for the private Docker socket and integrations,
and retains the stopped original for rollback. Restore that package with the
explicit destination name `personal`, not its temporary offline name.

```sh
# recovery.key must already exist, owned by the Podman owner, mode 0600.
# exclusions.txt is optional: exact verified regenerable relative paths only.
bash ./manage-safe-environement.sh export personal /safe/path/personal.sem.gpg \
  --passphrase-file /safe/path/recovery.key \
  --exclude-file /safe/path/exclusions.txt --stream-home --keep-snapshot --leave-stopped

# Check/decrypt the backup and validate its inner checksums before applying.
python3 worker-access/restrict-filesystem.py personal /safe/path/personal.sem.gpg --apply
```

The export stops ONLY the selected container for a consistent snapshot. Failure
automatically restarts it. Only successful `--leave-stopped` hands off cutover.
The recovery package includes the installed OCI image, both persistent homes,
named-volume data (excluding kernel PTY state), original definition and checksums.
The in-place migration does NOT restore/extract these homes: it keeps their
existing bind mounts. The package is for disaster recovery, not routine cutover.
The replacement reuses the snapshotted installed system, original isolated-home
bind, existing journal/PTY volumes and original engine creation flags. It refuses
unexpected changes to privilege, capabilities, device configuration, shared
memory or namespaces. The original stopped container is retained under a
timestamped rollback name; no homes, images, volumes or worktrees are pruned.

Before declaring completion, check root/developer filesystem boundaries, SSH
PTYS/SFTP, private rootless Docker build/Compose/0600 bind ownership, and baseline
X11/hardware GPU/audio/video integration. Keep the rollback until these pass.
Check GPU access as `developer`, not container root, and require a physical GPU
from Vulkan/OpenGL rather than accepting CPU `llvmpipe`. For an existing mapped
identity, the host `enable-gpu-access.sh` helper grants only DRM-node access and
backs up the original ACLs; it never broadens filesystem permissions or privileges.
Original sessions cannot survive replacing a container; host Orca/VNC and other
environments must not be restarted as part of this operation.

To roll back, stop the replacement, rename it to a diagnostic name, rename the
retained original back to `personal`, then start it. This restores the old mount
exposure too; it is a recovery action, not a security fix. Backup/restore never
overwrites an existing home; restore into a fresh path when recovering data.
