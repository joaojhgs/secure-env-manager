#!/usr/bin/env bash
# Stage isolated builders and a transport-only SSH account. Never enroll a VPS.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
create_idmap_fixture() {
  local fixture="$1" mapped_uid="$2" mapped_gid="$3"
  # Older uutils install resolves numeric owners as account names. Subordinate
  # IDs need not have host passwd entries; use chown's explicit numeric syntax.
  install -d -o root -g root -m 0700 "$fixture"
  chown -- "+$mapped_uid:+$mapped_gid" "$fixture"
  printf 'synthetic permission test\n' > "$fixture/key-mode-test"
  chown -- "+$mapped_uid:+$mapped_gid" "$fixture/key-mode-test"
  chmod 0600 "$fixture/key-mode-test"
}
usage() {
  echo 'Usage: sudo ./harden-worker-access.sh docker ENV [--allow-shared-developer]' >&2
  echo '       sudo ./harden-worker-access.sh stage ENV PUBLIC_KEY_FILE [--ssh-port PORT] [--allow-shared-developer]' >&2
}
die() { echo "ERROR: $*" >&2; exit 1; }
[[ $# -ge 2 && ( "$1" == stage || "$1" == docker ) ]] || { usage; exit 64; }
mode="$1"
scope="$2"
[[ "$scope" =~ ^[a-z][a-z0-9_-]{0,21}$ ]] || die 'Environment name must be 1–22 lowercase letters, digits, underscores or hyphens, starting with a letter.'
shift 2
public_key_path=''
requested_port=''
allow_shared=false
if [[ "$mode" == stage ]]; then
  [[ $# -ge 1 ]] || { usage; exit 64; }
  public_key_path="$(realpath -e -- "$1")"
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-shared-developer) allow_shared=true; shift ;;
    --ssh-port)
      [[ "$mode" == stage && $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 1024 && "$2" -le 65535 ]] || die 'Expected --ssh-port 1024..65535 for stage.'
      requested_port="$2"; shift 2 ;;
    *) usage; exit 64 ;;
  esac
done
[[ "$EUID" == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || die 'Run with sudo as the rootless Podman owner.'
owner="$SUDO_USER"
script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for tool in podman rootlesskit dockerd-rootless.sh dockerd newuidmap newgidmap slirp4netns socat useradd usermod loginctl systemctl systemd-escape runuser mount umount findmnt groupadd curl sha256sum; do
  command -v "$tool" >/dev/null || die "Missing prerequisite: $tool (no packages are installed automatically)."
done
if [[ "$mode" == stage ]]; then
  for tool in sshd visudo nc ssh-keygen; do command -v "$tool" >/dev/null || die "Missing prerequisite: $tool"; done
  [[ -f "$public_key_path" && ! -L "$public_key_path" ]] || die 'Expected a regular public-key file.'
  [[ "$(wc -l < "$public_key_path")" == 1 ]] || die 'Expected exactly one public key.'
  read -r key_type key_body key_comment < "$public_key_path"
  [[ "$key_type" == ssh-ed25519 && "$key_body" =~ ^[A-Za-z0-9+/]+=*$ ]] || die 'Expected an Ed25519 public key, not a private key or key options.'
  ssh-keygen -lf "$public_key_path" >/dev/null
fi
for asset in sem-builder-dockerd sem-ssh-dispatch sem-worker-connect; do
  [[ -f "$script_root/worker-access/$asset" ]] || die "Missing package asset: $asset"
done
owner_uid="$(id -u "$owner")"
owner_env=(env "XDG_RUNTIME_DIR=/run/user/$owner_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$owner_uid/bus")
as_owner() { runuser -u "$owner" -- "${owner_env[@]}" "$@"; }
as_owner podman container exists "$scope" || die 'Existing environment not found; nothing will be recreated.'
[[ "$(as_owner podman inspect --format '{{.State.Running}}' "$scope")" == true ]] || die 'Keep the existing environment running for staging.'
source_home="$(as_owner podman inspect --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}' "$scope")"
[[ -n "$source_home" && "$source_home" == /* && -d "$source_home" && ! -L "$source_home" ]] || die 'Developer bind source is ambiguous.'
source_home="$(realpath -e -- "$source_home")"
[[ "$source_home" != / && "$source_home" != /home && "$source_home" != "/home/$owner" ]] || die 'Refusing a broad host-home builder grant.'
# Compose both namespace mappings; a home directory's owner alone is not proof
# of the developer identity. Podman keep-id maps through its owner's namespace.
map_id() {
  awk -v id="$1" '$1 <= id && id < $1+$3 { print $2+id-$1; found=1; exit } END { if (!found) exit 1 }'
}
developer_uid="$(as_owner podman exec --user developer "$scope" id -u)"
developer_gid="$(as_owner podman exec --user developer "$scope" id -g)"
parent_uid="$(as_owner podman exec --user developer "$scope" cat /proc/self/uid_map | map_id "$developer_uid")"
parent_gid="$(as_owner podman exec --user developer "$scope" cat /proc/self/gid_map | map_id "$developer_gid")"
developer_host_uid="$(as_owner podman unshare cat /proc/self/uid_map | map_id "$parent_uid")"
developer_host_gid="$(as_owner podman unshare cat /proc/self/gid_map | map_id "$parent_gid")"
[[ "$(stat -c '%u:%g' "$source_home")" == "$developer_host_uid:$developer_host_gid" ]] || die 'Developer home ownership does not match the running namespace mapping.'
[[ "$developer_host_uid" != 0 && "$developer_host_uid" != "$owner_uid" ]] || die 'Developer home must be owned by an isolated mapped UID.'
# Existing boxes can share subordinate IDs even when their names differ.
# Shared identities may be deliberately accepted for host-only isolation.
# They never provide inter-environment isolation, so require an explicit flag.
while IFS= read -r other_scope; do
  [[ "$other_scope" == "$scope" ]] && continue
  other_home="$(as_owner podman inspect --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}' "$other_scope")"
  [[ -n "$other_home" && -d "$other_home" ]] || continue
  other_identity="$(stat -c '%u:%g' -- "$other_home")"
  if [[ "${other_identity%%:*}" == "$developer_host_uid" || "${other_identity##*:}" == "$developer_host_gid" ]]; then
    [[ "$allow_shared" == true ]] || die "Environment $other_scope shares the developer UID/GID with $scope; use --allow-shared-developer only if cross-environment access is acceptable. No changes made."
    echo "WARNING: $scope and $other_scope share a developer identity; their data and builder APIs are NOT isolated from each other." >&2
  fi
done < <(as_owner podman ps --all --format '{{.Names}}')
ssh_port=''
if [[ "$mode" == stage ]]; then
  ssh_port="$requested_port"
  owner_home="$(getent passwd "$owner" | cut -d: -f6)"
  metadata="$owner_home/.config/secure-env-manager/ssh/$scope.env"
  if [[ -z "$ssh_port" && -f "$metadata" ]]; then
    ssh_port="$(sed -n 's/^SEM_SSH_PORT=//p' "$metadata")"
  fi
  if [[ -z "$ssh_port" ]]; then
    ssh_port="$(as_owner podman exec --user developer "$scope" sh -c "ss -H -ltn | awk '\$4 ~ /127[.]0[.]0[.]1:[0-9]+\$/ { sub(/.*:/,\"\",\$4); if (\$4 == 2223 || \$4 == 24625 || \$4 == 23389) print \$4 }'")"
  fi
  [[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1024 && "$ssh_port" -le 65535 ]] || die 'Could not resolve exactly one approved container SSH port; use --ssh-port.'
  as_owner podman exec --user developer "$scope" /usr/bin/nc -z 127.0.0.1 "$ssh_port" || die 'Existing container SSH is not ready.'
  global_allow="$(sshd -T | awk '$1 == "allowusers" { print }')"
  if [[ -n "$global_allow" ]]; then
    [[ " $global_allow " == *' orca-jump '* ]] || die 'Existing host AllowUsers requires deliberate review before adding the jump account.'
  fi
  if [[ -e /etc/ssh/authorized_keys/orca-jump ]]; then
    read -r installed_type installed_body _ < /etc/ssh/authorized_keys/orca-jump
    [[ "$installed_type" == "$key_type" && "$installed_body" == "$key_body" && "$(wc -l < /etc/ssh/authorized_keys/orca-jump)" == 1 ]] || die 'Existing jump keys differ; refusing implicit key replacement.'
  fi
fi

backup="/var/backups/sem-worker-access/$scope-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -o root -g root -m 0700 "$backup"
printf '%s\n' "$source_home" > "$backup/developer-home-path.txt"
echo "Staging $scope: existing container remains running; original Docker/proxy unchanged."
echo "Verified developer host mapping: $developer_host_uid:$developer_host_gid"
builder="sem-build-$scope"
builder_home="/var/lib/sem-builders/$scope"
# Validate group reuse BEFORE creating a builder account.
share_group="sem-share-$scope"
if getent group "$share_group" >/dev/null; then
  [[ "$(getent group "$share_group" | cut -d: -f3)" == "$developer_host_gid" ]] || die 'Share-group mapping changed.'
elif getent group "$developer_host_gid" >/dev/null; then
  existing_group="$(getent group "$developer_host_gid" | cut -d: -f1)"
  [[ "$allow_shared" == true && "$existing_group" =~ ^sem-share-[a-z][a-z0-9_-]{0,21}$ ]] || die 'Mapped developer group already has an unrelated or non-approved shared host identity.'
  share_group="$existing_group"
fi
if getent passwd "$builder" >/dev/null; then
  [[ "$(getent passwd "$builder" | cut -d: -f6)" == "$builder_home" ]] || die 'Existing builder identity has an unexpected home.'
  [[ "$(getent passwd "$builder" | cut -d: -f7)" == /usr/sbin/nologin ]] || die 'Existing builder is not a locked service identity.'
else
  useradd --system --create-home --home-dir "$builder_home" --shell /usr/sbin/nologin "$builder"
fi
builder_uid="$(id -u "$builder")"
builder_gid="$(id -g "$builder")"
[[ "$builder_uid" != 0 && "$builder_uid" != "$owner_uid" && "$builder_uid" != "$developer_host_uid" ]] || die 'Builder must be a separate unprivileged UID.'
[[ " $(id -nG "$builder") " != *' docker '* && " $(id -nG "$builder") " != *' sudo '* ]] || die 'Builder has privileged host group membership.'
existing_subuid="$(awk -F: -v name="$builder" '$1 == name { print $2 ":" $3 }' /etc/subuid)"
existing_subgid="$(awk -F: -v name="$builder" '$1 == name { print $2 ":" $3 }' /etc/subgid)"
if [[ -z "$existing_subuid" && -z "$existing_subgid" ]]; then
  next_range="$(awk -F: 'BEGIN { end=524288 } $2+$3 > end { end=$2+$3 } END { printf "%.0f", int((end+65535)/65536)*65536 }' /etc/subuid /etc/subgid)"
  usermod --add-subuids "$next_range-$((next_range+65535))" --add-subgids "$next_range-$((next_range+65535))" "$builder"
else
  [[ "$existing_subuid" == "$existing_subgid" && "$existing_subuid" =~ ^[0-9]+:65536$ ]] || die 'Existing subordinate ranges need review.'
fi
if ! getent group "$share_group" >/dev/null; then
  groupadd --gid "$developer_host_gid" "$share_group"
fi
usermod --append --groups "$share_group" "$builder"
chmod 0700 "$builder_home"
install -d -o root -g root -m 0755 /etc/sem-worker-access /usr/local/libexec /etc/ssh/authorized_keys
install -d -o "$builder" -g "$share_group" -m 0710 "/run/sem-docker/$scope"
[[ ! -L "$builder_home/workspace" ]] || die 'Workspace mountpoint must not be a symlink.'
if findmnt -rn --mountpoint "$builder_home/workspace" >/dev/null; then
  # On retries this is already the mapped developer home. NEVER install/chmod
  # over an active bind mount: that would change the original home's mode.
  [[ "$(stat -c '%d:%i' "$builder_home/workspace")" == "$(stat -c '%d:%i' "$source_home")" && "$(stat -c '%u:%g' "$builder_home/workspace")" == "$builder_uid:$builder_gid" ]] || die 'Existing workspace mount differs from the expected scoped ID mapping.'
else
  install -d -o "$builder" -g "$builder" -m 0700 "$builder_home/workspace"
fi
for asset in sem-builder-dockerd sem-ssh-dispatch sem-worker-connect; do
  install -o root -g root -m 0755 "$script_root/worker-access/$asset" "/usr/local/libexec/$asset"
done
# Docker-only reconfiguration must not erase an existing approved SSH port.
if [[ "$mode" == docker && -f "/etc/sem-worker-access/$scope.conf" ]]; then
  [[ "$(stat -c '%u:%g:%a' "/etc/sem-worker-access/$scope.conf")" == 0:0:644 ]] || die 'Untrusted existing scope configuration.'
  ssh_port="$(sed -n 's/^SEM_SSH_PORT=//p' "/etc/sem-worker-access/$scope.conf")"
fi
printf 'SEM_SCOPE=%q\nSEM_OWNER=%q\nSEM_SSH_PORT=%q\nSEM_BUILDER_HOME=%q\n' "$scope" "$owner" "$ssh_port" "$builder_home" > "/etc/sem-worker-access/$scope.conf"
chown root:root "/etc/sem-worker-access/$scope.conf"
chmod 0644 "/etc/sem-worker-access/$scope.conf"

# Change the private mount's view, NEVER the source files' modes/ACLs/owners.
# Validate this kernel/filesystem/tool combination on a tiny synthetic fixture
# first. In particular, a 0600 key must stay 0600 and new bind files must land
# with the developer identity, not the builder's unrelated host UID.
echo '[1/4] Testing private ID-mapped mount (no home scan or permission rewrite)...'
# X-mount.idmap uses filesystem-ID:visible-mount-ID:range. The installed
# util-linux 2.39 manual reverses these labels; upstream documentation fix:
# https://github.com/util-linux/util-linux/commit/f2bfef30ded60f0a9b15d428f13f5fa5d19e4116
mapping_options="bind,X-mount.idmap=u:$developer_host_uid:$builder_uid:1 g:$developer_host_gid:$builder_gid:1"
fixture="$backup/idmap-fixture"
check_mount="$builder_home/.idmap-check"
create_idmap_fixture "$fixture" "$developer_host_uid" "$developer_host_gid"
install -d -o "$builder" -g "$builder" -m 0700 "$check_mount"
check_mounted=false
cleanup_check_mount() {
  if [[ "$check_mounted" == true ]]; then umount -- "$check_mount"; fi
}
trap cleanup_check_mount EXIT
mount -o "$mapping_options" -- "$fixture" "$check_mount" || die 'ID-mapped bind mounts are unsupported here; no ACL/chown fallback will be attempted.'
check_mounted=true
[[ "$(runuser -u "$builder" -- stat -c '%u:%g:%a' "$check_mount/key-mode-test")" == "$builder_uid:$builder_gid:600" ]] || die 'Private mount identity/mode test failed.'
runuser -u "$builder" -- sh -c 'umask 077; printf "scoped builder test\n" > "$1/created-by-builder"' sh "$check_mount"
[[ "$(stat -c '%u:%g:%a' "$fixture/created-by-builder")" == "$developer_host_uid:$developer_host_gid:600" ]] || die 'New bind-file ownership is incompatible with the developer.'
umount -- "$check_mount"
check_mounted=false
echo 'PASS: private mapping, 0600 preservation, and new-file ownership.'

echo '[2/4] Installing scoped workspace mount...'
source_metadata="$(stat -c '%u:%g:%a' "$source_home")"
mount_unit="$(systemd-escape --path --suffix=mount "$builder_home/workspace")"
if [[ -e "/etc/systemd/system/$mount_unit" ]]; then cp -p -- "/etc/systemd/system/$mount_unit" "$backup/workspace.mount"; fi
printf '[Unit]\nDescription=Scoped developer home for %s builder\n[Mount]\nWhat=%s\nWhere=%s/workspace\nType=none\nOptions=%s\n[Install]\nWantedBy=multi-user.target\n' "$scope" "$source_home" "$builder_home" "$mapping_options" > "/etc/systemd/system/$mount_unit"
printf 'd /run/sem-docker 0755 root root -\nd /run/sem-docker/%s 0710 %s %s -\n' "$scope" "$builder" "$share_group" > "/etc/tmpfiles.d/sem-build-$scope.conf"
install -d -o root -g root -m 0755 "/etc/systemd/system/user@$builder_uid.service.d"
printf '[Service]\nDelegate=cpu cpuset io memory pids\nMemoryHigh=3G\nMemoryMax=4G\nMemorySwapMax=1G\nTasksMax=4096\n' > "/etc/systemd/system/user@$builder_uid.service.d/50-sem-builder.conf"
install -d -o root -g "$builder" -m 0750 "$builder_home/.config" "$builder_home/.config/systemd" "$builder_home/.config/systemd/user"
# New service identities must not inherit the desktop's globally enabled
# audio stack. Mask only this builder account, without stopping any active unit.
for desktop_unit in pipewire.service pipewire.socket pipewire-pulse.service pipewire-pulse.socket wireplumber.service filter-chain.service; do
  mask_path="$builder_home/.config/systemd/user/$desktop_unit"
  if [[ -e "$mask_path" || -L "$mask_path" ]]; then
    [[ -L "$mask_path" && "$(readlink -- "$mask_path")" == /dev/null ]] || die 'Unexpected builder desktop unit; refusing replacement.'
  else
    ln -s /dev/null "$mask_path"
  fi
done
printf '[Unit]\nDescription=Rootless Docker for %s only\n[Service]\nEnvironment=SEM_BUILDER_SCOPE=%s\nEnvironment=DOCKERD=/usr/local/libexec/sem-builder-dockerd\nEnvironment=DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS=--copy-up=/home\nEnvironment=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true\nExecStart=/usr/local/libexec/sem-builder-dockerd start --host=unix:///run/user/%s/docker.sock --log-driver=local --log-opt=max-size=10m --log-opt=max-file=2\nRestart=on-failure\nRestartSec=5\nTimeoutStartSec=120\nDelegate=yes\nKillMode=mixed\n[Install]\nWantedBy=default.target\n' "$scope" "$scope" "$builder_uid" > "$builder_home/.config/systemd/user/sem-docker.service"
printf '[Unit]\nDescription=Private environment Docker socket\nAfter=sem-docker.service\nRequires=sem-docker.service\n[Service]\nExecStart=/usr/bin/socat UNIX-LISTEN:/run/sem-docker/%s/docker.sock,fork,mode=0660,group=%s UNIX-CONNECT:/run/user/%s/docker.sock\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=default.target\n' "$scope" "$developer_host_gid" "$builder_uid" > "$builder_home/.config/systemd/user/sem-docker-proxy.service"
chown root:root "$builder_home/.config/systemd/user/sem-docker.service" "$builder_home/.config/systemd/user/sem-docker-proxy.service"
chmod 0644 "$builder_home/.config/systemd/user/sem-docker.service" "$builder_home/.config/systemd/user/sem-docker-proxy.service"
# The unit directory is deliberately root-controlled. Enabling from the
# unprivileged user cannot create its wanted-by symlinks there. Install those
# as root, then use the builder's manager only for reload/start (not enable).
user_units="$builder_home/.config/systemd/user"
install -d -o root -g "$builder" -m 0750 "$user_units/default.target.wants"
for unit in sem-docker.service sem-docker-proxy.service; do
  wanted_link="$user_units/default.target.wants/$unit"
  if [[ -e "$wanted_link" || -L "$wanted_link" ]]; then
    [[ -L "$wanted_link" && "$(readlink -f -- "$wanted_link")" == "$user_units/$unit" ]] || die 'Unexpected existing builder service enablement; refusing replacement.'
  else
    ln -s -- "../$unit" "$wanted_link"
  fi
done
systemctl daemon-reload
systemctl enable --now "$mount_unit"
[[ "$(stat -c '%u:%g:%a' "$builder_home/workspace")" == "$builder_uid:$builder_gid:${source_metadata##*:}" ]] || die 'Persistent workspace mount did not apply the verified ID mapping.'
[[ "$(stat -c '%u:%g:%a' "$source_home")" == "$source_metadata" ]] || die 'Unexpected source metadata change; stopping staging.'
echo '[3/4] Starting ONLY the new scoped Docker services...'
loginctl enable-linger "$builder"
systemctl start "user@$builder_uid.service"
runuser -u "$builder" -- env "XDG_RUNTIME_DIR=/run/user/$builder_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$builder_uid/bus" systemctl --user daemon-reload
runuser -u "$builder" -- env "XDG_RUNTIME_DIR=/run/user/$builder_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$builder_uid/bus" systemctl --user start sem-docker.service sem-docker-proxy.service
docker_ready=false
for ((attempt=0;attempt<30;attempt++)); do
  if [[ "$(runuser -u "$builder" -- curl --silent --max-time 2 --unix-socket "/run/user/$builder_uid/docker.sock" http://localhost/_ping 2>/dev/null || true)" == OK ]]; then
    docker_ready=true
    break
  fi
  sleep 1
done
if [[ "$docker_ready" != true ]]; then
  runuser -u "$builder" -- env "XDG_RUNTIME_DIR=/run/user/$builder_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$builder_uid/bus" systemctl --user status sem-docker.service sem-docker-proxy.service --no-pager --lines=15 || true
  die 'New rootless Docker did not become ready; original Docker and SSH access are unchanged.'
fi
echo 'PASS: new Docker API responds; legacy access has not been switched.'

if [[ "$mode" == docker ]]; then
  printf '\nDOCKER READY: %s\nEndpoint: unix:///run/host/run/sem-docker/%s/docker.sock\nProtected backup: %s\n' "$scope" "$scope" "$backup"
  echo 'Host Docker/SSH and existing environment profiles are unchanged. This is not a full container-isolation audit.'
  exit 0
fi

echo '[4/4] Configuring transport-only SSH; existing connections remain open...'
if ! getent passwd orca-jump >/dev/null; then
  useradd --system --create-home --home-dir /var/lib/orca-jump --shell /bin/sh orca-jump
fi
[[ "$(getent passwd orca-jump | cut -d: -f6)" == /var/lib/orca-jump ]] || die 'Jump home is not the expected isolated path.'
[[ " $(id -nG orca-jump) " != *' sudo '* && " $(id -nG orca-jump) " != *' docker '* ]] || die 'Jump identity has privileged groups.'
chown root:root /var/lib/orca-jump
chmod 0755 /var/lib/orca-jump
install -o root -g root -m 0644 "$public_key_path" /etc/ssh/authorized_keys/orca-jump
printf 'orca-jump ALL=(root) NOPASSWD: /usr/local/libexec/sem-worker-connect %s\n' "$scope" > "/etc/sudoers.d/sem-worker-$scope"
chmod 0440 "/etc/sudoers.d/sem-worker-$scope"
visudo -cf "/etc/sudoers.d/sem-worker-$scope"
ssh_dropin=/etc/ssh/sshd_config.d/40-sem-orca-jump.conf
if [[ -e "$ssh_dropin" ]]; then cp -p -- "$ssh_dropin" "$backup/ssh-jump.conf"; fi
printf 'Match User orca-jump\n    AuthenticationMethods publickey\n    AuthorizedKeysFile /etc/ssh/authorized_keys/orca-jump\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PermitTTY no\n    DisableForwarding yes\n    X11Forwarding no\n    ForceCommand /usr/local/libexec/sem-ssh-dispatch\nMatch all\n' > "$ssh_dropin"
chmod 0644 "$ssh_dropin"
if ! sshd -t; then
  if [[ -f "$backup/ssh-jump.conf" ]]; then cp -p -- "$backup/ssh-jump.conf" "$ssh_dropin"; else mv -- "$ssh_dropin" "$backup/rejected-ssh-jump.conf"; fi
  die 'SSH config rejected; restored the previous jump config and did not reload SSH.'
fi
systemctl reload ssh.service
printf '\nSTAGED: %s\nDocker endpoint inside environment: unix:///run/host/run/sem-docker/%s/docker.sock\nJump identity: orca-jump (command %s only)\nProtected test/config backup: %s\n' "$scope" "$scope" "$scope" "$backup"
echo 'Original Docker proxy/access and existing sessions have NOT been revoked yet.'
echo 'Next: verify build/Compose/bind mounts and inner SSH PTYs, then deliberately activate the new endpoint and revoke legacy access.'
