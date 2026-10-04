#!/usr/bin/env bash
# Additive root bootstrap only. Activation is a separate, tested exact command.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
die() { echo "ERROR: $*" >&2; exit 1; }
refresh_checkpoint_sandbox() {
  [[ "$checkpoint_previous_pid" =~ ^[0-9]+$ ]] || die 'Invalid checkpoint PID snapshot.'
  [[ "$checkpoint_previous_pid" != 0 ]] || return 0
  [[ "$checkpoint_previous_policy" != default ]] || return 0
  [[ "$checkpoint_previous_policy" == invisible ]] || die 'Unexpected checkpoint proc policy; review it rather than replacing a running sandbox.'
  # Only refresh our previously unusable test relay. Never interrupt user traffic
  # or restart the legacy proxy, builders, primary relay, or any Distrobox.
  [[ "$(systemctl show sem-docker-compat-check.service -p MainPID --value)" == "$checkpoint_previous_pid" && "$(systemctl show sem-docker-compat-check.service -p TasksCurrent --value)" == 1 ]] || die 'Checkpoint changed or has active clients; no service was restarted.'
  echo 'Refreshing ONLY the idle checkpoint relay to apply the corrected proc visibility.'
  systemctl restart sem-docker-compat-check.service
}
ensure_relay_identity() {
  relay_user=sem-docker-relay
  [[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ && "$service_uid" != "$owner_uid" ]] || die 'Relay must use the non-root mapped developer identity, not the host owner.'
  relay_group=$(getent group "$service_gid" | cut -d: -f1)
  [[ "$relay_group" =~ ^sem-share-[a-z][a-z0-9_-]{0,21}$ ]] || die 'Relay requires an approved mapped share group.'
  local existing_user locked_password
  existing_user=$(getent passwd "$service_uid" | cut -d: -f1 || true)
  [[ -z "$existing_user" || "$existing_user" == "$relay_user" ]] || die 'Mapped UID has an unrelated host account; refusing to reuse it.'
  if ! getent passwd "$relay_user" >/dev/null; then
    # systemd's socket/user credential lookup requires an NSS account even for
    # numeric IDs. Name the already-used mapped identity without adding access.
    useradd --system --no-create-home --no-user-group --no-log-init --uid "$service_uid" --gid "$relay_group" --home-dir /nonexistent --shell /usr/sbin/nologin --password '!' "$relay_user"
  fi
  [[ "$(id -u "$relay_user")" == "$service_uid" && "$(id -g "$relay_user")" == "$service_gid" && "$(id -G "$relay_user")" == "$service_gid" ]] || die 'Relay account identity or supplementary groups differ from the approved mapping.'
  [[ "$(getent passwd "$relay_user" | cut -d: -f6)" == /nonexistent && "$(getent passwd "$relay_user" | cut -d: -f7)" == /usr/sbin/nologin ]] || die 'Relay account must have no home and no login shell.'
  locked_password=$(getent shadow "$relay_user" | cut -d: -f2)
  case "$locked_password" in
    '!'*|'*'*) ;;
    *) die 'Relay account password is not locked.' ;;
  esac
  unset locked_password
}
[[ "$EUID" == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root && $# == 1 ]] || {
  echo 'Usage (on notebook host): sudo bash ./stage-notebook-workers.sh JUMP_PUBLIC_KEY' >&2
  exit 64
}
owner="$SUDO_USER"
[[ "$owner" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 65
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
key=$(realpath -e -- "$1")
owner_uid=$(id -u "$owner")
owner_home=$(getent passwd "$owner" | cut -d: -f6)
owner_env=(env "XDG_RUNTIME_DIR=/run/user/$owner_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$owner_uid/bus")
as_owner() { runuser -u "$owner" -- "${owner_env[@]}" "$@"; }
for tool in python3 pgrep docker podman systemctl visudo; do command -v "$tool" >/dev/null; done
for asset in harden-worker-access.sh worker-access/sem-builder-dockerd worker-access/sem-worker-connect worker-access/sem-ssh-dispatch worker-access/sem-docker-compat.py worker-access/sem-notebook-docker-activate; do
  [[ -f "$repo/$asset" ]] || { echo "Missing package asset: $asset" >&2; exit 1; }
done
for scope in personal university work; do
  [[ "$(as_owner podman inspect --format '{{.State.Running}}' "$scope")" == true ]] || { echo "Keep $scope running; nothing is recreated by this bootstrap." >&2; exit 1; }
done
unit="$owner_home/.config/systemd/user/distrobox-docker-proxy.service"
[[ -f "$unit" && ! -L "$unit" ]] || { echo 'Expected original notebook Docker proxy unit.' >&2; exit 1; }
backup="/var/backups/sem-worker-access/notebook-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -o root -g root -m 0700 "$backup"
cp -p -- "$unit" "$backup/proxy.before.service"
docker ps --format '{{.ID}} {{.Names}} {{.Status}}' > "$backup/host-containers.before-stage.txt"
echo "STAGING ONLY. Original Docker endpoint and existing workloads remain running. Backup: $backup"
for entry in personal:24625 university:23389 work:24114; do
  scope=${entry%:*}
  port=${entry#*:}
  bash "$repo/harden-worker-access.sh" stage "$scope" "$key" --ssh-port "$port" --allow-shared-developer
done

first_home=$(as_owner podman inspect personal --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}')
service_uid=$(stat -c %u "$first_home")
service_gid=$(stat -c %g "$first_home")
[[ "$service_uid" != 0 && "$service_uid" != "$owner_uid" && "$service_gid" != 0 ]] || exit 66
backend_arguments=()
for scope in personal university work; do
  home=$(as_owner podman inspect "$scope" --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}')
  [[ "$(stat -c '%u:%g' "$home")" == "$service_uid:$service_gid" ]] || { echo 'Shared-identity compatibility requires matching developer UID/GID.' >&2; exit 1; }
  container_id=$(as_owner podman inspect "$scope" --format '{{.Id}}')
  [[ "$container_id" =~ ^[a-f0-9]{64}$ ]] || exit 67
  backend_arguments+=("$scope" "$container_id")
done
ensure_relay_identity
install -o root -g root -m 0644 "$repo/worker-access/sem-docker-compat.py" /usr/local/libexec/sem-docker-compat.py
install -o root -g root -m 0755 "$repo/worker-access/sem-notebook-docker-activate" /usr/local/libexec/sem-notebook-docker-activate
python3 -c 'import json,sys; uid,gid=map(int,sys.argv[1:3]); rest=sys.argv[3:]; print(json.dumps({"service_uid":uid,"service_gid":gid,"backends":[{"scope":scope,"container_id":ident,"peer_uid":uid,"socket":f"/run/sem-docker/{scope}/docker.sock"} for scope,ident in zip(rest[::2],rest[1::2])]}))' "$service_uid" "$service_gid" "${backend_arguments[@]}" > /etc/sem-worker-access/docker-compat.json
chown root:root /etc/sem-worker-access/docker-compat.json
chmod 0644 /etc/sem-worker-access/docker-compat.json
printf 'SEM_OWNER=%q\nSEM_BACKUP=%q\nSEM_PROXY_SHA256=%q\n' "$owner" "$backup" "$(sha256sum "$unit" | cut -d' ' -f1)" > /etc/sem-worker-access/notebook-migration.conf
chown root:root /etc/sem-worker-access/notebook-migration.conf
chmod 0600 /etc/sem-worker-access/notebook-migration.conf
printf '[Unit]\nDescription=Retired rootful proxy (private compatibility relay is host-managed)\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n[Install]\nWantedBy=default.target\n' > /etc/sem-worker-access/legacy-proxy-disabled.service
checkpoint_previous_pid=0
checkpoint_previous_policy=default
if systemctl is-active --quiet sem-docker-compat-check.service; then
  checkpoint_previous_pid=$(systemctl show sem-docker-compat-check.service -p MainPID --value)
  checkpoint_previous_policy=$(systemctl show sem-docker-compat-check.service -p ProtectProc --value)
fi
for suffix in '' '-check'; do
  stem="sem-docker-compat$suffix"
  listen=/tmp/distrobox-docker.sock
  [[ -z "$suffix" ]] || listen=/run/sem-docker-compat/check.sock
  printf '[Unit]\nDescription=Private Docker compatibility socket%s\n[Socket]\nListenStream=%s\nSocketUser=%s\nSocketGroup=%s\nSocketMode=0660\nDirectoryMode=0755\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n' "$suffix" "$listen" "$relay_user" "$relay_group" > "/etc/systemd/system/$stem.socket"
  # Peer cgroups live across user namespaces. hidepid/invisible denies even
  # same-UID peers there; allow ordinary metadata permissions, NOT ptrace caps.
  printf '[Unit]\nDescription=Unprivileged Docker compatibility relay%s\nRequires=%s.socket\nAfter=%s.socket\n[Service]\nUser=%s\nGroup=%s\nExecStart=/usr/bin/python3 /usr/local/libexec/sem-docker-compat.py\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectProc=default\nProcSubset=pid\nRestrictNamespaces=yes\nRestrictSUIDSGID=yes\nRestrictAddressFamilies=AF_UNIX\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nMemoryMax=64M\nTasksMax=64\nLimitNOFILE=256\nRestart=on-failure\nRestartSec=2\n' "$suffix" "$stem" "$stem" "$relay_user" "$relay_group" > "/etc/systemd/system/$stem.service"
done
printf '%s ALL=(root) NOPASSWD: /usr/local/libexec/sem-notebook-docker-activate activate\n' "$owner" > /etc/sudoers.d/sem-notebook-docker-activate
chmod 0440 /etc/sudoers.d/sem-notebook-docker-activate
visudo -cf /etc/sudoers.d/sem-notebook-docker-activate
systemctl daemon-reload
refresh_checkpoint_sandbox
# The original socket is still owned by the original proxy. Only the private
# checkpoint listener starts now; the exact activation helper swaps it later.
if ! systemctl start sem-docker-compat-check.socket; then
  systemctl status sem-docker-compat-check.socket --no-pager --lines=15 || true
  die 'Checkpoint socket failed; original Docker endpoint has NOT been switched.'
fi
for scope in personal university work; do
  if ! info=$(as_owner podman exec --user developer "$scope" curl --fail --silent --show-error --max-time 10 --unix-socket /run/host/run/sem-docker-compat/check.sock http://localhost/info); then
    systemctl status sem-docker-compat-check.service --no-pager --lines=15 || true
    die "Checkpoint API failed for $scope; original Docker endpoint has NOT been switched."
  fi
  printf '%s' "$info" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert "name=rootless" in x["SecurityOptions"]; assert x["DockerRootDir"] == "/var/lib/sem-builders/"+sys.argv[1]+"/.local/share/docker"' "$scope"
  echo "PASS: $scope checkpoint selects its private rootless builder."
done
echo 'STAGED ALL THREE. Old Docker access/workloads remain unchanged; no activation, recreation, pruning or volume migration performed.'
echo 'Tell the agent staging completed so builds/bind mounts and SSH can be checked before activation.'
