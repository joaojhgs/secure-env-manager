#!/usr/bin/env bash
# Synthetic permission checks only: no Docker proxy/config or credential edits.
set -euo pipefail
[[ $(id -u) != 0 ]] || { echo 'Run as the rootless Podman owner, not root.' >&2; exit 64; }
for tool in podman socat setfacl getfacl timeout nc mktemp awk; do
  command -v "$tool" >/dev/null
done
for scope in personal university work; do
  podman container exists "$scope"
  [[ $(podman inspect --format '{{.State.Running}}' "$scope") == true ]]
done
map_id() {
  awk -v id="$1" '$1 <= id && id < $1+$3 { print $2+id-$1; found=1; exit } END { if (!found) exit 1 }'
}
# Work's supplementary group must be unique, not its shared primary group.
work_group=985
has_group() { awk -v wanted="$1" '{ for (i=1;i<=NF;i++) if ($i==wanted) found=1 } END { exit !found }'; }
podman exec --user developer work id -G | has_group "$work_group"
for scope in personal university; do
  if podman exec --user developer "$scope" id -G | has_group "$work_group"; then
    echo "$scope also has the work-only group; refusing this fixture." >&2
    exit 65
  fi
done
parent_gid=$(podman exec --user developer work cat /proc/self/gid_map | map_id "$work_group")
host_gid=$(podman unshare cat /proc/self/gid_map | map_id "$parent_gid")
probe_dir=$(mktemp -d /tmp/sem-worker-boundary.XXXXXX)
server_pid=''
home_fixture=''
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ -n "$home_fixture" ]]; then podman exec --user developer work unlink -- "$home_fixture"; fi
  if [[ -S "$probe_dir/socket" ]]; then unlink -- "$probe_dir/socket"; fi
  rmdir -- "$probe_dir"
}
trap cleanup EXIT
chmod 0711 "$probe_dir"
socat "UNIX-LISTEN:$probe_dir/socket,fork,mode=0600" 'EXEC:/usr/bin/echo sem-boundary-ok' &
server_pid=$!
for ((attempt=0;attempt<30;attempt++)); do
  [[ -S "$probe_dir/socket" ]] && break
  sleep 0.1
done
[[ -S "$probe_dir/socket" ]]
setfacl -m "u::rw-,g::---,g:$host_gid:rw-,m::rw-,o::---" "$probe_dir/socket"
printf 'Synthetic socket work-group mapping: %s -> %s -> %s\n' "$work_group" "$parent_gid" "$host_gid"
getfacl -n "$probe_dir/socket"
for scope in personal university work; do
  podman exec --user developer "$scope" stat -c 'Socket view: %a %u:%g' "/run/host$probe_dir/socket"
  podman exec --user developer "$scope" getfacl -n "/run/host$probe_dir/socket"
  if podman exec --user developer "$scope" timeout 5 nc -N -w 2 -U "/run/host$probe_dir/socket" </dev/null | awk '$0 == "sem-boundary-ok" { found=1 } END { exit !found }'; then
    printf '%s synthetic work-only socket: ALLOWED\n' "$scope"
  else
    printf '%s synthetic work-only socket: DENIED\n' "$scope"
  fi
done
home_fixture=$(podman exec --user developer work mktemp /home/developer/.sem-boundary.XXXXXX)
[[ "$home_fixture" == /home/developer/.sem-boundary.* ]]
podman exec --user developer work stat -c 'Synthetic work-home file: %a %u:%g' "$home_fixture"
for scope in personal university; do
  if podman exec --user developer "$scope" sh -c 'exec 3<"$1"' sh "/run/host/opt/isolated_work/home/${home_fixture#/home/developer/}" 2>/dev/null; then
    printf '%s opening synthetic work-home 0600 file: ALLOWED (isolation failure)\n' "$scope"
  else
    printf '%s opening synthetic work-home 0600 file: DENIED\n' "$scope"
  fi
done
echo 'Probe complete; synthetic socket/file removed on exit. Real Docker access unchanged.'
