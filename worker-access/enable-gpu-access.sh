#!/usr/bin/env bash
# Host-side device ACLs for the actual mapped developer identity. No chmod 666,
# no host file grants, no changes to container capabilities or running sessions.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $EUID == 0 && $# == 2 ]] || die 'Run with sudo: enable-gpu-access.sh <environment> <Podman-owner>'
scope=$1
owner=$2
[[ $scope =~ ^[a-z][a-z0-9_-]{0,21}$ && $owner =~ ^[a-z_][a-z0-9_-]*$ ]] || die 'Invalid environment or owner'
for tool in podman runuser setfacl getfacl udevadm python3; do
    command -v "$tool" >/dev/null || die "Missing $tool"
done
owner_uid=$(id -u "$owner")
[[ $owner_uid -gt 0 ]] || die 'Podman owner must be a non-root user'
owner_env=(env "XDG_RUNTIME_DIR=/run/user/$owner_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$owner_uid/bus")
engine() { runuser -u "$owner" -- "${owner_env[@]}" podman "$@"; }
[[ $(engine inspect --format '{{.State.Running}}' "$scope") == true ]] || die 'Environment must be running to verify its developer identity'
source_home=$(engine inspect --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}' "$scope")
[[ -d $source_home && ! -L $source_home && $(realpath "$source_home") == "$source_home" ]] || die 'Missing or ambiguous isolated developer home'
guest_uid=$(engine exec "$scope" id -u developer)
pid=$(engine inspect --format '{{.State.Pid}}' "$scope")
[[ $guest_uid =~ ^[0-9]+$ && $guest_uid -ge 1000 && $pid =~ ^[0-9]+$ && $pid -gt 0 ]] || die 'Invalid running developer mapping'
mapped_uid=$(awk -v uid="$guest_uid" '$1 <= uid && uid < $1+$3 {print $2+uid-$1}' "/proc/$pid/uid_map")
[[ $mapped_uid =~ ^[0-9]+$ && $mapped_uid -ge 100000 && $mapped_uid != "$owner_uid" ]] || die 'Refusing non-rootless or ambiguous developer identity'
[[ $(stat -c %u "$source_home") == "$mapped_uid" ]] || die 'Developer mapping disagrees with isolated-home ownership'

mapfile -t nodes < <(find /dev/dri -maxdepth 1 -type c \( -name 'renderD[0-9]*' -o -name 'card[0-9]*' \) -print | sort)
[[ ${#nodes[@]} -gt 0 ]] || die 'No GPU character devices found'
for node in "${nodes[@]}"; do
    [[ $node =~ ^/dev/dri/(renderD|card)[0-9]+$ && ! -L $node && -c $node ]] || die 'Unexpected GPU device path'
done
backup="/var/backups/sem-gpu-access/$scope-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup"
getfacl -p -- "${nodes[@]}" > "$backup/original-acls"
chmod 600 "$backup/original-acls"
rule="/etc/udev/rules.d/99-sem-gpu-$scope.rules"
[[ ! -e $rule ]] || cp -p -- "$rule" "$backup/original-udev-rule"
printf '%s\n' "$mapped_uid" > "$backup/mapped-developer-uid"
printf '# SEM %s: mapped developer UID %s; GPU devices ONLY.\n' "$scope" "$mapped_uid" > "$backup/new-rule"
printf 'ACTION=="add|change", SUBSYSTEM=="drm", KERNEL=="renderD[0-9]*", RUN+="/usr/bin/setfacl -m u:%s:rw -- /dev/dri/%%k"\n' "$mapped_uid" >> "$backup/new-rule"
printf 'ACTION=="add|change", SUBSYSTEM=="drm", KERNEL=="card[0-9]*", RUN+="/usr/bin/setfacl -m u:%s:rw -- /dev/dri/%%k"\n' "$mapped_uid" >> "$backup/new-rule"
install -o root -g root -m 0644 "$backup/new-rule" "$rule"
for node in "${nodes[@]}"; do
    setfacl -m "u:$mapped_uid:rw" -- "$node"
done
# Apply current nodes directly; do NOT trigger unrelated DRM/desktop udev rules.
udevadm control --reload-rules
engine exec --user developer "$scope" python3 -c '
import glob,os,sys
nodes=glob.glob("/dev/dri/renderD*")
if not nodes:
    sys.exit("No GPU render nodes inside environment")
for path in nodes:
    fd=os.open(path, os.O_RDWR|os.O_CLOEXEC)
    os.close(fd)
    print("PASS: developer can open GPU render device", path)
'
printf 'GPU permissions enabled for %s (host mapped UID %s), including future device recreation.\nProtected rollback ACLs/rule: %s\n' "$scope" "$mapped_uid" "$backup"
