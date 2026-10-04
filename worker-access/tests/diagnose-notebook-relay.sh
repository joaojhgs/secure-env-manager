#!/usr/bin/env bash
# Read-only root diagnostic: no service/account/config writes or lifecycle actions.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ "$EUID" == 0 && $# == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || {
  echo 'Run on notebook host: sudo bash ./diagnose-notebook-relay.sh' >&2
  exit 64
}
owner="$SUDO_USER"
[[ "$owner" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 65
owner_uid=$(id -u "$owner")
relay_pid=$(systemctl show sem-docker-compat-check.service -p MainPID --value)
[[ "$relay_pid" =~ ^[1-9][0-9]+$ && "$relay_pid" -gt 1 && -d "/proc/$relay_pid" ]] || {
  echo 'Checkpoint relay is not running; no service is started by this probe.' >&2
  exit 66
}
relay_uid=$(id -u sem-docker-relay)
relay_gid=$(id -g sem-docker-relay)
[[ "$relay_uid" != 0 && "$relay_uid" != "$owner_uid" && "$relay_gid" != 0 ]] || exit 67
[[ $(stat -c '%u:%g:%a' /usr/local/libexec/sem-docker-compat.py) == 0:0:644 ]] || exit 68
peer_lookup_code='
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("compat", "/usr/local/libexec/sem-docker-compat.py")
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)
config = compat.load_config()
scope = sys.argv[1]
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        with open(f"/proc/{entry}/status", encoding="ascii") as source:
            uids = next(line.split()[1:] for line in source if line.startswith("Uid:"))
        if uids != [str(config["service_uid"])] * 4:
            continue
        with open(f"/proc/{entry}/cgroup", encoding="ascii") as source:
            groups = source.read(16385)
        if len(groups) > 16384:
            continue
        selected = compat.choose_backend(config, config["service_uid"], groups)
        if selected.split("/")[-2] == scope:
            print(entry)
            break
    except (OSError, PermissionError, StopIteration):
        continue
'
probe_code='
import importlib.util, json, os, socket, sys
spec = importlib.util.spec_from_file_location("compat", "/usr/local/libexec/sem-docker-compat.py")
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)
config = compat.load_config()
assert os.getuid() == config["service_uid"] and os.getgid() == config["service_gid"]
scope, pid, context = sys.argv[1:]
result = {"scope": scope, "context": context, "uid": os.getuid(), "gid": os.getgid()}
try:
    with open(f"/proc/{int(pid)}/cgroup", encoding="ascii") as source:
        groups = source.read(16385)
    assert len(groups) <= 16384
    selected = compat.choose_backend(config, os.getuid(), groups)
    result["peer_metadata"] = "ok"
    result["selected_scope"] = selected.split("/")[-2]
except (OSError, PermissionError) as error:
    result["peer_metadata"] = type(error).__name__
    result["metadata_errno"] = getattr(error, "errno", None)
try:
    backend = next(item for item in config["backends"] if item["scope"] == scope)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(backend["socket"])
        client.sendall(b"GET /_ping HTTP/1.0\r\nHost: localhost\r\n\r\n")
        reply = client.recv(512)
    result["backend_api"] = "ok" if b" 200 " in reply.split(b"\r\n", 1)[0] else "unexpected_status"
except OSError as error:
    result["backend_api"] = type(error).__name__
    result["backend_errno"] = error.errno
print(json.dumps(result), flush=True)
'
echo 'READ-ONLY: compare mapped non-root identity outside/inside running relay mount sandbox.'
systemctl show sem-docker-compat-check.service -p MainPID -p ProtectProc -p ProcSubset -p RestrictAddressFamilies
for scope in personal university work; do
  # Rootless podman top can report HPID="?" for cross-namespace peers. Root is
  # used ONLY to locate approved peers by UID and cgroup metadata, then dropped.
  peer_pid=$(env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -c "$peer_lookup_code" "$scope")
  [[ "$peer_pid" =~ ^[1-9][0-9]+$ && -d "/proc/$peer_pid" ]] || {
    echo "No stable developer peer PID found for $scope; no processes created or stopped."
    continue
  }
  [[ $(awk '$1 == "Uid:" { print $2 }' "/proc/$peer_pid/status") == "$relay_uid" ]] || exit 69
  [[ $(systemctl show sem-docker-compat-check.service -p MainPID --value) == "$relay_pid" ]] || exit 70
  printf '%s peer user namespace: ' "$scope"
  readlink "/proc/$peer_pid/ns/user"
  printf 'relay user namespace: '
  readlink "/proc/$relay_pid/ns/user"
  env PYTHONDONTWRITEBYTECODE=1 setpriv --reuid="$relay_uid" --regid="$relay_gid" --clear-groups --bounding-set=-all --no-new-privs /usr/bin/python3 -c "$probe_code" "$scope" "$peer_pid" host-mount
  env PYTHONDONTWRITEBYTECODE=1 nsenter --mount="/proc/$relay_pid/ns/mnt" -- setpriv --reuid="$relay_uid" --regid="$relay_gid" --clear-groups --bounding-set=-all --no-new-privs /usr/bin/python3 -c "$probe_code" "$scope" "$peer_pid" relay-mount
done
echo 'Finished read-only diagnostic. No services, endpoints, users or files changed.'
