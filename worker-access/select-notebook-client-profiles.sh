#!/usr/bin/env bash
# Existing notebook only: host owner uses its rootless Podman to deploy profiles.
# No host sudo, service restart, recursive home scan or permission rewrite.
set -euo pipefail
[[ $(id -u) != 0 ]] || exit 64
assets=$(cd -- "$(dirname -- "$0")" && pwd -P)
backup=$(mktemp -d /home/skyron/.local/share/sem-notebook-client-backup.XXXXXX)
echo "Client profile backup: $backup"
for scope in personal university work; do
  [[ $(podman inspect --format '{{.State.Running}}' "$scope") == true ]]
  endpoint="/run/host/run/sem-docker/$scope/docker.sock"
  response=$(podman exec --user developer "$scope" curl --fail --silent --show-error --max-time 5 --unix-socket "$endpoint" http://localhost/info)
  printf '%s' "$response" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "name=rootless" in d["SecurityOptions"]; assert d["DockerRootDir"] == "/var/lib/sem-builders/"+sys.argv[1]+"/.local/share/docker"' "$scope"
  if podman exec "$scope" test -f /etc/profile.d/docker-host.sh; then
    podman cp "$scope:/etc/profile.d/docker-host.sh" "$backup/$scope.docker-host.sh"
  fi
  # Back up only the two files being edited, not the home or its credentials.
  for filename in .zshenv .bashrc; do
    podman exec --user developer "$scope" test ! -L "/home/developer/$filename"
    if podman exec --user developer "$scope" test -f "/home/developer/$filename"; then
      podman cp "$scope:/home/developer/$filename" "$backup/$scope$filename"
    fi
  done
  # Inner SSH may pin individual home init files in a different mount namespace.
  # Keep a system zsh entry too, so future SSH shells inherit the SDK endpoint.
  podman exec "$scope" test -f /etc/zsh/zshenv
  podman cp "$scope:/etc/zsh/zshenv" "$backup/$scope.system-zshenv"
  podman cp "$assets/profiles/notebook-$scope.sh" "$scope:/etc/profile.d/docker-host.sh"
  podman exec "$scope" chmod 0644 /etc/profile.d/docker-host.sh
  podman exec "$scope" sh -c '
    set -eu
    line="if [ \"\$EUID\" = 1001 ] && [ -r /etc/profile.d/docker-host.sh ]; then . /etc/profile.d/docker-host.sh; fi"
    grep -qxF "$line" /etc/zsh/zshenv || sed -i "1i$line" /etc/zsh/zshenv'
  # Mechanical, idempotent insertion before any non-interactive early return.
  podman exec --user developer "$scope" bash -c '
    set -euo pipefail
    line="[ ! -r /etc/profile.d/docker-host.sh ] || . /etc/profile.d/docker-host.sh"
    for filename in /home/developer/.zshenv /home/developer/.bashrc; do
      [[ -f $filename ]] || install -m 0600 /dev/null "$filename"
      if ! grep -qxF "$line" "$filename"; then
        sed -i "1i$line" "$filename"
      fi
    done'
  echo "PASS: $scope private Docker profile selected for future bash/zsh shells."
done
echo 'Existing shells, running Docker workloads and Distroboxes were not restarted.'
