#!/usr/bin/env bash
# Run as developer through inner SSH after the private builders are verified.
# Selects a user-owned Docker context; does not stop services or alter credentials.
set -euo pipefail
[[ $(id -u) == 1001 && $# == 1 && $1 =~ ^[a-z][a-z0-9_-]{0,21}$ ]] || exit 64
scope=$1
config=/home/developer/.docker
endpoint="unix:///run/host/run/sem-docker/$scope/docker.sock"
context="sem-$scope-rootless"
info=$(docker --config "$config" --host "$endpoint" info --format '{{json .}}')
printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "name=rootless" in d["SecurityOptions"]; assert d["DockerRootDir"] == "/var/lib/sem-builders/"+sys.argv[1]+"/.local/share/docker"' "$scope"
current=$(env -u DOCKER_HOST -u DOCKER_CONTEXT docker --config "$config" context show)
[[ $current == default || $current == "$context" ]] || { echo 'An unrelated existing Docker context is selected; refusing to overwrite it.' >&2; exit 65; }
if docker --config "$config" context inspect "$context" >/dev/null 2>&1; then
  [[ $(docker --config "$config" context inspect "$context" --format '{{.Endpoints.docker.Host}}') == "$endpoint" ]] || exit 66
else
  docker --config "$config" context create "$context" --docker "host=$endpoint"
fi
if [[ $current != "$context" ]]; then
  if [[ -f $config/config.json ]]; then
    backup=$(mktemp "$config/config.before-sem-context.XXXXXX")
    cp -- "$config/config.json" "$backup"
    chmod 0600 "$backup"
    echo "Docker client configuration backup: $backup"
  fi
  docker --config "$config" context use "$context"
fi
docker info --format 'Selected Docker: {{.DockerRootDir}} {{json .SecurityOptions}}'
echo "PASS: $scope Docker CLI selects its private builder without requiring a shell export."
