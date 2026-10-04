#!/usr/bin/env bash
# Run as developer inside an existing environment. Only creates owned test assets.
set -euo pipefail
[[ $(id -u) != 0 && $# == 1 && $1 =~ ^[a-z][a-z0-9_-]{0,21}$ ]] || exit 64
scope=$1
case ${DOCKER_HOST:-} in
  unix:///run/host/run/sem-docker/"$scope"/docker.sock|unix:///run/host/run/sem-docker-compat/check.sock|unix:///run/host/tmp/distrobox-docker.sock) ;;
  *) echo 'An explicit, validated compatibility endpoint is required.' >&2; exit 65 ;;
esac
test_root=$(mktemp -d /home/developer/.sem-builder-smoke.XXXXXX)
export SEM_TEST_ROOT=$test_root SEM_TEST_IMAGE="sem-worker-access-test:${scope}-${test_root##*.}"
export DOCKER_CONFIG="$test_root/config"
mkdir "$DOCKER_CONFIG"
project="sem-smoke-${scope}-${test_root##*.}"
project=${project,,}
compose=/usr/libexec/docker/cli-plugins/docker-compose
[[ -x $compose ]] || { echo 'Compose plugin unavailable.' >&2; rmdir "$DOCKER_CONFIG" "$test_root"; exit 66; }
dc() { docker --config "$DOCKER_CONFIG" "$@"; }
cleanup() {
  local result=$?
  if [[ -f $test_root/compose.yaml ]]; then
    "$compose" -p "$project" -f "$test_root/compose.yaml" down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ $(dc image inspect --format '{{index .Config.Labels "sem.worker-access-test"}}' "$SEM_TEST_IMAGE" 2>/dev/null) == true ]]; then
    dc image rm "$SEM_TEST_IMAGE" >/dev/null || true
  fi
  for file in Dockerfile compose.yaml input.txt private-input compose-result; do
    [[ ! -f $test_root/$file ]] || unlink "$test_root/$file"
  done
  rmdir "$DOCKER_CONFIG" "$test_root" || true
  exit "$result"
}
trap cleanup EXIT
# Assert route BEFORE any Docker mutation. No rootful fallback or implicit context.
info=$(dc info --format '{{json .}}')
printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "name=rootless" in d["SecurityOptions"]; assert d["DockerRootDir"] == "/var/lib/sem-builders/"+sys.argv[1]+"/.local/share/docker"' "$scope"
echo "PASS: $scope smoke test routes only to its rootless builder."
tar -x -C "$test_root" --no-same-owner --no-same-permissions
install -m 0600 "$test_root/input.txt" "$test_root/private-input"
timeout 180 docker --config "$DOCKER_CONFIG" build --tag "$SEM_TEST_IMAGE" "$test_root"
[[ $(dc run --rm --network none "$SEM_TEST_IMAGE") == 'build command passed' ]]
timeout 60 "$compose" -p "$project" -f "$test_root/compose.yaml" run --rm --no-deps probe
[[ $(<"$test_root/compose-result") == 'compose bind write passed' ]]
for file in private-input compose-result; do
  [[ $(stat -c '%u:%g:%a' "$test_root/$file") == "$(id -u):$(id -g):600" ]]
done
echo "PASS: $scope real image build/run, Compose, private bind read/write, and developer-owned 0600 files."
