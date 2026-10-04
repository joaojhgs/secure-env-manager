#!/usr/bin/env bash
# No sudo, live profile writes, service changes or container lifecycle commands.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
manager="$repo/manage-safe-environement.sh"
for script in "$manager" "$repo/harden-worker-access.sh" "$repo/worker-access/sem-builder-dockerd" "$repo/worker-access/sem-worker-connect" "$repo/worker-access/sem-ssh-dispatch"; do
  bash -n "$script"
done
load_function() { source <(sed -n "/^function $1()/,/^}/p" "$manager"); }
load_function sem_docker_socket_inside
for scope in personal university work test-worker a123456789012345678901; do
  [[ $(sem_docker_socket_inside "$scope") == "/run/host/run/sem-docker/$scope/docker.sock" ]]
done
for scope in '' ../personal 'personal;id' 'UPPERCASE' 'a1234567890123456789012' $'personal\nwork'; do
  if sem_docker_socket_inside "$scope" >/dev/null; then echo 'FAIL: invalid scope accepted'; exit 1; fi
  if SSH_ORIGINAL_COMMAND="$scope" bash "$repo/worker-access/sem-ssh-dispatch" >/dev/null 2>&1; then echo 'FAIL: invalid dispatcher scope accepted'; exit 1; fi
done
if grep -q 'UNIX-CONNECT:/var/run/docker.sock\|aa-complain /etc/apparmor.d' "$manager"; then
  echo 'FAIL: rootful passthrough or global AppArmor weakening remains'; exit 1
fi
probe_dir=$(mktemp -d /tmp/sem-policy-tests.XXXXXX)
cleanup() { for file in "$probe_dir"/*.log; do [[ ! -f "$file" ]] || unlink -- "$file"; done; rmdir -- "$probe_dir"; }
trap cleanup EXIT
export SEM_TEST_REPO="$repo"
for probe_case in success shared builder-failure ping-failure non-rootless; do
  export SEM_TEST_CASE="$probe_case" SEM_TEST_LOG="$probe_dir/$probe_case.log"
  probe_status=0
  bash -euo pipefail -c '
    manager="$SEM_TEST_REPO/manage-safe-environement.sh"
    for name in sem_docker_socket_inside setup_docker_proxy sem_setup_rootless_docker; do
      source <(sed -n "/^function $name()/,/^}/p" "$manager")
    done
    die() { echo "$*" >&2; exit 1; }
    require_commands() { :; }
    sudo() {
      printf "sudo %s\n" "$*" >> "$SEM_TEST_LOG"
      [[ "$SEM_TEST_CASE" != builder-failure ]] || return 17
    }
    podman() {
      printf "podman %s\n" "$*" >> "$SEM_TEST_LOG"
      case " $* " in
        *" curl "*)
          [[ "$SEM_TEST_CASE" != ping-failure ]] || return 7
          printf "OK\n" ;;
        *" docker info "*)
          if [[ "$SEM_TEST_CASE" == non-rootless ]]; then
            printf "[\"name=seccomp\"]\n"
          else
            printf "[\"name=rootless\",\"name=seccomp\"]\n"
          fi ;;
        *) return 64 ;;
      esac
    }
    distrobox() {
      printf "distrobox %s\n" "$*" >> "$SEM_TEST_LOG"
      # tee is mocked and drains stdin without writing a real file.
      case " $* " in *" tee "*) while IFS= read -r line; do :; done ;; esac
    }
    SCRIPT_DIR="$SEM_TEST_REPO"; BOX_NAME=test-worker; ACTION=setup-docker
    SEM_ALLOW_SHARED_DEVELOPER=0
    [[ "$SEM_TEST_CASE" != shared ]] || SEM_ALLOW_SHARED_DEVELOPER=1
    sem_setup_rootless_docker
  ' >/dev/null 2>&1 || probe_status=$?
  case "$probe_case" in
    success|shared)
      [[ "$probe_status" == 0 ]]
      grep -q 'distrobox.*tee /etc/profile.d/docker-host.sh' "$SEM_TEST_LOG"
      if [[ "$probe_case" == shared ]]; then grep -q -- '--allow-shared-developer' "$SEM_TEST_LOG"; fi ;;
    *)
      [[ "$probe_status" != 0 ]]
      if grep -q '^distrobox' "$SEM_TEST_LOG"; then echo "FAIL: $probe_case changed profiles"; exit 1; fi ;;
  esac
  printf 'PASS: %s\n' "$probe_case"
done
for shared_policy in false true; do
  shared_status=0
  SEM_TEST_SHARED="$shared_policy" bash -euo pipefail -c '
    allow_shared="$SEM_TEST_SHARED"; scope=personal
    developer_host_uid=101000; developer_host_gid=101001
    die() { exit 18; }
    as_owner() {
      case "$*" in
        "podman ps --all --format {{.Names}}") printf "personal\nuniversity\nwork\n" ;;
        "podman inspect "*) printf "/tmp\n" ;;
        *) exit 19 ;;
      esac
    }
    stat() { printf "101000:101001\n"; }
    source <(sed -n "/^while IFS= read -r other_scope;/,/^done < <(as_owner podman ps/p" "$SEM_TEST_REPO/harden-worker-access.sh")
  ' >/dev/null 2>&1 || shared_status=$?
  if [[ "$shared_policy" == false ]]; then [[ "$shared_status" == 18 ]]; else [[ "$shared_status" == 0 ]]; fi
  printf 'PASS: shared-identity-policy=%s\n' "$shared_policy"
done
for group_case in scoped-denied scoped-allowed unrelated wrong-map; do
  group_status=0
  SEM_TEST_GROUP="$group_case" bash -euo pipefail -c '
    scope=university; developer_host_gid=101001; allow_shared=true
    [[ "$SEM_TEST_GROUP" != scoped-denied ]] || allow_shared=false
    die() { exit 18; }
    getent() {
      [[ "$1" == group ]] || exit 19
      if [[ "$2" == sem-share-university ]]; then
        [[ "$SEM_TEST_GROUP" == wrong-map ]] || return 2
        printf "sem-share-university:x:101002:\n"
      elif [[ "$2" == 101001 ]]; then
        if [[ "$SEM_TEST_GROUP" == unrelated ]]; then
          printf "docker:x:101001:\n"
        else
          printf "sem-share-personal:x:101001:\n"
        fi
      else
        exit 19
      fi
    }
    source <(sed -n "/^share_group=/,/^fi$/p" "$SEM_TEST_REPO/harden-worker-access.sh")
    [[ "$share_group" == sem-share-personal ]]
  ' >/dev/null 2>&1 || group_status=$?
  if [[ "$group_case" == scoped-allowed ]]; then [[ "$group_status" == 0 ]]; else [[ "$group_status" == 18 ]]; fi
  printf 'PASS: share-group=%s\n' "$group_case"
done
bash "$manager" help >/dev/null
if bash "$manager" help '../bad' >/dev/null 2>&1; then echo 'FAIL: traversal accepted by manager'; exit 1; fi
echo 'PASS: syntax, scope validation, private endpoints, failure-before-activation and no rootful fallback.'
