#!/usr/bin/env bash
# Account-policy regression with mocked NSS/useradd; no host account mutations.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SEM_RELAY_TEST_SOURCE="$repo/stage-notebook-workers.sh"
for trial in create existing uid-collision wrong-uid wrong-gid extra-group wrong-home wrong-shell unlocked root-id host-id unrelated-group; do
  status=0
  SEM_RELAY_TEST_CASE="$trial" bash -euo pipefail -c '
    source <(sed -n "/^ensure_relay_identity()/,/^}/p" "$SEM_RELAY_TEST_SOURCE")
    die() { exit 18; }
    service_uid=101000; service_gid=101001; owner_uid=1000; created=false
    [[ "$SEM_RELAY_TEST_CASE" != root-id ]] || service_uid=0
    [[ "$SEM_RELAY_TEST_CASE" != host-id ]] || service_uid=1000
    getent() {
      case "$1:$2" in
        group:101001)
          [[ "$SEM_RELAY_TEST_CASE" != unrelated-group ]] || { printf "docker:x:101001:\n"; return; }
          printf "sem-share-personal:x:101001:\n" ;;
        passwd:101000)
          [[ "$SEM_RELAY_TEST_CASE" != uid-collision ]] || { printf "unrelated:x:101000:101001::/nonexistent:/usr/sbin/nologin\n"; return; }
          [[ "$SEM_RELAY_TEST_CASE" != create ]] || return 2
          printf "sem-docker-relay:x:101000:101001::/nonexistent:/usr/sbin/nologin\n" ;;
        passwd:sem-docker-relay)
          [[ "$SEM_RELAY_TEST_CASE" != create || "$created" == true ]] || return 2
          home=/nonexistent; shell=/usr/sbin/nologin
          [[ "$SEM_RELAY_TEST_CASE" != wrong-home ]] || home=/home/skyron
          [[ "$SEM_RELAY_TEST_CASE" != wrong-shell ]] || shell=/bin/bash
          printf "sem-docker-relay:x:101000:101001::%s:%s\n" "$home" "$shell" ;;
        shadow:sem-docker-relay)
          [[ "$SEM_RELAY_TEST_CASE" != unlocked ]] || { printf "sem-docker-relay:unlocked:1:0:99999:7:::\n"; return; }
          printf "sem-docker-relay:!:1:0:99999:7:::\n" ;;
        *) return 2 ;;
      esac
    }
    id() {
      [[ "$2" == sem-docker-relay ]]
      case "$1" in
        -u) [[ "$SEM_RELAY_TEST_CASE" != wrong-uid ]] || { printf "123\n"; return; }; printf "101000\n" ;;
        -g) [[ "$SEM_RELAY_TEST_CASE" != wrong-gid ]] || { printf "123\n"; return; }; printf "101001\n" ;;
        -G) [[ "$SEM_RELAY_TEST_CASE" != extra-group ]] || { printf "101001 27\n"; return; }; printf "101001\n" ;;
        *) return 2 ;;
      esac
    }
    useradd() {
      [[ "$SEM_RELAY_TEST_CASE" == create ]]
      [[ "$*" == "--system --no-create-home --no-user-group --no-log-init --uid 101000 --gid sem-share-personal --home-dir /nonexistent --shell /usr/sbin/nologin --password ! sem-docker-relay" ]]
      created=true
    }
    ensure_relay_identity
    [[ "$relay_user" == sem-docker-relay && "$relay_group" == sem-share-personal ]]
    [[ "$SEM_RELAY_TEST_CASE" != create || "$created" == true ]]
  ' || status=$?
  case "$trial" in
    create|existing) [[ "$status" == 0 ]] ;;
    *) [[ "$status" == 18 ]] ;;
  esac
  echo "PASS: relay-identity=$trial"
done
