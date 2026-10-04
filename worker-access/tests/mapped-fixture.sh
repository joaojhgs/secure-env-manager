#!/usr/bin/env bash
# Numeric ownership regression; no sudo, daemon or real workspace changes.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source <(sed -n '/^create_idmap_fixture()/,/^}/p' "$repo/harden-worker-access.sh")
probe=$(mktemp -d /tmp/sem-mapped-fixture.XXXXXX)
cleanup() {
  [[ ! -f "$probe/fixture/key-mode-test" ]] || unlink -- "$probe/fixture/key-mode-test"
  [[ ! -d "$probe/fixture" ]] || rmdir -- "$probe/fixture"
  rmdir -- "$probe"
}
trap cleanup EXIT
declare -a ownership_calls=()
install() {
  # Model an installer which accepts account names, not subordinate numeric IDs.
  [[ $# == 8 && "$1" == -d && "$2" == -o && "$3" == root && "$4" == -g && "$5" == root && "$6" == -m && "$7" == 0700 ]]
  mkdir -m 0700 -- "$8"
}
chown() {
  [[ $# == 3 && "$1" == -- && "$2" == +101000:+101001 ]]
  ownership_calls+=("$3")
}
create_idmap_fixture "$probe/fixture" 101000 101001
[[ "${#ownership_calls[@]}" == 2 ]]
[[ "${ownership_calls[0]}" == "$probe/fixture" ]]
[[ "${ownership_calls[1]}" == "$probe/fixture/key-mode-test" ]]
[[ $(stat -c %a "$probe/fixture") == 700 ]]
[[ $(stat -c %a "$probe/fixture/key-mode-test") == 600 ]]
[[ $(<"$probe/fixture/key-mode-test") == 'synthetic permission test' ]]
echo 'PASS: unnamed subordinate IDs use explicit numeric chown, not install account lookup; private 0700/0600 modes retained.'
