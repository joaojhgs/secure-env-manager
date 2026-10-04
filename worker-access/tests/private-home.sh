#!/usr/bin/env bash
# Real unprivileged RootlessKit mount test; never starts Docker or edits host homes.
set -euo pipefail
[[ $(id -u) != 0 ]] || { echo 'Run as an unprivileged host user.' >&2; exit 64; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
probe=$(mktemp -d /tmp/sem-private-home.XXXXXX)
cleanup() {
  [[ ! -f "$probe/source/sentinel" ]] || unlink -- "$probe/source/sentinel"
  [[ ! -d "$probe/source" ]] || rmdir -- "$probe/source"
  rmdir -- "$probe"
}
trap cleanup EXIT
mkdir -m 0700 -- "$probe/source"
printf 'synthetic private workspace\n' > "$probe/source/sentinel"
chmod 0600 "$probe/source/sentinel"
host_home_before=$(stat -c '%d:%i:%u:%g:%a:%F' /home/developer 2>/dev/null || printf absent)
export SEM_LAUNCHER_SOURCE="$repo/worker-access/sem-builder-dockerd" SEM_PRIVATE_HOME_PROBE="$probe"
rootlesskit --net=none --copy-up=/home bash -euo pipefail -c '
  source <(sed -n "/^prepare_private_developer_mountpoint()/,/^}/p" "$SEM_LAUNCHER_SOURCE")
  prepare_private_developer_mountpoint
  [[ -d /home/developer && ! -L /home/developer ]]
  mount --bind "$SEM_PRIVATE_HOME_PROBE/source" /home/developer
  [[ $(</home/developer/sentinel) == "synthetic private workspace" ]]
  [[ $(stat -c %a /home/developer/sentinel) == 600 ]]
  umount -- /home/developer
  rmdir -- /home/developer
  echo "PASS: real private copy-up mount accepts scoped bind without following host home."

  ln -s "$SEM_PRIVATE_HOME_PROBE/missing" /home/developer
  prepare_private_developer_mountpoint
  [[ -d /home/developer && ! -L /home/developer ]]
  printf "synthetic marker\n" > /home/developer/marker
  status=0
  (prepare_private_developer_mountpoint) >/dev/null 2>&1 || status=$?
  [[ "$status" == 68 && -f /home/developer/marker ]]
  unlink -- /home/developer/marker
  rmdir -- /home/developer
  echo "PASS: dangling private links work; unexpected real directories are preserved and refused."

  ln -s "$SEM_PRIVATE_HOME_PROBE/source" /home/developer
  findmnt() {
    [[ "$SEM_GUARD_CASE" != missing-mount ]] || return 1
    if [[ "$*" == *"-o FSTYPE" ]]; then
      [[ "$SEM_GUARD_CASE" != wrong-fstype ]] || { printf "ext4\n"; return; }
      printf "tmpfs\n"
    else
      [[ "$SEM_GUARD_CASE" != shared-mount ]] || { printf "shared\n"; return; }
      printf "private\n"
    fi
  }
  for SEM_GUARD_CASE in missing-mount wrong-fstype shared-mount; do
    status=0
    (prepare_private_developer_mountpoint) >/dev/null 2>&1 || status=$?
    [[ "$status" == 67 && -L /home/developer ]]
    echo "PASS: $SEM_GUARD_CASE refuses before unlink."
  done
  unlink -- /home/developer
'
[[ $(stat -c '%d:%i:%u:%g:%a:%F' /home/developer 2>/dev/null || printf absent) == "$host_home_before" ]]
[[ $(<"$probe/source/sentinel") == 'synthetic private workspace' ]]
echo 'PASS: original host home metadata and source sentinel unchanged.'
