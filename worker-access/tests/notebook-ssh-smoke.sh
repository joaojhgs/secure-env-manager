#!/usr/bin/env bash
# Uses separately pinned host keys obtained through the existing trusted host SSH.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: notebook-ssh-smoke.sh SSH_KEY_DIRECTORY NOTEBOOK_HOSTNAME' >&2; exit 64; }
key_dir=$1
host=$2
[[ $key_dir == /* && $host =~ ^[a-zA-Z0-9.-]+$ ]] || exit 64
pinned="$key_dir/sem_notebook_known_hosts"
outer=(ssh -oBatchMode=yes -oConnectTimeout=10 -oIdentityAgent=none -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes
  -oHostKeyAlias=sem-notebook-jump -oUserKnownHostsFile="$pinned" -i "$key_dir/sem_orca_jump_ed25519")
for scope in personal university work; do
  case $scope in personal) port=24625 ;; university) port=23389 ;; work) port=24114 ;; esac
  proxy="ssh -T -oBatchMode=yes -oConnectTimeout=10 -oIdentityAgent=none -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes -oHostKeyAlias=sem-notebook-jump -oUserKnownHostsFile='$pinned' -i '$key_dir/sem_orca_jump_ed25519' orca-jump@$host $scope"
  options=(-oBatchMode=yes -oConnectTimeout=10 -oIdentityAgent=none -oIdentitiesOnly=yes -oStrictHostKeyChecking=yes
    -oHostKeyAlias="sem-notebook-$scope" -oUserKnownHostsFile="$pinned" -i "$key_dir/orca_skyron_notebook_${scope}_ed25519" -oProxyCommand="$proxy")
  result=$(ssh "${options[@]}" -p "$port" -tt developer@127.0.0.1 'test -t 0 && test -t 1 && tty && test "$(id -u)" = 1001 && printf "nested-pty-ok\n"')
  [[ $result == *nested-pty-ok* ]]
  echo "PASS: $scope nested SSH authenticates developer and allocates a PTY."
  fixture=$(ssh "${options[@]}" -p "$port" -T developer@127.0.0.1 'mktemp -d /home/developer/.sem-ssh-smoke.XXXXXX')
  [[ $fixture == /home/developer/.sem-ssh-smoke.* && $fixture != *[[:space:]]* ]]
  download=$(mktemp /tmp/sem-ssh-download.XXXXXX)
  cleanup() {
    ssh "${options[@]}" -p "$port" -T developer@127.0.0.1 "if test -f '$fixture/input.txt'; then unlink '$fixture/input.txt'; fi; rmdir '$fixture'" || true
    unlink "$download"
  }
  trap cleanup EXIT
  scp "${options[@]}" -P "$port" "$(dirname -- "$0")/input.txt" "developer@127.0.0.1:$fixture/input.txt"
  scp "${options[@]}" -P "$port" "developer@127.0.0.1:$fixture/input.txt" "$download"
  cmp "$(dirname -- "$0")/input.txt" "$download"
  cleanup
  trap - EXIT
  echo "PASS: $scope SFTP upload/download matches the synthetic input."
  status=0
  ssh "${options[@]}" -p "$port" -T root@127.0.0.1 true >/dev/null 2>&1 || status=$?
  [[ $status == 255 ]] || { echo "FAIL: $scope developer identity permitted root authentication or an unexpected status." >&2; exit 1; }
  echo "PASS: $scope developer key cannot authenticate as root."
done
for command in id 'personal;id'; do
  status=0
  "${outer[@]}" -T "orca-jump@$host" "$command" >/dev/null 2>&1 || status=$?
  case "$command:$status" in id:69|'personal;id':64) ;; *) echo 'FAIL: outer command restriction.' >&2; exit 1 ;; esac
done
status=0
response=$("${outer[@]}" -T -W 127.0.0.1:24625 "orca-jump@$host" 2>&1) || status=$?
[[ $status == 255 && $response == *'administratively prohibited'* ]]
status=0
response=$("${outer[@]}" -tt "orca-jump@$host" 'personal;id' 2>&1) || status=$?
# OpenSSH may abort before the forced command when the requested PTY is denied.
[[ ( $status == 64 || $status == 255 ) && $response == *'PTY allocation request failed'* ]]
echo 'PASS: transport-only outer account rejects host commands, forwarding and outer PTYs.'
