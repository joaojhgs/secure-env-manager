#!/usr/bin/env bash
# Checkpoint-only reload regression; no service mutations, sudo or Docker calls.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SEM_CHECKPOINT_TEST_SOURCE="$repo/stage-notebook-workers.sh"
for trial in inactive unchanged idle busy changed unexpected invalid; do
  status=0
  SEM_CHECKPOINT_TEST_CASE="$trial" bash -euo pipefail -c '
    source <(sed -n "/^refresh_checkpoint_sandbox()/,/^}/p" "$SEM_CHECKPOINT_TEST_SOURCE")
    die() { exit 18; }
    checkpoint_previous_pid=207371; checkpoint_previous_policy=invisible; restarted=0
    case "$SEM_CHECKPOINT_TEST_CASE" in
      inactive) checkpoint_previous_pid=0 ;;
      unchanged) checkpoint_previous_policy=default ;;
      unexpected) checkpoint_previous_policy=ptraceable ;;
      invalid) checkpoint_previous_pid=bad ;;
    esac
    systemctl() {
      case "$*" in
        "show sem-docker-compat-check.service -p MainPID --value")
          [[ "$SEM_CHECKPOINT_TEST_CASE" != changed ]] || { printf "207372\n"; return; }
          printf "207371\n" ;;
        "show sem-docker-compat-check.service -p TasksCurrent --value")
          [[ "$SEM_CHECKPOINT_TEST_CASE" != busy ]] || { printf "2\n"; return; }
          printf "1\n" ;;
        "restart sem-docker-compat-check.service") restarted=$((restarted+1)) ;;
        *) exit 99 ;;
      esac
    }
    refresh_checkpoint_sandbox
    if [[ "$SEM_CHECKPOINT_TEST_CASE" == idle ]]; then [[ "$restarted" == 1 ]]; else [[ "$restarted" == 0 ]]; fi
  ' || status=$?
  case "$trial" in
    inactive|unchanged|idle) [[ "$status" == 0 ]] ;;
    *) [[ "$status" == 18 ]] ;;
  esac
  echo "PASS: checkpoint-refresh=$trial"
done
for directive in 'ProtectProc=default\nProcSubset=pid' 'CapabilityBoundingSet=\nAmbientCapabilities=' 'ProtectSystem=strict' 'ProtectHome=yes' 'RestrictAddressFamilies=AF_UNIX' 'RestrictNamespaces=yes' 'NoNewPrivileges=yes'; do
  grep -Fq -- "$directive" "$SEM_CHECKPOINT_TEST_SOURCE"
done
echo 'PASS: relay keeps zero capabilities, non-root peer policy and other sandbox restrictions.'
