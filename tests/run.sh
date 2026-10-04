#!/bin/bash
set -euo pipefail
export LC_ALL=C
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SUITE_DIR=$(mktemp -d /tmp/cssh-tests.XXXXXXXXXX)
trap 'rm -rf -- "$SUITE_DIR"' EXIT
umask 077
for name in host old new; do
  ssh-keygen -q -t ed25519 -N '' -f "$SUITE_DIR/$name"
done
CASES=(
  append restricted comment_quotes unknown_types no_newline idempotent replace
  confirm_missing confirm_wrong harden include_harden preserve_hardening
  match_append match_main match_nested match_quoted match_equals match_hash
  match_root mfa wrong_key_path invalid_config service_missing reload_failure
  live_validation partial_write rollback_reload fresh_failure fresh_stage_failure backup_failure signal_failure
  key_symlink config_symlink dir_symlink lock_symlink hardlink writable_home
  concurrent empty_input private_input corrupt_input mismatched_type duplicate_input
  include_spaces include_ambiguous include_cycle relative_include managed_block cli_help cli_missing cli_nonroot cli_home
  real_login
)
passed=0
for scenario in "${CASES[@]}"; do
  if bash "$SCRIPT_DIR/scenario.sh" "$scenario" "$SUITE_DIR" > "$SUITE_DIR/$scenario.log" 2>&1; then
    printf 'PASS %s\n' "$scenario"
    passed=$((passed+1))
  else
    printf 'FAIL %s\n' "$scenario" >&2
    cat -- "$SUITE_DIR/$scenario.log" >&2
    exit 1
  fi
done
printf '\n%d tests passed.\n' "$passed"
