#!/bin/bash
set -Eeuo pipefail
export LC_ALL=C
umask 077
shopt -s nullglob
shopt -u dotglob nocaseglob failglob extglob globstar
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../cssh.sh"
SCENARIO=$1 SUITE=$2 ACTION=${3:-}
FIXTURE="$SUITE/$SCENARIO"
ROOT_UID=$UID ACCOUNT_NAME=$(id -un) ACCOUNT_HOME="$FIXTURE/home"
SSHD_CONFIG="$FIXTURE/sshd_config" SSHD_BIN=$(command -v sshd)
INPUT_FILE="$SUITE/new.pub" MODE=append DISABLE_PASSWORD=0
CONFIRMATIONS=() STAGING_FILES=() RELOAD_COMMAND=()
WORK='' TRANSACTION_ACTIVE=0

assert() { "$@" || { printf 'Assertion failed: %s\n' "$*" >&2; exit 1; }; }
assert_same() { cmp -s "$1" "$2" || { printf 'Files differ: %s %s\n' "$1" "$2" >&2; exit 1; }; }
assert_unchanged() {
  assert_same "$FIXTURE/before-keys" "$ACCOUNT_HOME/.ssh/authorized_keys"
  assert_same "$FIXTURE/before-config" "$SSHD_CONFIG"
}
policy() { "$SSHD_BIN" -T -f "$SSHD_CONFIG" | awk -v wanted="$1" '$1 == wanted {$1=""; sub(/^ /, ""); print}'; }

prepare_service() { [[ $SCENARIO != service_missing ]] || fail 'test service unavailable'; }
reload_service() {
  local count=0
  [[ ! -f $FIXTURE/reloads ]] || count=$(cat "$FIXTURE/reloads")
  count=$((count+1)); printf '%s\n' "$count" > "$FIXTURE/reloads"
  if [[ $SCENARIO == reload_failure || $SCENARIO == fresh_failure ]] && (( count == 1 )); then return 1; fi
  [[ $SCENARIO != rollback_reload ]] || return 1
  if [[ $SCENARIO == signal_failure ]] && (( count == 1 )); then kill -TERM "$$"; fi
  if [[ $SCENARIO == real_login ]]; then
    kill -HUP "$(cat "$FIXTURE/daemon-pid")"
    sleep 0.1
  fi
}
atomic_install() {
  if [[ $SCENARIO == partial_write && $2 == "$SSHD_CONFIG" && ! -f $FIXTURE/write-failed ]]; then
    : > "$FIXTURE/write-failed"; return 1
  fi
  if [[ $SCENARIO == fresh_stage_failure && $2 == "$ACCOUNT_HOME/.ssh/authorized_keys" ]]; then
    install_staged_file "$FIXTURE/missing-file" "$2" "$3"; return $?
  fi
  install_staged_file "$@"
}
mktemp() {
  if [[ $SCENARIO == backup_failure && $1 == "$SSHD_CONFIG.bak."* ]]; then return 1; fi
  command mktemp "$@"
}
validate_config() {
  timeout 30 "$SSHD_BIN" -t -f "$1"
  if [[ $SCENARIO == live_validation && $1 == "$SSHD_CONFIG" ]]; then return 1; fi
}

if [[ $ACTION == action ]]; then
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  WORK=$(mktemp -d "$FIXTURE/work.XXXXXXXXXX")
  case $SCENARIO in
    replace) MODE=replace ;;
    confirm_missing) MODE=replace ;;
    confirm_wrong) MODE=replace; CONFIRMATIONS=(SHA256:wrong) ;;
    harden|include_harden|preserve_hardening|match_main|match_nested|match_quoted|match_equals|match_hash|mfa)
      DISABLE_PASSWORD=1 ;;
    empty_input|private_input|corrupt_input|mismatched_type|duplicate_input) INPUT_FILE="$FIXTURE/input.pub" ;;
    include_cycle) ;; # inspect_config must reject before OpenSSH is called.
  esac
  if [[ $SCENARIO == preserve_hardening && ${4:-} == append ]]; then DISABLE_PASSWORD=0; fi
  load_keys
  case $SCENARIO in
    replace|harden|include_harden|preserve_hardening|match_main|match_nested|match_quoted|match_equals|match_hash|mfa)
      CONFIRMATIONS=("${FINGERPRINTS[0]}") ;;
  esac
  apply_changes
  exit 0
fi

mkdir -p "$ACCOUNT_HOME/.ssh"
chmod 700 "$ACCOUNT_HOME" "$ACCOUNT_HOME/.ssh"
cp "$SUITE/old.pub" "$ACCOUNT_HOME/.ssh/authorized_keys"
chmod 600 "$ACCOUNT_HOME/.ssh/authorized_keys"
cat > "$SSHD_CONFIG" <<CONFIG
HostKey $SUITE/host
PidFile $FIXTURE/server.pid
AuthorizedKeysFile $ACCOUNT_HOME/.ssh/authorized_keys
PermitRootLogin yes
UsePAM no
PubkeyAuthentication no
PasswordAuthentication yes
KbdInteractiveAuthentication yes
CONFIG
NEW_KEY=$(cat "$SUITE/new.pub")
run_action() { bash "$SCRIPT_DIR/scenario.sh" "$SCENARIO" "$SUITE" action; }
expect_failure() {
  if run_action > "$FIXTURE/failure.log" 2>&1; then
    printf 'Expected failure: %s\n' "$SCENARIO" >&2; exit 1
  fi
}
case $SCENARIO in
  restricted) printf 'from="127.0.0.1",command="printf hello world",restrict %s\n' "$NEW_KEY" > "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
  comment_quotes) printf 'from="127.0.0.1",restrict %s unmatched '\'' quote\n' "$NEW_KEY" > "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
  unknown_types)
    printf '%s\n' 'sk-ssh-ed25519@openssh.com AAAAtest device' 'ssh-ed25519-cert-v01@openssh.com AAAAtest certificate' 'unknown future record' >> "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
  no_newline) printf '%s' "$(cat "$SUITE/old.pub")" > "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
  replace) printf 'from="127.0.0.1",no-port-forwarding %s\n# retained comment\n' "$NEW_KEY" >> "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
  include_harden|include_spaces)
    mkdir "$FIXTURE/include space"
    printf '%s\n' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication yes' > "$FIXTURE/include space/01.conf"
    printf 'Include "%s/include space/*.conf" # trailing comment\n' "$FIXTURE" >> "$SSHD_CONFIG" ;;
  match_append|match_main) printf '%s\n' 'Match User nobody' 'PasswordAuthentication yes' >> "$SSHD_CONFIG" ;;
  match_nested|match_equals|match_quoted|match_hash)
    included="$FIXTURE/nested.conf"
    [[ $SCENARIO != match_hash ]] || included="$FIXTURE/config#match"
    if [[ $SCENARIO == match_quoted ]]; then
      printf '%s\n' '"Match" User nobody' 'PasswordAuthentication yes' > "$included"
      printf '"Include"="%s"\n' "$included" >> "$SSHD_CONFIG"
    elif [[ $SCENARIO == match_equals ]]; then
      printf '%s\n' 'Match=User nobody' 'PasswordAuthentication yes' > "$included"
      printf 'Include=%s\n' "$included" >> "$SSHD_CONFIG"
    else
      printf '%s\n' 'Match User nobody' 'PasswordAuthentication yes' > "$included"
      printf 'Include %s\n' "$included" >> "$SSHD_CONFIG"
    fi ;;
  match_root) printf 'Match User %s\nPubkeyAuthentication no\n' "$ACCOUNT_NAME" >> "$SSHD_CONFIG" ;;
  mfa) printf '%s\n' 'AuthenticationMethods publickey,password' >> "$SSHD_CONFIG" ;;
  wrong_key_path) sed -i "s|$ACCOUNT_HOME/.ssh/authorized_keys|$FIXTURE/other|" "$SSHD_CONFIG" ;;
  invalid_config) printf '%s\n' 'UnsupportedTestDirective yes' >> "$SSHD_CONFIG" ;;
  reload_failure) chmod 750 "$ACCOUNT_HOME/.ssh" ;;
  fresh_failure|fresh_stage_failure) rm "$ACCOUNT_HOME/.ssh/authorized_keys"; rmdir "$ACCOUNT_HOME/.ssh" ;;
  key_symlink|config_symlink|lock_symlink)
    printf 'unchanged\n' > "$FIXTURE/victim"
    case $SCENARIO in
      key_symlink) target="$ACCOUNT_HOME/.ssh/authorized_keys" ;;
      config_symlink) target="$SSHD_CONFIG" ;;
      lock_symlink) target="$FIXTURE/.cssh.lock" ;;
    esac
    rm -f "$target"; ln -s "$FIXTURE/victim" "$target" ;;
  dir_symlink)
    rm "$ACCOUNT_HOME/.ssh/authorized_keys"; rmdir "$ACCOUNT_HOME/.ssh"
    mkdir "$FIXTURE/other"; ln -s "$FIXTURE/other" "$ACCOUNT_HOME/.ssh" ;;
  hardlink) ln "$ACCOUNT_HOME/.ssh/authorized_keys" "$FIXTURE/linked" ;;
  writable_home) chmod 777 "$ACCOUNT_HOME" ;;
  concurrent)
    : > "$FIXTURE/.cssh.lock"; chmod 600 "$FIXTURE/.cssh.lock"
    exec {TEST_LOCK}<> "$FIXTURE/.cssh.lock"; flock -n "$TEST_LOCK" ;;
  empty_input) printf '# comment only\n' > "$FIXTURE/input.pub" ;;
  private_input) cp "$SUITE/new" "$FIXTURE/input.pub" ;;
  corrupt_input) printf '%s\n' 'ssh-ed25519 AAAAnotvalid broken' > "$FIXTURE/input.pub" ;;
  mismatched_type) printf '%s\n' "${NEW_KEY/ssh-ed25519/ssh-rsa}" > "$FIXTURE/input.pub" ;;
  duplicate_input) printf '%s\n%s other comment\n' "$NEW_KEY" "$NEW_KEY" > "$FIXTURE/input.pub" ;;
  include_ambiguous) printf 'Include /etc/ssh/[[:alpha:]].conf\n' >> "$SSHD_CONFIG" ;;
  include_cycle) printf 'Include %s\n' "$SSHD_CONFIG" >> "$SSHD_CONFIG" ;;
  managed_block) printf '%s\n' '# BEGIN cssh managed configuration' 'UnexpectedOption yes' >> "$SSHD_CONFIG" ;;
esac
[[ ! -f $ACCOUNT_HOME/.ssh/authorized_keys ]] || cp -L "$ACCOUNT_HOME/.ssh/authorized_keys" "$FIXTURE/before-keys"
cp -L "$SSHD_CONFIG" "$FIXTURE/before-config"

case $SCENARIO in
  confirm_missing|confirm_wrong|match_main|match_nested|match_quoted|match_equals|match_hash|match_root|mfa|wrong_key_path|invalid_config|service_missing|hardlink|writable_home|concurrent|include_ambiguous|include_cycle|managed_block|backup_failure)
    expect_failure; assert_unchanged; assert test ! -f "$FIXTURE/reloads" ;;
  empty_input|private_input|corrupt_input|mismatched_type)
    expect_failure; assert_unchanged ;;
  key_symlink|config_symlink|lock_symlink)
    expect_failure; assert test "$(cat "$FIXTURE/victim")" = unchanged; assert test -L "$target" ;;
  dir_symlink) expect_failure; assert test -L "$ACCOUNT_HOME/.ssh"; assert test ! -e "$FIXTURE/other/authorized_keys" ;;
  reload_failure|live_validation|partial_write|rollback_reload|signal_failure)
    expect_failure; assert_unchanged
    if [[ $SCENARIO == reload_failure ]]; then assert test "$(stat -c %a "$ACCOUNT_HOME/.ssh")" = 750; fi
    if [[ $SCENARIO == rollback_reload ]]; then assert grep -q '回滚未完全成功' "$FIXTURE/failure.log"; fi ;;
  fresh_failure|fresh_stage_failure)
    expect_failure; assert test ! -e "$ACCOUNT_HOME/.ssh"; assert_same "$FIXTURE/before-config" "$SSHD_CONFIG" ;;
  cli_help) assert bash "$SCRIPT_DIR/../cssh.sh" --help ;;
  cli_missing)
    if bash "$SCRIPT_DIR/../cssh.sh" > "$FIXTURE/cli.log" 2>&1; then exit 1; fi
    assert grep -q -- '--key-file' "$FIXTURE/cli.log" ;;
  cli_nonroot)
    if (( UID == 0 )) && command -v setpriv >/dev/null; then
      if setpriv --reuid=65534 --regid=65534 --clear-groups bash "$SCRIPT_DIR/../cssh.sh" --key-file /does-not-exist > "$FIXTURE/cli.log" 2>&1; then exit 1; fi
      assert grep -q '必须以 root 运行' "$FIXTURE/cli.log"
    else
      printf 'SKIP nonroot CLI check (requires root and setpriv)\n'
    fi ;;
  cli_home)
    if (( UID != 0 )); then printf 'SKIP root CLI check\n'; exit 0; fi
    bash -c '
      source "$1/cssh.sh"
      apply_changes() {
        local expected
        expected=$(getent passwd 0 | cut -d: -f6)
        [[ $ACCOUNT_HOME == "$expected" && $ACCOUNT_HOME != "$HOME" ]]
      }
      export HOME=/deliberately-wrong-home
      main --key-file "$2/new.pub"
    ' test "$SCRIPT_DIR/.." "$SUITE" ;;
  relative_include)
    WORK=$(mktemp -d "$FIXTURE/work.XXXXXXXXXX")
    trap 'rm -rf -- "$WORK"' EXIT
    CONFIG_DIR="$FIXTURE"; HAS_MATCH=0; declare -A SCAN_STACK=()
    printf 'Include relative.conf\n' >> "$SSHD_CONFIG"
    printf 'Match User nobody\nPasswordAuthentication yes\n' > "$FIXTURE/relative.conf"
    inspect_config "$SSHD_CONFIG"; assert test "$HAS_MATCH" = 1 ;;
  real_login)
    if (( UID != 0 )); then printf 'SKIP real login (requires root)\n'; exit 0; fi
    port=$((20000+RANDOM%30000))
    # The fixture uses a temporary home; system SSH files are never changed.
    sed -i -e 's/UsePAM no/UsePAM yes/' -e 's/PubkeyAuthentication no/PubkeyAuthentication yes/' "$SSHD_CONFIG"
    printf 'ListenAddress 127.0.0.1\nPort %s\nStrictModes no\nLogLevel ERROR\n' "$port" >> "$SSHD_CONFIG"
    printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$SUITE/host.pub")" > "$FIXTURE/known_hosts"
    "$SSHD_BIN" -D -e -f "$SSHD_CONFIG" > "$FIXTURE/daemon.log" 2>&1 & daemon=$!
    printf '%s\n' "$daemon" > "$FIXTURE/daemon-pid"
    trap 'kill "$daemon" 2>/dev/null || :; wait "$daemon" 2>/dev/null || :' EXIT
    started=0
    for ((attempt=0; attempt<100; attempt++)); do
      kill -0 "$daemon" 2>/dev/null || { cat "$FIXTURE/daemon.log"; exit 1; }
      if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then started=1; break; fi
      sleep 0.02
    done
    assert test "$started" = 1
    login() {
      ssh -F /dev/null -p "$port" -i "$SUITE/$1" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$FIXTURE/known_hosts" -o ConnectTimeout=3 \
        root@127.0.0.1 'printf CSSH_LOGIN_OK'
    }
    assert login old
    if login new 2>/dev/null; then exit 1; fi
    run_action
    assert login old; assert login new
    printf '%s\n' "$(cat "$SUITE/old.pub")" "command=\"printf CSSH_RESTRICTED\",restrict $NEW_KEY" > "$ACCOUNT_HOME/.ssh/authorized_keys"
    run_action
    result=$(login new); [[ $result == *CSSH_RESTRICTED ]] || exit 1
    # Invoke the same action with explicit destructive options in an isolated shell.
    bash -c '
      source "$1/cssh.sh"
      set -Eeuo pipefail; umask 077; shopt -s nullglob
      ROOT_UID=0 ACCOUNT_NAME=root ACCOUNT_HOME="$2/home" SSHD_CONFIG="$2/sshd_config"
      SSHD_BIN=$(command -v sshd) INPUT_FILE="$3/new.pub" MODE=replace DISABLE_PASSWORD=1
      STAGING_FILES=() TRANSACTION_ACTIVE=0 TEST_FIXTURE=$2
      trap cleanup EXIT; trap "exit 143" TERM
      WORK=$(mktemp -d "$2/work.XXXXXXXXXX")
      prepare_service() { :; }
      reload_service() { kill -HUP "$(cat "$TEST_FIXTURE/daemon-pid")"; sleep 0.1; }
      load_keys; CONFIRMATIONS=("${FINGERPRINTS[0]}"); apply_changes
    ' test "$SCRIPT_DIR/.." "$FIXTURE" "$SUITE"
    result=$(login new); [[ $result == *CSSH_RESTRICTED ]] || exit 1
    if login old 2>/dev/null; then exit 1; fi
    assert test "$(policy passwordauthentication)" = no
    assert test "$(policy kbdinteractiveauthentication)" = no ;;
  *)
    run_action
    case $SCENARIO in
      restricted|comment_quotes) assert_same "$FIXTURE/before-keys" "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
      replace)
        assert grep -q '^# ssh-ed25519' "$ACCOUNT_HOME/.ssh/authorized_keys"
        assert grep -q '^from="127.0.0.1",no-port-forwarding' "$ACCOUNT_HOME/.ssh/authorized_keys" ;;
      idempotent)
        cp "$ACCOUNT_HOME/.ssh/authorized_keys" "$FIXTURE/once-keys"; cp "$SSHD_CONFIG" "$FIXTURE/once-config"
        run_action
        assert_same "$FIXTURE/once-keys" "$ACCOUNT_HOME/.ssh/authorized_keys"; assert_same "$FIXTURE/once-config" "$SSHD_CONFIG"
        backups=("$FIXTURE"/sshd_config.bak.*); assert test "${#backups[@]}" = 2 ;;
      harden|include_harden)
        assert test "$(policy passwordauthentication)" = no; assert test "$(policy kbdinteractiveauthentication)" = no ;;
      preserve_hardening)
        bash "$SCRIPT_DIR/scenario.sh" "$SCENARIO" "$SUITE" action append
        assert test "$(policy passwordauthentication)" = no ;;
      no_newline|duplicate_input) assert test "$(grep -c '^ssh-ed25519 ' "$ACCOUNT_HOME/.ssh/authorized_keys")" = 2 ;;
      match_append) assert grep -q '^Match User nobody$' "$SSHD_CONFIG" ;;
      append|unknown_types)
        assert grep -Fq "$(cat "$SUITE/old.pub")" "$ACCOUNT_HOME/.ssh/authorized_keys"
        assert grep -Fq "$NEW_KEY" "$ACCOUNT_HOME/.ssh/authorized_keys"
        assert test "$(policy passwordauthentication)" = yes ;;
    esac
    assert test "$(stat -c %a "$ACCOUNT_HOME/.ssh/authorized_keys")" = 600
    assert test "$(stat -c %a "$ACCOUNT_HOME/.ssh")" = 700
    ;;
esac
