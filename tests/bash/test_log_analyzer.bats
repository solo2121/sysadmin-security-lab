#!/usr/bin/env bats
#
# Unit tests for tools/sysadmin/monitoring/log-analyzer.sh
#
# Scope:
#   These tests source the real script (guarded against auto-execution
#   by its own `[[ "${BASH_SOURCE[0]}" == "${0}" ]]` check, line 199) and
#   exercise the pure, non-interactive functions: find_first_log() and
#   summarize_errors(). They deliberately do NOT call analyze_log_file,
#   main_menu, search_all_logs, realtime_monitoring_menu, or
#   analyze_custom_log — those call `read -r -p` and would block waiting
#   on stdin, or (realtime_monitoring_menu) tail -f forever. Out of scope
#   for a non-interactive CI unit test.

SCRIPT_PATH="${BATS_TEST_DIRNAME}/../../tools/sysadmin/monitoring/log-analyzer.sh"

setup() {
    # shellcheck disable=SC1090
    source "$SCRIPT_PATH"

    # log-analyzer.sh sets `set -Eeuo pipefail` for its own execution.
    # Restore normal test semantics right after sourcing so it can't
    # silently change how these assertions behave.
    set +Eeuo pipefail

    TEST_TMPDIR="$(mktemp -d)"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "log-analyzer.sh sources without executing main_menu" {
    declare -f main_menu >/dev/null
    declare -f find_first_log >/dev/null
}

@test "find_first_log returns the first readable path" {
    echo "log contents" > "$TEST_TMPDIR/second.log"

    run find_first_log "$TEST_TMPDIR/does-not-exist.log" "$TEST_TMPDIR/second.log"

    [ "$status" -eq 0 ]
    [ "$output" = "$TEST_TMPDIR/second.log" ]
}

@test "find_first_log skips unreadable paths and picks the next readable one" {
    echo "first"  > "$TEST_TMPDIR/first.log"
    echo "second" > "$TEST_TMPDIR/second.log"
    chmod 000 "$TEST_TMPDIR/first.log"

    run find_first_log "$TEST_TMPDIR/first.log" "$TEST_TMPDIR/second.log"

    [ "$status" -eq 0 ]
    [ "$output" = "$TEST_TMPDIR/second.log" ]

    chmod 644 "$TEST_TMPDIR/first.log"
}

@test "find_first_log returns failure when no path is readable" {
    run find_first_log "$TEST_TMPDIR/nope-a.log" "$TEST_TMPDIR/nope-b.log"

    [ "$status" -eq 1 ]
}

@test "summarize_errors counts and ranks repeated error lines" {
    cat > "$TEST_TMPDIR/sample.log" <<'LOG'
Jan 01 00:00:01 host app: connection failed
Jan 01 00:00:02 host app: connection failed
Jan 01 00:00:03 host app: authentication denied
LOG

    run summarize_errors "$TEST_TMPDIR/sample.log"

    [ "$status" -eq 0 ]
    [[ "$output" == *"2 "*"failed"* ]]
    [[ "$output" == *"denied"* ]]
}

@test "summarize_errors handles a file with no matching lines" {
    echo "Jan 01 00:00:01 host app: all systems nominal" > "$TEST_TMPDIR/clean.log"

    run summarize_errors "$TEST_TMPDIR/clean.log"

    [ "$status" -eq 0 ]
}
