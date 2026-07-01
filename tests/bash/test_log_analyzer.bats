#!/usr/bin/env bats
#
# Unit tests for sysadmin/monitoring/log-analyzer.sh
#
# Exercises the pure log-parsing logic (find_first_log, summarize_errors)
# against fixture log files. No root privileges or real system logs
# required.
#
# Run with:
#   bats tests/bash/test_log_analyzer.bats

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../sysadmin/monitoring/log-analyzer.sh"
    FIXTURE_DIR="$(mktemp -d)"
    source "$SCRIPT"
}

teardown() {
    rm -rf "$FIXTURE_DIR"
}

@test "script defines the expected log-analysis functions" {
    declare -F find_first_log
    declare -F summarize_errors
    declare -F analyze_log_file
}

@test "find_first_log returns the first readable path" {
    touch "$FIXTURE_DIR/exists.log"
    run find_first_log "$FIXTURE_DIR/missing.log" "$FIXTURE_DIR/exists.log"
    [ "$status" -eq 0 ]
    [ "$output" = "$FIXTURE_DIR/exists.log" ]
}

@test "find_first_log skips unreadable paths and finds the next one" {
    touch "$FIXTURE_DIR/second.log"
    run find_first_log "/definitely/does/not/exist.log" "$FIXTURE_DIR/second.log"
    [ "$status" -eq 0 ]
    [ "$output" = "$FIXTURE_DIR/second.log" ]
}

@test "find_first_log fails when no candidate path is readable" {
    run find_first_log "/no/such/path-a.log" "/no/such/path-b.log"
    [ "$status" -eq 1 ]
}

@test "summarize_errors counts and ranks repeated error lines" {
    cat > "$FIXTURE_DIR/app.log" <<'EOF'
Jan 01 00:00:01 host app: connection failed to db
Jan 01 00:00:02 host app: connection failed to db
Jan 01 00:00:03 host app: connection failed to db
Jan 01 00:00:04 host app: disk critical low space
Jan 01 00:00:05 host app: request completed ok
EOF
    run summarize_errors "$FIXTURE_DIR/app.log"
    [ "$status" -eq 0 ]
    [[ "$output" == *"3 app: connection failed to db"* ]]
    [[ "$output" == *"disk critical low space"* ]]
    [[ "$output" != *"request completed ok"* ]]
}

@test "summarize_errors handles a missing file gracefully" {
    run summarize_errors "$FIXTURE_DIR/does-not-exist.log"
    [ "$status" -eq 0 ]
}
