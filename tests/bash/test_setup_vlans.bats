#!/usr/bin/env bats
#
# Script: BATS tests for setup-vlans.sh
# Author: Miguel A. Carlo
# Description:
#   Unit tests for the VLAN setup script. These tests source the target
#   script and exercise its helper functions (logging, error handling)
#   and configuration variables without requiring network or root privileges.
# Usage:
#   bats tests/bash/test_setup_vlans.bats

SCRIPT="${BATS_TEST_DIRNAME}/../../labs/security/ad-pentest-vlan/scripts/setup-vlans.sh"

# Sourced at file scope (not inside a function) so that array variables
# like VLAN_CONFIG, which the script declares with `declare -A`, remain
# visible across all @test blocks instead of being scoped local to a
# setup() function.
source "$SCRIPT"

@test "script defines the expected logging functions" {
    declare -F log_info
    declare -F log_success
    declare -F log_warning
    declare -F log_error
    declare -F die
}

@test "log_info prints an info-tagged message" {
    run log_info "hello world"
    [ "$status" -eq 0 ]
    [[ "$output" == *"hello world"* ]]
    [[ "$output" == *"[*]"* ]]
}

@test "log_success prints a success-tagged message" {
    run log_success "all good"
    [ "$status" -eq 0 ]
    [[ "$output" == *"all good"* ]]
    [[ "$output" == *"[+]"* ]]
}

@test "log_warning prints a warning-tagged message" {
    run log_warning "careful"
    [ "$status" -eq 0 ]
    [[ "$output" == *"careful"* ]]
    [[ "$output" == *"[!]"* ]]
}

@test "log_error prints an error-tagged message" {
    run log_error "broken"
    [ "$status" -eq 0 ]
    [[ "$output" == *"broken"* ]]
    [[ "$output" == *"[-]"* ]]
}

@test "die exits non-zero and prints the error message" {
    run die "fatal failure"
    [ "$status" -eq 1 ]
    [[ "$output" == *"fatal failure"* ]]
}

@test "VLAN_CONFIG defines all five expected VLANs" {
    source "$SCRIPT"
    [ "${#VLAN_CONFIG[@]}" -eq 5 ]
    [[ -n "${VLAN_CONFIG[10]:-}" ]]
    [[ -n "${VLAN_CONFIG[20]:-}" ]]
    [[ -n "${VLAN_CONFIG[30]:-}" ]]
    [[ -n "${VLAN_CONFIG[40]:-}" ]]
    [[ -n "${VLAN_CONFIG[99]:-}" ]]
}

@test "VLAN_CONFIG entries follow the bridge:gateway:description format" {
    source "$SCRIPT"
    for vlan_id in "${!VLAN_CONFIG[@]}"; do
        entry="${VLAN_CONFIG[$vlan_id]}"
        IFS=':' read -r bridge gateway description <<< "$entry"
        [[ "$bridge" == br-* ]]
        [[ "$gateway" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
        [[ -n "$description" ]]
    done
}
