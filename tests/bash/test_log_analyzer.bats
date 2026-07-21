#!/usr/bin/env bash
#
# Modern Linux Log Analyzer
#
# Functions:
#   find_first_log
#   summarize_errors
#   analyze_log_file
#
# Designed for:
#   - CI testing
#   - Security labs
#   - Linux troubleshooting
#

set -o pipefail


log_info() {
    echo "[*] $*"
}


log_success() {
    echo "[+] $*"
}


log_warning() {
    echo "[!] $*"
}


log_error() {
    echo "[-] $*"
}


die() {
    log_error "$1"
    return 1
}


find_first_log() {

    local paths=("$@")

    for logfile in "${paths[@]}"; do

        if [[ -r "$logfile" ]]; then
            echo "$logfile"
            return 0
        fi

    done

    return 1
}


summarize_errors() {

    local logfile="$1"

    if [[ ! -f "$logfile" ]]; then
        return 0
    fi


    grep -i "error\|failed\|critical" "$logfile" \
        | sed -E 's/^.*(error|failed|critical)/\1/' \
        | sort \
        | uniq -c \
        | sort -nr

}


analyze_log_file() {

    local logfile="$1"


    if [[ ! -f "$logfile" ]]; then
        return 1
    fi


    log_info "Analyzing $logfile"

    summarize_errors "$logfile"

}


main() {

    local logfile

    logfile=$(find_first_log \
        "/var/log/syslog" \
        "/var/log/messages" \
        "/var/log/auth.log"
    ) || die "No readable log file found"


    analyze_log_file "$logfile"

}


#
# Prevent execution when sourced by BATS
#
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi