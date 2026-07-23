#!/usr/bin/env bash

# ============================================================
# ClamAV Security Manager
# Author: Miguel A. Carlo
# Description: Interactive ClamAV manager for signature updates,
#              quick scans, custom scans, quarantine actions,
#              database details, and scan statistics.
# ============================================================

set -Eeuo pipefail

# ------------------------------------------------------------
# Auto elevate
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    exec sudo CLAM_UI_HOME="${HOME:-}" "$0" "$@"
fi

# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------
LOG_DIR="/var/log/clamav-ui"
QUARANTINE_DIR="/var/quarantine"
SCAN_LOG="$LOG_DIR/scan.log"
USER_HOME="${CLAM_UI_HOME:-}"
if [[ -z "$USER_HOME" && -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
fi
USER_HOME="${USER_HOME:-$HOME}"

mkdir -p "$LOG_DIR"
mkdir -p "$QUARANTINE_DIR"

# ------------------------------------------------------------
# Spinner
# ------------------------------------------------------------
spinner=( "|" "/" "-" "\\" )

# ------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------
cleanup() {
    tput cnorm 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------
# Requirements
# ------------------------------------------------------------
check_requirements() {

    if ! command -v clamscan >/dev/null 2>&1; then
        echo -e "${RED}ClamAV not installed.${NC}"
        exit 1
    fi

    if ! command -v freshclam >/dev/null 2>&1; then
        echo -e "${RED}freshclam not installed.${NC}"
        exit 1
    fi
}

# ------------------------------------------------------------
# UI
# ------------------------------------------------------------
header() {

    clear 2>/dev/null || true

    echo -e "${CYAN}"
    echo " ClamAV Security Manager"
    echo " Professional Linux Edition"
    echo
    echo " [1]  Update Virus Database"
    echo " [2]  Quick Scan"
    echo " [3]  Home Directory Scan"
    echo " [4]  Full System Scan"
    echo " [5]  Custom Path Scan"
    echo " [6]  Quarantine Scan"
    echo " [7]  View Scan Logs"
    echo " [8]  Database Information"
    echo " [9]  Scan Statistics"
    echo " [10] Scheduler"
    echo " [0]  Exit"
    echo
    echo -e "${NC}"
}

# ------------------------------------------------------------
pause() {
    echo
    read -rp "Press Enter to continue..."
}

# ------------------------------------------------------------
success() {
    echo -e "${GREEN}✓ $1${NC}"
}

warning() {
    echo -e "${YELLOW}$1${NC}"
}

# ------------------------------------------------------------
# Database update
# ------------------------------------------------------------
update_database() {

    echo
    warning "Updating signatures..."
    echo

    freshclam

    success "Virus database updated."
}

# ------------------------------------------------------------
# Scanner engine
# ------------------------------------------------------------
run_scan() {

    local target="$1"
    local quarantine="${2:-false}"
    local exclude_dirs="${3:-}"

    [[ ! -e "$target" ]] && return

    local tmp_log
    tmp_log=$(mktemp)

    echo
    echo -e "${BLUE}Target:${NC} $target"
    echo

    tput civis 2>/dev/null || true

    if [[ "$quarantine" == "true" ]]; then

        # shellcheck disable=SC2086
        clamscan \
            -r \
            $exclude_dirs \
            --move="$QUARANTINE_DIR" \
            "$target" \
            2>&1 | tee "$tmp_log" >> "$SCAN_LOG" &

    else

        # shellcheck disable=SC2086
        clamscan \
            -r \
            $exclude_dirs \
            "$target" \
            2>&1 | tee "$tmp_log" >> "$SCAN_LOG" &
    fi

    local scan_pid=$!
    local index=0

    while kill -0 "$scan_pid" 2>/dev/null; do

        local current_file=$(grep "^/" "$tmp_log" | tail -1 || true)

        printf "\r${GREEN}[Scanning]${NC} %s " \
            "${spinner[$index]}"

        if [[ -n "${current_file:-}" ]]; then
            printf "${CYAN}%s${NC}" "$current_file"
        fi

        index=$(( (index + 1) % 4 ))

        sleep 0.10

    done

    local scan_status=0
    set +e
    wait "$scan_pid"
    scan_status=$?
    set -e

    echo
    echo

    if (( scan_status > 1 )); then

        echo -e "${RED}Scan failed or was interrupted. Exit code: ${scan_status}${NC}"

    elif grep -q "Infected files: 0" "$tmp_log"; then
        success "No threats detected."

    else

        echo -e "${RED}Threats detected:${NC}"
        grep "FOUND" "$tmp_log" || true

    fi

    rm -f "$tmp_log"

    tput cnorm 2>/dev/null || true
}

# ------------------------------------------------------------
quick_scan() {

    run_scan "/tmp"
}

# ------------------------------------------------------------
home_scan() {

    run_scan "$USER_HOME"
}

# ------------------------------------------------------------
system_scan() {

    run_scan "/" false \
        "--exclude-dir=^/proc --exclude-dir=^/sys --exclude-dir=^/dev --exclude-dir=^/run"
}

# ------------------------------------------------------------
custom_scan() {

    echo
    read -rp "Enter file or directory: " path

    run_scan "$path"
}

# ------------------------------------------------------------
quarantine_scan() {

    echo
    read -rp "Enter file or directory: " path

    run_scan "$path" true
}

# ------------------------------------------------------------
view_logs() {

    clear 2>/dev/null || true

    [[ -f "$SCAN_LOG" ]] || touch "$SCAN_LOG"

    less "$SCAN_LOG"
}

# ------------------------------------------------------------
database_info() {

    clear 2>/dev/null || true

    shopt -s nullglob
    local db_files=(/var/lib/clamav/*.cvd /var/lib/clamav/*.cld)
    shopt -u nullglob

    if (( ${#db_files[@]} )); then
        local db_file
        for db_file in "${db_files[@]}"; do
            sigtool --info "$db_file" 2>/dev/null || true
            echo
        done
    else
        warning "No ClamAV database files found."
    fi

    echo
}

# ------------------------------------------------------------
stats() {

    clear 2>/dev/null || true

    echo
    echo " Log file:"
    echo " $SCAN_LOG"
    echo

    echo " Threats found:"
    grep -c "FOUND" "$SCAN_LOG" 2>/dev/null || echo "0"

    echo

    echo " Total scans:"
    grep -c "SCAN SUMMARY" "$SCAN_LOG" 2>/dev/null || echo "0"

    echo
}

# ------------------------------------------------------------
scheduler() {

    clear 2>/dev/null || true

    echo
    echo " Example cron jobs"
    echo
    echo " Daily database update:"
    echo "  0 4 * * * freshclam"
    echo
    echo " Weekly home scan:"
    echo "  0 2 * * 0 clamscan -r \$HOME"
    echo
}

# ============================================================
# Main
# ============================================================
main() {

    check_requirements

    while true; do

        header

        read -rp "Selection: " choice

        case "$choice" in

            1) update_database ;;
            2) quick_scan ;;
            3) home_scan ;;
            4) system_scan ;;
            5) custom_scan ;;
            6) quarantine_scan ;;
            7) view_logs ;;
            8) database_info ;;
            9) stats ;;
            10) scheduler ;;
            0) exit 0 ;;

            *) warning "Invalid selection." ;;

        esac

        pause

    done
}

main
