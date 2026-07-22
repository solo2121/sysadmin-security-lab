#!/usr/bin/env bash
# ============================================================
# UFW Firewall Manager
# Author: Miguel A. Carlo
# Description: Menu-driven UFW administration tool for firewall
#              status, rule creation, rule deletion, logging,
#              and firewall enable/disable workflows.
# Version: 1.2
# Requires: ufw, bash 4+, root privileges
# ============================================================
set -euo pipefail
IFS=$'\n\t'
# -------------------------------------------------------------
# This script provides a menu-driven interface to manage UFW
# (Uncomplicated Firewall) rules, including adding, deleting,
# and toggling the firewall status.
# -------------------------------------------------------------

# --- constants -----------------------------------------------
SCRIPT_NAME="$(basename "${0:-}")"

# --- colours via tput (safe) ---------------------------------
RED=$(tput setaf 1)
GRN=$(tput setaf 2)
YEL=$(tput setaf 3)
BLU=$(tput setaf 4)
MAG=$(tput setaf 5)
CYN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BOLD=$(tput bold)
RESET=$(tput sgr0)
: "${RED}${GRN}${YEL}${BLU}${MAG}${CYN}${WHITE}${BOLD}${RESET}"
readonly RED GRN YEL BLU MAG CYN WHITE BOLD RESET

# --- sanity checks -------------------------------------------
command -v ufw >/dev/null 2>&1 || {
    echo "${RED}ufw not found – install first${RESET}" >&2
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    echo "${RED}${BOLD}Need root – restarting via sudo …${RESET}" >&2
    exec sudo "$0" "$@"
fi

# --- helpers -------------------------------------------------
log_info() { echo -e "${BLU}[*]${RESET} $1"; }
log_success() { echo -e "${GRN}[+]${RESET} $1"; }
log_warning() { echo -e "${YEL}[!]${RESET} $1"; }
log_error() { echo -e "${RED}[-]${RESET} $1" >&2; }

pause() { read -rp "${YEL}${BOLD}Press Enter to continue …${RESET}"; }


print_status() {
    echo
    if ufw status | grep -q 'Status: active'; then
        echo "${GRN}● UFW is ACTIVE${RESET}"
    else
        echo "${RED}● UFW is INACTIVE${RESET}"
    fi
    echo
}

print_rules() {
    echo -e "\n${BLU}${BOLD}=== CURRENT RULES ===${RESET}"
    ufw status numbered | sed \
        -e "s/^\[[0-9]\+/${YEL}${BOLD}&${RESET}/" \
        -e "s/ALLOW/${GRN}${BOLD}ALLOW${RESET}/g" \
        -e "s/DENY\|REJECT\|LIMIT/${RED}${BOLD}&${RESET}/g"
}

# --- add rule ------------------------------------------------
add_rule() {
    echo -e "\n${BLU}${BOLD}=== ADD RULE ===${RESET}"
    read -rp "${CYN}${BOLD}Action (allow/deny/reject/limit): ${RESET}" action
    if [[ ! "$action" =~ ^(allow|deny|reject|limit)$ ]]; then
        log_error "Invalid action."
    else
        read -rp "${CYN}${BOLD}Port/service (22, 80/tcp, http): ${RESET}" port
        if [[ -z $port ]]; then
            log_error "Port cannot be empty"
        fi

        read -rp "${CYN}${BOLD}From IP/CIDR (blank = any): ${RESET}" src
        cmd=(ufw "$action")
        [[ -n $src ]] && cmd+=(from "$src")
        cmd+=(to any port "$port")

        echo -e "\n${YEL}Running: ${cmd[*]}${RESET}"
        if "${cmd[@]}"; then
            log_success "Rule added"
        else
            log_error "Failed to add rule"
        fi
    fi
}

# --- delete rule ---------------------------------------------
delete_rule() {
    print_rules
    read -rp "${YEL}${BOLD}Rule number to delete (c = cancel): ${RESET}" num
    [[ $num == [cC] ]] && return
    if [[ ! $num =~ ^[0-9]+$ ]]; then
        log_error "Invalid number"
        return 1
    fi

    if ufw --force delete "$num"; then
        log_success "Rule deleted"
    else
        log_error "Could not delete rule"
    fi
}

# --- toggle / reset -----------------------------------------
toggle_firewall() {
    PS3="${YEL}${BOLD}Choose: ${RESET}"
    select choice in enable disable reload reset back; do
        case $choice in
            enable)  ufw enable ;;
            disable) ufw disable ;;
            reload)  ufw reload ;;
            reset)
                read -rp "${RED}${BOLD}Reset UFW? (y/N): ${RESET}" c
                [[ $c =~ [Yy] ]] && ufw --force reset
                ;;
            back|"") return ;;
            *) continue ;;
        esac
        break
    done
}

# --- main loop ----------------------------------------------
trap 'echo -e "\n${RED}Aborted by user${RESET}"; exit 130' INT TERM

while :; do
    clear
    echo "${BLU}${BOLD}"
    echo "============================================="
    echo "          UFW FIREWALL MANAGEMENT           "
    echo "=============================================${RESET}"
    print_status

    cat <<EOF
${WHITE}${BOLD}MENU:${RESET}
 ${BLU}1${RESET} Show rules
 ${BLU}2${RESET} Add rule
 ${BLU}3${RESET} Delete rule
 ${BLU}4${RESET} Toggle / reload / reset
 ${BLU}5${RESET} Exit
EOF

    read -rp "${YEL}${BOLD}Choice (1-5): ${RESET}" c
    case $c in
        1) clear; print_rules; pause ;;
        2) clear; add_rule; sleep 1 ;;
        3) clear; delete_rule; sleep 1 ;;
        4) clear; toggle_firewall; sleep 1 ;;
        5) echo "${BLU}${BOLD}Bye!${RESET}"; exit 0 ;;
        *) continue ;;
    esac
done
