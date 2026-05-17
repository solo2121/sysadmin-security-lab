#!/usr/bin/env bash
set -Eeuo pipefail

export VAGRANT_DEFAULT_PROVIDER=libvirt

# ============================================================
# VAGRANT LAB MANAGER v6.2 (STABLE 2026 EDITION)
# ============================================================

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- Groups ----------
readonly DEVOPS=("devops-1")
readonly WORKERS=("worker-1" "worker-2")
readonly ANSIBLE_NODES=("node1" "node2")
readonly LINUX_LABS=("ubuntu-lab" "rocky-lab" "alma-lab" "suse-lab")

declare -A machine_states=()
declare -A machine_options=()
machine_names=()

# ---------- Cleanup ----------
cleanup() {
    printf "\n${YELLOW}Exiting...${NC}\n"
    exit 0
}
trap cleanup INT TERM

# ---------- UI ----------
clear_screen() {
    clear || printf "\033[H\033[2J"
}

header() {
    printf "${BLUE}┌──────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}│ ${WHITE}${BOLD}VAGRANT LAB MANAGER v6.2${NC}           ${BLUE}│${NC}\n"
    printf "${BLUE}└──────────────────────────────────────────────┘${NC}\n"
}

pause() {
    read -r -p "Press Enter to continue..."
}

error() {
    printf "${RED}✗ %s${NC}\n" "$1"
}

icon() {
    case "$1" in
        running) echo -e "${GREEN}▶${NC}" ;;
        poweroff) echo -e "${RED}■${NC}" ;;
        not_created) echo -e "${YELLOW}○${NC}" ;;
        saved) echo -e "${CYAN}◉${NC}" ;;
        *) echo -e "${GRAY}?${NC}" ;;
    esac
}

# ---------- Requirements ----------
check_requirements() {
    command -v vagrant >/dev/null || { error "vagrant not installed"; exit 1; }
    vagrant plugin list | grep -qi libvirt || { error "vagrant-libvirt missing"; exit 1; }
}

# ---------- Refresh ----------
refresh() {
    machine_states=()
    machine_names=()

    while IFS=',' read -r _ name type state; do
        [[ "$type" != "state" ]] && continue
        [[ -z "$name" ]] && continue
        machine_states["$name"]="$state"
    done < <(vagrant status --machine-readable 2>/dev/null || true)

    if ((${#machine_states[@]} > 0)); then
        mapfile -t machine_names < <(printf '%s\n' "${!machine_states[@]}" | sort)
    fi
}

# ---------- VM ACTION ----------
run_vm() {
    local action="$1"
    local vm="$2"

    case "$action" in
        ssh) vagrant ssh "$vm" ;;
        up) vagrant up "$vm" --provision ;;
        start) vagrant up "$vm" ;;
        halt) vagrant halt "$vm" ;;
        reload) vagrant reload "$vm" --provision ;;
        provision) vagrant provision "$vm" ;;
        destroy) vagrant destroy -f "$vm" ;;
    esac
}

# ---------- GROUP DISPLAY ----------
show_group() {
    local title="$1"
    shift

    echo
    echo -e "${PURPLE}${BOLD}${title}${NC}"
    printf "${GRAY}────────────────────────────────────────────${NC}\n"

    for vm in "$@"; do
        local state="${machine_states[$vm]:-not_created}"

        printf " ${CYAN}[%02d]${NC} %-18s %-3s %-12s\n" \
            "$IDX" \
            "$vm" \
            "$(icon "$state")" \
            "$state"

        machine_options["$IDX"]="$vm"
        ((IDX++))
    done
}

# ---------- VM MENU ----------
vm_menu() {
    local vm="$1"

    while true; do
        refresh
        clear_screen
        header

        echo
        printf " VM:    ${CYAN}%s${NC}\n" "$vm"
        printf " State: ${YELLOW}%s${NC}\n" "${machine_states[$vm]:-not_created}"

        echo
        echo "[S] SSH"
        echo "[U] Up + Provision"
        echo "[T] Start"
        echo "[H] Halt"
        echo "[R] Reload"
        echo "[P] Provision"
        echo "[D] Destroy"
        echo "[B] Back"
        echo "[Q] Quit"

        echo
        read -r -p "Selection › " sel

        case "${sel^^}" in
            S) run_vm ssh "$vm"; pause ;;
            U) run_vm up "$vm"; pause ;;
            T) run_vm start "$vm"; pause ;;
            H) run_vm halt "$vm"; pause ;;
            R) run_vm reload "$vm"; pause ;;
            P) run_vm provision "$vm"; pause ;;
            D) run_vm destroy "$vm"; pause ;;
            B) return ;;
            Q) exit 0 ;;
            *) error "Invalid selection"; pause ;;
        esac
    done
}

# ---------- GROUP ACTIONS ----------
start_group() {
    case "$1" in
        devops)   for vm in "${DEVOPS[@]}"; do vagrant up "$vm" --provision; done ;;
        worker)   for vm in "${WORKERS[@]}"; do vagrant up "$vm" --provision; done ;;
        ansible)  for vm in "${ANSIBLE_NODES[@]}"; do vagrant up "$vm" --provision; done ;;
        labs)     for vm in "${LINUX_LABS[@]}"; do vagrant up "$vm" --provision; done ;;
        all)      vagrant up --provision ;;
    esac
}

halt_all() {
    vagrant halt -f || true
}

# ---------- MAIN ----------
check_requirements

while true; do
    refresh
    clear_screen

    IDX=1
    machine_options=()

    header

    show_group "DEVOPS" "${DEVOPS[@]}"
    show_group "WORKERS" "${WORKERS[@]}"
    show_group "ANSIBLE NODES" "${ANSIBLE_NODES[@]}"
    show_group "LINUX LABS" "${LINUX_LABS[@]}"

    echo
    echo "[A] Start All"
    echo "[V] Start DevOps"
    echo "[W] Start Workers"
    echo "[N] Start Ansible"
    echo "[L] Start Linux Labs"
    echo "[B] Halt All"
    echo "[R] Refresh"
    echo "[Q] Quit"

    echo
    read -r -p "Selection › " sel

    if [[ "$sel" =~ ^[0-9]+$ ]]; then
        if [[ -n "${machine_options[$sel]:-}" ]]; then
            vm_menu "${machine_options[$sel]}"
        else
            error "Invalid VM selection"
            pause
        fi
        continue
    fi

    case "${sel^^}" in
        A) start_group all; pause ;;
        V) start_group devops; pause ;;
        W) start_group worker; pause ;;
        N) start_group ansible; pause ;;
        L) start_group labs; pause ;;
        B) halt_all; pause ;;
        R) ;;
        Q) exit 0 ;;
        *) error "Invalid selection"; pause ;;
    esac

done