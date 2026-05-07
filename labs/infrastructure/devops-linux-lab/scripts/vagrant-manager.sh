#!/usr/bin/env bash
# ============================================================
# LINUX VAGRANT MANAGER v4.0 (Grouped Lab Control)
# ============================================================

export VAGRANT_DEFAULT_PROVIDER="libvirt"

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

declare -A machine_states machine_options
declare -a machine_names
IDX=1

HAS_VIRSH=$(command -v virsh >/dev/null 2>&1 && echo 1 || echo 0)

# ---------- GROUPS ----------
DEVOPS=("devops")
K8S=("k8s-cp" "k8s-w1" "k8s-w2")
LINUX_LABS=("ubuntu-lab" "rocky-lab" "alma-lab" "opensuse-lab")

# ---------- UI ----------
clear_screen(){ printf "\033[H\033[2J"; }

header(){
  printf "${BLUE}┌──────────────────────────────────────────────┐${NC}\n"
  printf "${BLUE}│ ${BOLD}${WHITE}LINUX LAB MANAGER v4.0${NC}              │${NC}\n"
  printf "${BLUE}└──────────────────────────────────────────────┘${NC}\n"
}

icon(){
  case "$1" in
    running) echo -e "${GREEN}▶${NC}" ;;
    poweroff) echo -e "${RED}⏹${NC}" ;;
    not_created) echo -e "${YELLOW}○${NC}" ;;
    *) echo -e "${YELLOW}?${NC}" ;;
  esac
}

# ---------- STATUS ----------
refresh(){
  machine_names=()
  machine_states=()

  while IFS=',' read -r _ name type state; do
    [[ "$type" == "state" ]] || continue
    [[ -z "$name" ]] && continue
    machine_names+=("$name")
    machine_states["$name"]="$state"
  done < <(vagrant status --machine-readable 2>/dev/null)

  mapfile -t machine_names < <(printf '%s\n' "${machine_names[@]}" | sort -u)

  if (( HAS_VIRSH )); then
    for m in "${machine_names[@]}"; do
      s=$(virsh domstate "$m" 2>/dev/null)
      case "$s" in
        running) machine_states["$m"]="running" ;;
        shut*|off) machine_states["$m"]="poweroff" ;;
        *) machine_states["$m"]="not_created" ;;
      esac
    done
  fi
}

get_ip(){
  [[ "${machine_states[$1]}" != "running" ]] && { echo "offline"; return; }
  virsh domifaddr "$1" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1
}

# ---------- DISPLAY GROUP ----------
show_group(){
  local title=$1; shift
  local group=("$@")

  echo
  echo -e "${PURPLE}${BOLD}$title${NC}"
  printf "${GRAY}────────────────────────────────────────────${NC}\n"

  for m in "${group[@]}"; do
    printf " ${CYAN}[%02d]${NC} %-25s %-3s %-10s ${GRAY}%s${NC}\n" \
      "$IDX" "$m" "$(icon "${machine_states[$m]}")" \
      "${machine_states[$m]}" "$(get_ip "$m")"

    machine_options[$IDX]="$m"
    ((IDX++))
  done
}

# ---------- MENU ----------
menu(){
  clear_screen
  IDX=1
  machine_options=()

  header

  show_group "DEVOPS" "${DEVOPS[@]}"
  show_group "KUBERNETES" "${K8S[@]}"
  show_group "LINUX LABS" "${LINUX_LABS[@]}"

  echo
  echo -e "${CYAN}[A] Start All  [K] Start K8s  [L] Start Labs"
  echo -e "[H] Halt VM  [B] Halt All  [D] Destroy VM  [R] Refresh  [Q] Quit${NC}"
}

# ---------- ACTIONS ----------
vm_action(){
  local vm="$1"
  local state="${machine_states[$vm]}"

  case "$state" in
    running) vagrant ssh "$vm" ;;
    *) vagrant up "$vm" ;;
  esac
}

pause(){
  echo
  printf "${GRAY}Press Enter to continue...${NC}"
  read -r
}

vm_menu(){
  local vm="$1"
  local sel

  [[ -z "$vm" ]] && return

  while true; do
    refresh
    clear_screen
    header

    echo
    echo -e "${PURPLE}${BOLD}VM MANAGEMENT${NC}"
    printf "${GRAY}────────────────────────────────────────────${NC}\n"
    printf " VM:     ${CYAN}%s${NC}\n" "$vm"
    printf " State:  %-3s %-12s\n" "$(icon "${machine_states[$vm]}")" "${machine_states[$vm]}"
    printf " IP:     ${GRAY}%s${NC}\n" "$(get_ip "$vm")"

    echo
    echo -e "${CYAN}[S] SSH into VM"
    echo -e "[U] Start / Up VM"
    echo -e "[H] Halt VM"
    echo -e "[R] Reload VM"
    echo -e "[P] Provision VM"
    echo -e "[D] Destroy VM"
    echo -e "[I] Refresh Status / IP"
    echo -e "[B] Back to Main Menu"
    echo -e "[Q] Quit${NC}"
    echo

    printf "${BOLD}Action for $vm › ${NC}"
    read -r sel

    case "${sel^^}" in
      S)
        if [[ "${machine_states[$vm]}" == "running" ]]; then
          vagrant ssh "$vm"
        else
          echo -e "${YELLOW}$vm is not running. Start it first with [U].${NC}"
          pause
        fi
        ;;
      U)
        vagrant up "$vm"
        pause
        ;;
      H)
        vagrant halt "$vm"
        pause
        ;;
      R)
        vagrant reload "$vm"
        pause
        ;;
      P)
        vagrant provision "$vm"
        pause
        ;;
      D)
        echo -e "${RED}${BOLD}Destroy $vm? This removes the VM.${NC}"
        printf "Type ${BOLD}yes${NC} to confirm › "
        read -r confirm

        if [[ "$confirm" == "yes" ]]; then
          vagrant destroy -f "$vm"
          pause
        fi
        ;;
      I)
        refresh
        ;;
      B)
        return
        ;;
      Q)
        exit
        ;;
    esac
  done
}

start_group(){
  for m in "$@"; do
    echo -e "${YELLOW}Starting $m...${NC}"
    vagrant up "$m"
  done
}

halt_vm(){
  local vm
  local choice

  printf "VM number › "
  read -r choice
  vm="${machine_options[$choice]}"
  [[ -n "$vm" ]] && vagrant halt "$vm"
}

destroy_vm(){
  local vm
  local choice

  printf "VM number › "
  read -r choice
  vm="${machine_options[$choice]}"
  [[ -n "$vm" ]] && vagrant destroy -f "$vm"
}

halt_all(){
  for m in "${machine_names[@]}"; do
    vagrant halt "$m"
  done
}

# ---------- MAIN ----------
refresh

while true; do
  menu
  printf "${BOLD}Selection › ${NC}"
  read -r sel

  if [[ "$sel" =~ ^[0-9]+$ ]]; then
    vm_menu "${machine_options[$sel]}"
    refresh
    continue
  fi

  case "${sel^^}" in
    Q) exit ;;
    R) refresh ;;
    A) start_group "${machine_names[@]}" ;;
    K) start_group "${K8S[@]}" ;;
    L) start_group "${LINUX_LABS[@]}" ;;
    H) halt_vm ;;
    B) halt_all ;;
    D) destroy_vm ;;
  esac

  refresh
done
