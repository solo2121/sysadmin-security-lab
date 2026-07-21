#!/usr/bin/env bash
# ============================================================
# Linux Log Analysis Tool
# Author: Miguel A. Carlo
# Description: Interactive log triage utility for system, auth,
#              kernel, and web logs with filtering and live views.
# ============================================================

set -Eeuo pipefail

VERSION="2.0.0"

if [[ -t 1 ]]; then
  RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
  BLUE=$(tput setaf 4); CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; RESET=''
fi

SYSTEM_LOG_PATHS=("/var/log/syslog" "/var/log/messages")
AUTH_LOG_PATHS=("/var/log/auth.log" "/var/log/secure")
KERNEL_LOG_PATHS=("/var/log/kern.log" "/var/log/dmesg")
WEB_ACCESS_PATHS=("/var/log/apache2/access.log" "/var/log/nginx/access.log")
WEB_ERROR_PATHS=("/var/log/apache2/error.log" "/var/log/nginx/error.log")

pause(){ echo; read -r -p "Press Enter to continue..."; }
warn(){ printf "${YELLOW}%s${RESET}\n" "$*"; }
error(){ printf "${RED}%s${RESET}\n" "$*" >&2; }

find_first_log(){
  local path

  for path in "$@"; do
    [[ -r "$path" ]] && { printf '%s\n' "$path"; return 0; }
  done

  return 1
}

display_header(){
  clear 2>/dev/null || true
  printf "${BLUE}=============================================${RESET}\n"
  printf "${BOLD} Linux Log Analysis Tool v%s${RESET}\n" "$VERSION"
  printf " Author: Miguel A. Carlo\n"
  printf "${BLUE}=============================================${RESET}\n"
  echo
}

section(){
  printf "\n${CYAN}== %s ==${RESET}\n" "$*"
}

show_matches(){
  local title="$1"
  local pattern="$2"
  local file="$3"
  local count="${4:-20}"

  section "$title"
  grep -Ei --color=always "$pattern" "$file" 2>/dev/null | tail -n "$count" || warn "No matches."
}

summarize_errors(){
  local file="$1"

  section "Most frequent error messages"
  grep -Ei 'error|fail|critical|segfault|denied' "$file" 2>/dev/null \
    | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //' \
    | sort \
    | uniq -c \
    | sort -nr \
    | head -10 || warn "No error summary available."
}

analyze_log_file(){
  local title="$1"
  local file="$2"

  display_header
  section "$title ($(basename "$file"))"
  printf "${BOLD}Path:${RESET} %s\n" "$file"
  printf "${BOLD}Size:${RESET} %s\n" "$(du -h "$file" 2>/dev/null | awk '{print $1}')"
  printf "${BOLD}Modified:${RESET} %s\n" "$(stat -c '%y' "$file" 2>/dev/null || true)"

  show_matches "Recent warnings" 'warn|warning' "$file"
  show_matches "Recent errors" 'error|fail|failed|critical|segfault|denied' "$file"
  summarize_errors "$file"
  pause
}

analyze_from_paths(){
  local title="$1"
  shift
  local file

  file="$(find_first_log "$@")" || {
    error "No readable log file found for: $title"
    pause
    return
  }

  analyze_log_file "$title" "$file"
}

analyze_system_logs(){ analyze_from_paths "System Logs" "${SYSTEM_LOG_PATHS[@]}"; }
analyze_auth_logs(){ analyze_from_paths "Authentication Logs" "${AUTH_LOG_PATHS[@]}"; }
analyze_kernel_logs(){ analyze_from_paths "Kernel Logs" "${KERNEL_LOG_PATHS[@]}"; }
analyze_web_access_logs(){ analyze_from_paths "Web Access Logs" "${WEB_ACCESS_PATHS[@]}"; }
analyze_web_error_logs(){ analyze_from_paths "Web Error Logs" "${WEB_ERROR_PATHS[@]}"; }

analyze_custom_log(){
  local file

  display_header
  read -r -p "Log file path: " file
  [[ -r "$file" ]] || { error "File is not readable: $file"; pause; return; }
  analyze_log_file "Custom Log" "$file"
}

realtime_monitoring_menu(){
  local file

  display_header
  read -r -p "Log file to follow: " file
  [[ -r "$file" ]] || { error "File is not readable: $file"; pause; return; }
  warn "Press Ctrl+C to stop live monitoring."
  sleep 1
  tail -f "$file"
}

search_all_logs(){
  local pattern path found=0
  local paths=(
    "${SYSTEM_LOG_PATHS[@]}"
    "${AUTH_LOG_PATHS[@]}"
    "${KERNEL_LOG_PATHS[@]}"
    "${WEB_ACCESS_PATHS[@]}"
    "${WEB_ERROR_PATHS[@]}"
  )

  display_header
  read -r -p "Search pattern: " pattern
  [[ -n "$pattern" ]] || { warn "Empty search pattern."; pause; return; }

  for path in "${paths[@]}"; do
    [[ -r "$path" ]] || continue
    section "$path"
    grep -Ein --color=always "$pattern" "$path" 2>/dev/null | tail -n 20 || true
    found=1
  done

  ((found)) || warn "No readable standard logs found."
  pause
}

display_menu(){
  echo -e "${GREEN}[1]${RESET} System logs"
  echo -e "${GREEN}[2]${RESET} Authentication logs"
  echo -e "${GREEN}[3]${RESET} Kernel logs"
  echo -e "${GREEN}[4]${RESET} Web access logs"
  echo -e "${GREEN}[5]${RESET} Web error logs"
  echo -e "${GREEN}[6]${RESET} Custom log file"
  echo -e "${GREEN}[7]${RESET} Real-time log monitoring"
  echo -e "${GREEN}[8]${RESET} Search standard logs"
  echo -e "${GREEN}[0]${RESET} Exit"
  echo
}

check_root_access(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    warn "Some logs may require root privileges for full access."
  fi
}

main_menu(){
  local choice

  while true; do
    display_header
    display_menu
    read -r -p "Selection: " choice

    case "$choice" in
      1) analyze_system_logs ;;
      2) analyze_auth_logs ;;
      3) analyze_kernel_logs ;;
      4) analyze_web_access_logs ;;
      5) analyze_web_error_logs ;;
      6) analyze_custom_log ;;
      7) realtime_monitoring_menu ;;
      8) search_all_logs ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid option."; sleep 1 ;;
    esac
  done
}

# Only run interactively if executed directly, not when sourced (e.g. by tests)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  check_root_access
  main_menu
fi
