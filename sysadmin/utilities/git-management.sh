#!/usr/bin/env bash
# ============================================================
# Git Management Toolkit
# Author: Miguel A. Carlo
# Description: Interactive Git helper for common repository
#              status, branch, commit, remote, and sync tasks.
# ============================================================

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail
shopt -s nocasematch

handle_error() {
    local exit_code=${1:-$?}
    local line_number=${2:-$LINENO}
    local command_name=${3:-$BASH_COMMAND}
    printf "Error occurred in '%s' at line %d: command '%s' exited with status %d\n" \
        "${0##*/}" "$line_number" "$command_name" "$exit_code" >&2
    exit "$exit_code"
}

trap 'handle_error $? $LINENO "$BASH_COMMAND"' ERR

for completion_file in \
    /usr/share/bash-completion/completions/git \
    /etc/bash_completion.d/git \
    ~/.git-completion.bash
do
    if [[ -f "$completion_file" ]]; then
        # shellcheck disable=SC1090
        source "$completion_file"
        break
    fi
done

bind -x '"\C-l": clear' || true
bind 'set completion-ignore-case on' || true
bind 'set show-all-if-ambiguous on' || true
bind 'TAB:menu-complete' || true

show_menu() {
    clear
    printf "%s\n" "==================================" \
                  "        Git Management Menu" \
                  "==================================" \
                  "1. Check Git Status" \
                  "2. Add Files to Staging" \
                  "3. Commit Changes" \
                  "4. Push to Remote" \
                  "5. Fetch from Remote" \
                  "6. Pull from Remote" \
                  "7. View Git Log" \
                  "8. View Branches" \
                  "9. Exit" \
                  "=================================="
}

check_git_repo() {
    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        printf "Error: Not a git repository!\n" >&2
        exit 1
    fi
}

git_status() {
    printf "\nGit Status:\n"
    printf "%s\n" "----------"
    git status
}

add_files() {
    printf "\nCurrent status:\n"
    git status --short
    printf "\n"

    read -rp "Add all files? (y/n) or specify files: " choice
    case "$choice" in
        [yY]|[yY][eE][sS])
            git add .
            printf "All files added to staging area.\n"
            ;;
        [nN]|[nN][oO])
            read -rp "Enter file names to add (space-separated), or press Enter to cancel: " -a files_to_add
            if (( ${#files_to_add[@]} > 0 )); then
                git add "${files_to_add[@]}"
                printf "Added: %s\n" "${files_to_add[*]}"
            else
                printf "No files added.\n"
                return 1
            fi
            ;;
        *)
            read -ra files_to_add <<<"$choice"
            if (( ${#files_to_add[@]} > 0 )); then
                git add "${files_to_add[@]}"
                printf "Added: %s\n" "${files_to_add[*]}"
            else
                printf "No files added.\n"
                return 1
            fi
            ;;
    esac
}

commit_changes() {
    printf "\nStaged files:\n"
    git diff --cached --name-only || true
    printf "\n"

    printf "Enter commit details (following CONTRIBUTING.md standards):\n"
    printf "Common types: feat, fix, docs, style, refactor, test, chore\n"

    read -rp "Type (e.g., feat): " type
    read -rp "Scope (optional, e.g., git-tool): " scope
    read -rp "Description: " description

    if [[ -z "$type" || -z "$description" ]]; then
        printf "Error: Type and Description are required.\n" >&2
        return 1
    fi

    local commit_msg
    if [[ -n "$scope" ]]; then
        commit_msg="$type($scope): $description"
    else
        commit_msg="$type: $description"
    fi

    if ! git commit -m "$commit_msg"; then
        printf "Commit failed!\n" >&2
        return 1
    fi
    printf "Changes committed successfully with message: %s\n" "$commit_msg"
}

push_changes() {
    local current_branch branch confirm proceed
    current_branch=$(git branch --show-current)

    if [[ -z "$current_branch" ]]; then
        printf "Error: Could not determine current branch.\n" >&2
        return 1
    fi

    if [[ "$current_branch" == "main" || "$current_branch" == "master" ]]; then
        printf "Warning: You are attempting to push directly to the protected branch '%s'.\n" "$current_branch"
        read -rp "This is generally not recommended. Continue? (y/n): " proceed
        [[ "$proceed" =~ ^[yY]$ ]] || return 1
    fi

    printf "\nPushing changes to remote repository...\n"
    read -rp "Push to branch '$current_branch'? (y/n): " confirm

    if [[ "$confirm" =~ ^[yY]$ ]]; then
        branch="$current_branch"
    else
        read -rp "Enter branch name (default: $current_branch): " branch
        branch=${branch:-$current_branch}
    fi

    if [[ -z "$branch" ]]; then
        printf "Error: Branch name cannot be empty.\n" >&2
        return 1
    fi

    if ! git push origin "$branch"; then
        printf "Push to branch '%s' failed!\n" "$branch" >&2
        return 1
    fi

    printf "Changes pushed successfully to '%s'!\n" "$branch"
}

fetch_changes() {
    printf "\nFetching changes from remote repository...\n"
    if ! git fetch; then
        printf "Fetch failed!\n" >&2
        return 1
    fi
    printf "Fetch completed!\n\n"

    printf "Remote changes summary:\n"
    if ! git log HEAD..origin/"$(git branch --show-current)" --oneline 2>/dev/null; then
        printf "No new changes to fetch.\n"
    fi
}

pull_changes() {
    local current_branch
    current_branch=$(git branch --show-current)

    if [[ -z "$current_branch" ]]; then
        printf "Error: Could not determine current branch.\n" >&2
        return 1
    fi

    printf "\nPulling changes from remote repository...\n"
    if ! git pull origin "$current_branch"; then
        printf "Pull failed!\n" >&2
        return 1
    fi
    printf "Pull completed!\n"
}

view_log() {
    printf "\nGit Log (last 10 commits):\n"
    printf "%s\n" "-------------------------"
    git log --oneline -10
    printf "\n"

    read -rp "View detailed log? (y/n): " detail
    if [[ "$detail" =~ ^[yY]$ ]]; then
        git log -5 --pretty=format:"%h - %an, %ar : %s"
        printf "\n"
    fi
}

view_branches() {
    printf "\nLocal branches:\n"
    printf "%s\n" "---------------"
    git branch
    printf "\nRemote branches:\n"
    printf "%s\n" "----------------"
    git branch -r
}

wait_for_input() {
    read -rp "Press Enter to continue..."
}

main() {
    check_git_repo

    while true; do
        show_menu
        read -rp "Please select an option (1-9): " choice

        case "$choice" in
            1) clear; git_status; wait_for_input ;;
            2) clear; add_files; wait_for_input ;;
            3) clear; commit_changes; wait_for_input ;;
            4) clear; push_changes; wait_for_input ;;
            5) clear; fetch_changes; wait_for_input ;;
            6) clear; pull_changes; wait_for_input ;;
            7) clear; view_log; wait_for_input ;;
            8) clear; view_branches; wait_for_input ;;
            9) printf "Goodbye!\n"; exit 0 ;;
            *)
                printf "Invalid option! Please select 1-9.\n" >&2
                sleep 1
                ;;
        esac
    done
}

main "$@"