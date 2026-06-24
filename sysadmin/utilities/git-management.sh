#!/usr/bin/env bash
# ============================================================
# Git Management Toolkit
# Author: Miguel A. Carlo
# Description: Interactive Git helper for common repository
#              status, branch, commit, remote, and sync tasks.
# ============================================================

# Enable strict mode
set -o errexit      # Exit on error
set -o nounset      # Exit on unset variables
set -o pipefail     # Catch pipe failures
shopt -s nocasematch # Case-insensitive matching

# Error handling function
handle_error() {
    local exit_code=$?
    local line_number=$1
    local command_name=${2:-"unknown"}
    echo "Error occurred at line $line_number: command '$command_name' exited with status $exit_code" >&2
    exit "$exit_code"
}

trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# Enable git completion if available
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

# Enhanced readline settings
bind -x '"\C-l": clear' # Bind Ctrl+L to clear
bind 'set completion-ignore-case on'
bind 'set show-all-if-ambiguous on'
bind 'TAB:menu-complete'

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
    if ! git rev-parse --git-dir &>/dev/null; then
        printf "Error: Not a git repository!\\n" >&2
        exit 1
    fi
}

git_status() {
    printf "\\nGit Status:\\n"
    printf "%s\\n" "----------"
    git status
}

add_files() {
    printf "\\nCurrent status:\\n"
    git status --short
    printf "\\n"
    
    read -rp "Add all files? (y/n) or specify files: " choice

    case "$choice" in
        [yY]|[yY][eE][sS])
            git add .
            printf "All files added to staging area.\\n"
            ;;
        *)
            read -rp "Enter file names to add (space-separated), or press Enter to cancel: " -a files_array
            if (( ${#files_array[@]} > 0 )); then
                git add "${files_array[@]}"
                printf "Selected files added to staging area.\\n"
            else 
                printf "No files added.\\n"
                return 1
            fi
            ;;
    esac
}

commit_changes() {
    printf "\\nStaged files:\\n"
    git diff --cached --name-only
    printf "\\n"
    
    printf "Enter commit details (following CONTRIBUTING.md standards):\\n"
    printf "Common types: feat, fix, docs, style, refactor, test, chore\\n"
    
    read -rp "Type (e.g., feat): " type
    read -rp "Scope (optional, e.g., git-tool): " scope
    read -rp "Description: " description

    if [[ -z "$type" || -z "$description" ]]; then
        printf "Error: Type and Description are required.\\n" >&2
        return 1
    fi

    local commit_msg
    if [[ -n "$scope" ]]; then
        commit_msg="$type($scope): $description"
    else
        commit_msg="$type: $description"
    fi

    if ! git commit -m "$commit_msg"; then
        printf "Commit failed!\\n" >&2
        return 1
    fi
    printf "Changes committed successfully with message: %s\\n" "$commit_msg"
}

push_changes() {
    local current_branch
    current_branch=$(git branch --show-current)
    
    # Safety check for protected branches
    if [[ "$current_branch" == "main" || "$current_branch" == "master" ]]; then
        printf "Warning: You are attempting to push directly to the protected branch '%s'.\\n" "$current_branch"
        read -rp "Are you sure you want to continue? (y/n): " proceed
        [[ "$proceed" =~ ^[yY] ]] || return 1
    fi

    printf "\\nPushing changes to remote repository...\\n"
    read -rp "Push to branch '$current_branch'? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[yY] ]]; then
        if ! git push origin "$current_branch"; then
            printf "Push failed!\\n" >&2
            return 1
        fi
    else
        read -rp "Enter branch name: " branch
        if [[ -z "$branch" ]]; then
            printf "Error: Branch name cannot be empty.\\n" >&2
            return 1
        fi
        if ! git push origin "$branch"; then
            printf "Push failed!\\n" >&2
            return 1
        fi
    fi
    
    printf "Changes pushed successfully!\\n"
}

fetch_changes() {
    printf "\\nFetching changes from remote repository...\\n"
    if ! git fetch; then
        printf "Fetch failed!\\n" >&2
        return 1
    fi
    printf "Fetch completed!\\n\\n"
    
    printf "Remote changes summary:\\n"
    if ! git log HEAD..origin/"$(git branch --show-current)" --oneline 2>/dev/null; then
        printf "No new changes to fetch.\\n"
    fi
}

pull_changes() {
    local current_branch
    current_branch=$(git branch --show-current)
    
    printf "\\nPulling changes from remote repository...\\n"
    if ! git pull origin "$current_branch"; then
        printf "Pull failed!\\n" >&2
        return 1
    fi
    printf "Pull completed!\\n"
}

view_log() {
    printf "\\nGit Log (last 10 commits):\\n"
    printf "%s\\n" "-------------------------"
    git log --oneline -10
    printf "\\n"
    
    read -rp "View detailed log? (y/n): " detail
    if [[ "$detail" =~ ^[yY] ]]; then
        git log -5 --pretty=format:"%h - %an, %ar : %s"
    fi
}

view_branches() {
    printf "\\nLocal branches:\\n"
    printf "%s\\n" "---------------"
    git branch
    printf "\\nRemote branches:\\n"
    printf "%s\\n" "----------------"
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
            9) printf "Goodbye!\\n"; exit 0 ;;
            *) 
                printf "Invalid option! Please select 1-9.\\n" >&2
                sleep 1
                ;;
        esac
    done
}

main "$@"
