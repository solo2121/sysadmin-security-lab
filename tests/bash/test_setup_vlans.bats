
#!/usr/bin/env bash

# Author: Miguel A. Carlo
# Description: VLAN setup helper script.

declare -A VLAN_CONFIG=(
    [10]="br-users:10.0.10.1:Users"
    [20]="br-servers:10.0.20.1:Servers"
    [30]="br-printers:10.0.30.1:Printers"
    [40]="br-management:10.0.40.1:Management"
    [99]="br-native:10.0.99.1:Native"
)

log_info()    { printf '[*] %s\n' "$*"; }
log_success() { printf '[+] %s\n' "$*"; }
log_warning() { printf '[!] %s\n' "$*"; }
log_error()   { printf '[-] %s\n' "$*" >&2; }

die() {
    log_error "$*"
    return 1
}

main() {
    # script logic here
    :
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi