#!/usr/bin/env bash
# Linux Network Security Audit Script

set -euo pipefail

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

echo -e "${BLUE}=== Linux Network Security Audit ===${RESET}\n"

# ------------------------------------------------------------
# 1. Network interfaces
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Network interfaces:${RESET}"
ip -brief addr
echo

# ------------------------------------------------------------
# 2. Routing table
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Routing table:${RESET}"
ip route
echo

# ------------------------------------------------------------
# 3. Listening ports (TCP/UDP)
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Listening ports (TCP/UDP):${RESET}"
ss -tulnp | sed '1d' || echo "  ss not available"
echo

# ------------------------------------------------------------
# 4. Services listening on all interfaces (0.0.0.0 / ::)
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Services listening on ALL interfaces:${RESET}"

exposed=$(ss -tulnp | awk '
    $5 ~ /0\.0\.0\.0|:::/ {
        print $1, $5, $7
    }
')

if [[ -n "$exposed" ]]; then
    echo -e "${RED}  WARNING: Externally exposed services:${RESET}"
    echo "$exposed" | sed 's/^/   - /'
else
    echo -e "${GREEN}  OK: No services listening on all interfaces${RESET}"
fi
echo

# ------------------------------------------------------------
# 5. SSH exposure
# ------------------------------------------------------------
echo -e "${YELLOW}[+] SSH exposure:${RESET}"

if ss -tlnp | grep -q ':22 '; then
    echo -e "${YELLOW}  SSH is listening:${RESET}"
    ss -tlnp | grep ':22 '
else
    echo -e "${GREEN}  SSH is not listening${RESET}"
fi
echo

# ------------------------------------------------------------
# 6. Firewall status
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Firewall status:${RESET}"

if command -v ufw &>/dev/null; then
    ufw status verbose
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --state
    firewall-cmd --list-all
elif command -v nft &>/dev/null; then
    nft list ruleset
else
    echo "  No firewall tool detected"
fi
echo

# ------------------------------------------------------------
# 7. IP forwarding (should be OFF on desktops)
# ------------------------------------------------------------
echo -e "${YELLOW}[+] IP forwarding:${RESET}"

ipv4_fwd=$(sysctl -n net.ipv4.ip_forward)
ipv6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "N/A")

if [[ "$ipv4_fwd" == "1" ]]; then
    echo -e "${RED}  WARNING: IPv4 forwarding ENABLED${RESET}"
else
    echo -e "${GREEN}  IPv4 forwarding disabled${RESET}"
fi

if [[ "$ipv6_fwd" == "1" ]]; then
    echo -e "${RED}  WARNING: IPv6 forwarding ENABLED${RESET}"
else
    echo -e "${GREEN}  IPv6 forwarding disabled${RESET}"
fi
echo

# ------------------------------------------------------------
# 8. Established external connections
# ------------------------------------------------------------
echo -e "${YELLOW}[+] Established external connections:${RESET}"
ss -tunp | awk '
    $1 == "ESTAB" && $5 !~ /127\.0\.0\.1|::1/ {
        print
    }
'
echo

# ------------------------------------------------------------
# 9. Summary
# ------------------------------------------------------------
echo -e "${BLUE}=== Network Audit Complete ===${RESET}"
echo -e "${GREEN}Review RED warnings carefully.${RESET}"
