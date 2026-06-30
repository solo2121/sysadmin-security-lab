#!/usr/bin/env bash
set -euo pipefail

echo "Fixing markdown link references..."

declare -A MAP=(
  ["ARCHITECTURE.md"]="architecture.md"
  ["LAB_GUIDE.md"]="lab-guide.md"
  ["SECURITY-HARDENING.md"]="security-hardening.md"
  ["SETUP-GUIDE.md"]="setup-guide.md"
  ["Complete-DevOps-Platform-Guide.md"]="complete-devops-platform-guide.md"
  ["AD_MITRE_log_source_playbook.md"]="ad-mitre-log-source-playbook.md"
  ["SECURITY-SCOPE.md"]="security-scope.md"
)

for old in "${!MAP[@]}"; do
  new="${MAP[$old]}"
  echo "Fixing: $old → $new"

  find . -type f -name "*.md" -exec sed -i "s|$old|$new|g" {} +
done

echo "Done."
