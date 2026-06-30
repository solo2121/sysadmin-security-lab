#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo " Markdown Filename Normalizer"
echo "========================================="

rename_file() {
    local file="$1"

    dir="$(dirname "$file")"
    base="$(basename "$file")"

    # Skip GitHub standard files
    case "$base" in
        README.md|LICENSE|SECURITY.md|CONTRIBUTING.md|CHANGELOG.md|CODE_OF_CONDUCT.md)
            return
            ;;
    esac

    new=$(echo "$base" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/_/-/g' \
        | sed 's/ /-/g' \
        | sed 's/--*/-/g')

    if [[ "$base" != "$new" ]]; then
        echo
        echo "$base"
        echo " -> $new"

        git mv "$file" "$dir/$new"
    fi
}

export -f rename_file

find . -type f -name "*.md" \
    ! -path "./.git/*" \
    -print0 |
while IFS= read -r -d '' file
do
    rename_file "$file"
done

echo
echo "Done."