#!/usr/bin/env bash

# Exit on error
set -e

REPO_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
YEAR=$(date +%Y)
OWNER="Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>" # Change this to your name/organization

# Define the GPLv3 header text
HEADER_TEXT="// Copyright ${YEAR} ${OWNER}
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details."

FILES=$(find "$REPO_DIR"/*/src -type f -name "*.rs")

for FILE in $FILES; do
  if grep -q "Copyright (C)" "$FILE"; then
    echo "Skipping (already has header): $FILE"
  else
    echo "Adding header to: $FILE"
    
    # Create a temporary file with the header + blank line + original content
    TMP_FILE=$(mktemp)
    printf "%s\n\n" "$HEADER_TEXT" > "$TMP_FILE"
    cat "$FILE" >> "$TMP_FILE"
    
    # Overwrite the original file
    mv "$TMP_FILE" "$FILE"
  fi
done

echo "Done"
