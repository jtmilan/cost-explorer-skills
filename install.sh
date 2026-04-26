#!/bin/bash
# Install script for cost-explorer skills
#
# Symlinks all skills into ~/.claude/skills/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$HOME/.claude/skills"

# Create skills directory if needed
mkdir -p "$SKILLS_DIR"

# Symlink all 3 skills
for skill in cost-explorer-query cost-anomaly-investigate finops-recommend; do
    src="$SCRIPT_DIR/skills/$skill"
    dest="$SKILLS_DIR/$skill"

    if [ -L "$dest" ]; then
        rm "$dest"
    fi

    if [ -d "$src" ]; then
        ln -s "$src" "$dest"
        echo "Linked: $skill -> $dest"
    else
        echo "Warning: $src not found, skipping"
    fi
done

echo "Installation complete"
exit 0
