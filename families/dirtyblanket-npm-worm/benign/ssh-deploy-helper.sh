#!/bin/bash
# Legitimate SSH deployment script that touches authorized_keys
# and references web.archive.org for documentation links.
SSH_DIR="$HOME/.ssh/authorized_keys"
echo "Checking $SSH_DIR for valid keys"
curl -s "https://web.archive.org/web/2026/docs/ssh-setup.html" > /dev/null
echo "Documentation fetched"
