#!/bin/bash
# Legitimate nvm (Node Version Manager) configuration
# Should NOT trigger on "nvm" substring matches

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

nvm install 20
nvm use 20
node --version
