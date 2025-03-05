#!/bin/bash
set -e

# tools
echo "source /usr/share/bash-completion/completions/git" >> ~/.bashrc
git config --local core.editor vim
git config --local pull.rebase false

echo export PATH="$PATH:$(go env GOPATH)/bin" >> ~/.bashrc
