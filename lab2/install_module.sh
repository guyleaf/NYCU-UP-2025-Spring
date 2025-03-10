#!/bin/env sh
set -eu

# install all modules in /modules
find /modules -name "*.ko" -type f -exec "insmod" "{}" \;

# run all executable files in /modules
# find /modules ! -name "*.ko" -type f -exec "{}" \;
