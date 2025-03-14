#!/bin/env sh
set -eu

# install all modules in /modules
find /modules -name "*.ko" -type f -exec "insmod" "{}" \;

i=0
while [ "${i}" -le 6 ]; do
	./test_crypto test "${i}"
	i=$((i + 1))
done
