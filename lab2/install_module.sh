#!/bin/env sh
set -eu

# install all modules in /modules
find /modules -name "*.ko" -type f -exec "insmod" "{}" \;

# download missing files
echo "a77e4e644ecf204f062106bab6938c38  test_crypto" >/md5sum
echo "6bcfed610a256de36acdf4eb106f58b7  fun.jpg.enc" >>/md5sum

if [ ! -f "/test_crypto" ]; then
	echo "Downloading test_crypto..."
	wget https://up.zoolab.org/unixprog/lab02/test_crypto
fi

if [ ! -f "/fun.jpg.enc" ]; then
	echo "Downloading fun.jpg.enc..."
	wget https://up.zoolab.org/unixprog/lab02/fun.jpg.enc
fi

md5sum -c /md5sum
chmod +x /test_crypto

# tests
# ignore erros
echo 3 >/proc/sys/kernel/printk

i=0
while [ "${i}" -le 6 ]; do
	/test_crypto test "${i}"
	i=$((i + 1))
done
/test_crypto dec -i fun.jpg.enc -o fun.jpg -k "e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f" -s 128 -m ADV

echo 8 >/proc/sys/kernel/printk
