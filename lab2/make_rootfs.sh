#!/usr/bin/env sh
set -eu

pwd=$PWD

# unzip rootfs
cd vm/dist && rm -rf rootfs && mkdir rootfs && cd rootfs && (bunzip2 -c ../rootfs.cpio.bz2 | cpio -i) && cd "$pwd"

# copy built module to rootfs
cd cryptomod && make clean && make && make install && cd "$pwd"

# copy installation script to rootfs
chmod +x install_module.sh
cp install_module.sh vm/dist/rootfs

# zip rootfs
cd vm/dist && cd rootfs && (find . | cpio -o --format newc | bzip2 >../rootfs.cpio.bz2) && cd "$pwd"
