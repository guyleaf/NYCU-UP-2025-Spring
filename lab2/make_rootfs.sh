#!/usr/bin/env sh
set -eu

pwd=$PWD

cd vm/dist
if [ ! -f "rootfs.orig.cpio.bz2" ]; then
	cp rootfs.cpio.bz2 rootfs.orig.cpio.bz2
fi

# unzip rootfs
rm -rf rootfs && mkdir rootfs && cd rootfs && (bunzip2 -c ../rootfs.orig.cpio.bz2 | cpio -i) && cd "${pwd}"

# copy built module to rootfs
cd cryptomod && make clean && make && make install && cd "${pwd}"

# copy installation script to rootfs
chmod +x install_module.sh
cp install_module.sh vm/dist/rootfs

# copy test_crypto to rootfs
# cd vm && chmod +x test_crypto && cp test_crypto dist/rootfs && cd "${pwd}"

# zip rootfs
cd vm/dist && cd rootfs && (find . | cpio -o --format newc | bzip2 >../rootfs.cpio.bz2) && cd "${pwd}"
