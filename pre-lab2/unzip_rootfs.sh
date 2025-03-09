#!/usr/bin/env sh

cd vm/dist && rm -rf rootfs && mkdir rootfs && cd rootfs && (bunzip2 -cv ../rootfs.cpio.bz2 | cpio -iv)
