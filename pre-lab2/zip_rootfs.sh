#!/usr/bin/env sh

cd vm/dist && cd rootfs && (find . | cpio -o --format newc | bzip2 >../rootfs.cpio.bz2)
