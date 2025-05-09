#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import base64
import hashlib
import sys
import time

from pwn import process, remote


def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    start_time = time.time()
    print("solving pow ...")
    solved = b""
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h.startswith("000000"):
            solved = str(i).encode()
            print("solved =", solved)
            break
    end_time = time.time()
    print(f"done in {end_time - start_time}s.")
    r.sendlineafter(b"string S: ", base64.b64encode(solved))
    z = r.recvline()
    print(z.decode().strip())
    z = r.recvline()
    print(z.decode().strip())


if __name__ == "__main__":
    r = None
    if len(sys.argv) == 2:
        r = remote("localhost", int(sys.argv[1]))
    elif len(sys.argv) == 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = process("./pow.py")
    solve_pow(r)
    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
