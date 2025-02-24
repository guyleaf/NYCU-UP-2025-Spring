#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import base64
import itertools
import random
import sys
import zlib

from pwn import process, remote
from solpow import solve_pow


def send_msg(r: remote, m: str):
    zm = zlib.compress(m.encode())
    mlen = len(zm)

    msg = base64.b64encode(mlen.to_bytes(4, "little") + zm)
    r.sendline(msg)


def recv_msg(r: remote):
    message = r.recvline().decode()
    message = message.removeprefix(">>> ").removesuffix(" <<<")
    message = base64.b64decode(message.encode())

    m = zlib.decompress(message[4:])
    return m


def filter_pool(pool: list[str], guess: str, A: int, B: int):
    def _filter(answer: str):
        A_check = 0
        B_check = 0
        for x, y in zip(answer, guess):
            if x == y:
                A_check += 1
            elif x in guess:
                B_check += 1
        return A_check == A and B_check == B

    return list(filter(_filter, pool))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        ## for remote access
        r = remote("up.zoolab.org", 10155)
        solve_pow(r)
    else:
        ## for local testing
        r = process("./guess.dist.py", shell=False)

    message = recv_msg(r)
    print(message.decode())

    answer_pool = list(itertools.permutations(range(10), 4))
    random.shuffle(answer_pool)
    answer_pool = ["".join(map(str, number)) for number in answer_pool]

    while True:
        prefix = recv_msg(r)

        guess = random.choice(answer_pool)
        print(guess)
        send_msg(r, guess)

        result = recv_msg(r)
        A, B = int.from_bytes(result[:4]), int.from_bytes(result[5:9])
        print(f"{A}A{B}B")

        message = recv_msg(r)
        print(message.decode())

        if A == 4:
            break

        answer_pool = filter_pool(answer_pool, guess, A, B)

    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
