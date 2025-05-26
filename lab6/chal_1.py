from pwn import asm, remote


def solve(r: remote, data: bytes):
    # r.newline = b"\r\n"
    msg = r.recvuntil(b"Enter your code> ").decode()
    print(msg)

    r.sendline(data)
    msg = r.recvuntil(b"}").decode()
    print(msg)

    r.close()


if __name__ == "__main__":
    with open("./chal_1.asm") as f:
        content = f.read()

    data = asm(content, arch="amd64", os="linux")
    print("Length of the shellcode: ", len(data))

    ## for remote access
    r = remote("up.zoolab.org", 12341)
    solve(r, data)
