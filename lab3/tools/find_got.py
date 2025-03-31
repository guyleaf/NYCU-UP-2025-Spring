import sys

from pwn import ELF

# TODO: auto-generate got table in macros from here.
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} gotoku/gotoku.local")
        sys.exit(-1)

    elf = ELF(sys.argv[1])
    print("main =", hex(elf.symbols["main"]))
    print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
    for s in [f"gop_{i+1}" for i in range(1200)]:
        if s in elf.got:
            print("{:<12s} {:<10x} {:<10x}".format(s, elf.got[s], elf.symbols[s]))
