import argparse
from pathlib import Path

from pwn import ELF
from pwnlib.args import SILENT


def parse_args():
    parser = argparse.ArgumentParser(
        description="Get relative addresses of GOT table entries and Create a header file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", type=str, help="Path of the gotoku executable file")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="got_gotoku.h",
        help="Output path of the header file",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # read ELF in silent mode
    SILENT("")
    elf = ELF(args.path)
    header_name = out_path.name.upper().replace(".", "_")
    header_name = f"__{header_name}__"
    with open(out_path, "w") as f:
        f.write(f"#ifndef {header_name}\n")
        f.write(f"#define {header_name}\n\n")

        main_addr = elf.symbols["main"]
        f.write(f"#define MAIN {hex(main_addr)}\n\n")

        # print("main =", main_addr)
        # print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
        for s in [f"gop_{i+1}" for i in range(1200)]:
            if s in elf.got:
                got_addr = elf.got[s]
                f.write(f"#define {s.upper()} {hex(got_addr)}\n")

                # print("{:<12s} {:<10x} {:<10x}".format(s, got_addr, elf.symbols[s]))

        f.write("\n#endif\n")
