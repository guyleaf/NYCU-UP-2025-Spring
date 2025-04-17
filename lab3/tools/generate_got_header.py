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
        min_got_offset = float("inf")
        max_got_offset = float("-inf")
        got_offsets = []
        for s in [f"gop_{i}" for i in range(1, 1201)]:
            got_offset = elf.got[s] - main_addr
            got_offsets.append(hex(got_offset))
            min_got_offset = min(min_got_offset, got_offset)
            max_got_offset = max(max_got_offset, got_offset)
        array = ",".join(got_offsets)
        f.write(f"uintptr_t GOT_OFFSETS[] = {{{array}}};\n")

        f.write("\n")
        f.write(f"#define MIN_GOT_OFFSET {hex(min_got_offset)}\n")
        f.write(f"#define MAX_GOT_OFFSET {hex(max_got_offset)}\n")
        f.write("\n#endif\n")
