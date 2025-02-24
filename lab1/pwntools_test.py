from pwn import process

if __name__ == "__main__":
    r = process("read Z; echo You got $Z", shell=True)
    r.sendline(b"AAA")
    r.interactive()
