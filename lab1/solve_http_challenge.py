from pwn import remote

if __name__ == "__main__":
    conn = remote("ipinfo.io", 80)
    conn.send(b"GET /ip HTTP/1.1\r\n")
    conn.send(b"Host: ipinfo.io\r\n")
    conn.send(b"User-Agent: curl/7.88.1\r\n")
    conn.send(b"Accept: */*\r\n\r\n")
    for _ in range(8):
        conn.recvline()
    ip = conn.recv().decode("utf-8")
    conn.close()

    print(f"IP: {ip}")
