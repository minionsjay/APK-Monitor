#!/usr/bin/env python3
# 极简 SOCKS5 (no-auth, CONNECT),仅用于本地验证管路。出口=本机(WSL宿主)网络。
import socket, threading, struct, select, sys

LISTEN = ("127.0.0.1", 1080)

def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r: break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except Exception: pass

def handle(c):
    try:
        ver, n = c.recv(1), None
        if ver != b"\x05": c.close(); return
        nm = c.recv(1)[0]; c.recv(nm)
        c.sendall(b"\x05\x00")  # no auth
        hdr = c.recv(4)
        if len(hdr) < 4: c.close(); return
        ver, cmd, _, atyp = hdr[0], hdr[1], hdr[2], hdr[3]
        if atyp == 1:
            host = socket.inet_ntoa(c.recv(4))
        elif atyp == 3:
            ln = c.recv(1)[0]; host = c.recv(ln).decode()
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, c.recv(16))
        else:
            c.close(); return
        port = struct.unpack("!H", c.recv(2))[0]
        if cmd != 1:  # only CONNECT
            c.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"); c.close(); return
        try:
            up = socket.create_connection((host, port), timeout=15)
        except Exception:
            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); c.close(); return
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        pipe(c, up)
    except Exception:
        try: c.close()
        except Exception: pass

def main():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN); s.listen(128)
    print(f"SOCKS5 listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
