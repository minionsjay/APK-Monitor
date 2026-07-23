import ssl, socket, struct, json, hmac, hashlib, os

# fhvbdg 配置
CONTROL_NODES = ["129.204.151.112", "43.138.250.177", "8.134.177.243"]
PORT = 30052
PSK = ""  # 空 PSK
AES_KEY = b"gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz"

def hmac_sha256_hex(key, msg):
    h = hmac.new(key.encode() if isinstance(key, str) else key,
                 msg.encode() if isinstance(msg, str) else msg, hashlib.sha256)
    return h.hexdigest()

def try_connect(node):
    print(f"\n--- {node}:{PORT} ---")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((node, PORT), timeout=10)
    tls = ctx.wrap_socket(sock, server_hostname="sdk.3jw0c.com")
    print(f"TLS OK")

    nonce = os.urandom(16).hex()
    mac = hmac_sha256_hex(PSK, "hello" + nonce)

    req = {"nonce": nonce, "mac": mac}
    req_json = json.dumps(req).encode()
    print(f"JSON ({len(req_json)}): {req_json[:100]}")

    pkt = struct.pack(">I", 0xDEADBEEF) + struct.pack(">H", 0) + struct.pack(">H", len(req_json)) + req_json
    print(f"Sending DEADBEEF ({len(pkt)} bytes)")
    tls.sendall(pkt)

    tls.settimeout(10)
    try:
        header = tls.recv(8)
        if header:
            print(f"Response header ({len(header)}): {header.hex()}")
            if len(header) >= 8 and struct.unpack(">I", header[:4])[0] == 0xDEADBEEF:
                resp_len = struct.unpack(">H", header[6:8])[0]
                print(f"DEADBEEF! respLen={resp_len}")
                body = b""
                while len(body) < resp_len:
                    chunk = tls.recv(resp_len - len(body))
                    if not chunk:
                        break
                    body += chunk
                print(f"Body ({len(body)}): {body[:500]}")
        else:
            print("No response")
    except socket.timeout:
        print("超时")

    tls.close()

for node in CONTROL_NODES:
    try:
        try_connect(node)
    except Exception as e:
        print(f"失败: {e}")
