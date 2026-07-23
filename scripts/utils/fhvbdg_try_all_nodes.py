import ssl, socket, struct, json, hmac, hashlib, os, sys

# fhvbdg 节点
NODES = ["43.248.2.74", "110.41.82.109", "129.204.151.112", "43.138.250.177", "8.134.177.243"]
PORT = 30052
PSK = ""
SNI = "sdk.3jw0c.com"

def hmac_sha256_hex(key, msg):
    h = hmac.new(key.encode(), msg.encode(), hashlib.sha256)
    return h.hexdigest()

def try_node(node):
    print(f"\n--- {node}:{PORT} ---")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((node, PORT), timeout=10)
        tls = ctx.wrap_socket(sock, server_hostname=SNI)
        print(f"TLS OK")
    except Exception as e:
        print(f"TLS fail: {e}")
        return

    nonce = os.urandom(16).hex()
    mac = hmac_sha256_hex(PSK, "hello" + nonce)
    req = {"nonce": nonce, "mac": mac}
    req_json = json.dumps(req).encode()
    pkt = struct.pack(">I", 0xDEADBEEF) + struct.pack(">H", 0) + struct.pack(">H", len(req_json)) + req_json
    print(f"Sending {len(pkt)}B")
    try:
        tls.sendall(pkt)
        tls.settimeout(10)
        header = tls.recv(8)
        if header:
            magic = struct.unpack(">I", header[:4])[0]
            print(f"Resp magic: {hex(magic)}")
            if magic == 0xDEADBEEF:
                resp_len = struct.unpack(">H", header[6:8])[0]
                print(f"respLen={resp_len}")
                body = b""
                while len(body) < resp_len:
                    chunk = tls.recv(resp_len - len(body))
                    if not chunk:
                        break
                    body += chunk
                print(f"Body: {body[:500]}")
                try:
                    resp = json.loads(body)
                    if "app_line_ips" in resp:
                        print(f"PROXY NODES: {resp['app_line_ips']}")
                except:
                    pass
        else:
            print("No response")
    except socket.timeout:
        print("Timeout")
    except Exception as e:
        print(f"Error: {e}")
    tls.close()

for node in NODES:
    try_node(node)
