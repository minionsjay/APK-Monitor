import ssl, socket, threading, struct, os, time, hashlib

CERT_FILE = "/tmp/sdk33_cert.pem"
KEY_FILE = "/tmp/sdk33_key.pem"
LISTEN_PORT = 30151
CONTROL_NODES = ["106.53.12.54", "193.112.206.154", "8.138.41.144"]
LOG_FILE = "/home/ninini/Agents/APK-Research/mitm_raw.log"

open(LOG_FILE, "w").close()

def handle(client_conn, addr):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        client_tls = ctx.wrap_socket(client_conn, server_side=True)
        
        server_conn = socket.create_connection((CONTROL_NODES[0], LISTEN_PORT), timeout=10)
        server_ctx = ssl.create_default_context()
        server_ctx.check_hostname = False
        server_ctx.verify_mode = ssl.CERT_NONE
        server_tls = server_ctx.wrap_socket(server_conn, server_hostname="bilibili.com")
        
        def forward(src, dst, name):
            buf = b''
            while True:
                try:
                    data = src.read(65536)
                    if not data:
                        break
                    buf += data
                    
                    # 记录所有数据
                    with open(LOG_FILE, "ab") as f:
                        f.write(f"[{name}] {len(data)} bytes\n".encode())
                        f.write(f"  hex: {data[:60].hex()}\n".encode())
                        # 检查是否是 JSON
                        if b'{' in data[:10]:
                            f.write(f"  ✅ JSON! {data[:100]}\n".encode())
                        # 检查是否是 DEADBEEF
                        if len(data) >= 4 and struct.unpack(">I", data[:4])[0] == 0xDEADBEEF:
                            f.write(f"  DEADBEEF\n".encode())
                        f.write(b"\n")
                    
                    dst.write(data)
                except:
                    break
        
        t1 = threading.Thread(target=forward, args=(client_tls, server_tls, "req"))
        t2 = threading.Thread(target=forward, args=(server_tls, client_tls, "resp"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        client_tls.close()
        server_tls.close()
    except Exception as e:
        print(f"Error: {e}")

# 生成自签名证书
os.system('openssl req -x509 -newkey rsa:2048 -keyout /tmp/sdk33_key.pem -out /tmp/sdk33_cert.pem -days 365 -nodes -subj "/CN=bilibili.com" 2>/dev/null')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", LISTEN_PORT))
server.listen(5)
print(f"MITM raw proxy on port {LISTEN_PORT}")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle, args=(conn, addr)).start()
