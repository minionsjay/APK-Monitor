import ssl, socket, threading, struct, os, time

CERT_FILE = "/tmp/sdk33_cert.pem"
KEY_FILE = "/tmp/sdk33_key.pem"
LISTEN_PORT = 30151
CONTROL_NODES = ["106.53.12.54", "193.112.206.154", "8.138.41.144"]
BIN_FILE = "/home/ninini/Agents/APK-Research/mitm_full.bin"

# 清空文件
open(BIN_FILE, "w").close()

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
        
        conn_id = id(client_conn)
        
        def forward(src, dst, name):
            while True:
                try:
                    data = src.read(65536)
                    if not data:
                        break
                    # 记录到二进制文件
                    with open(BIN_FILE, "ab") as f:
                        f.write(struct.pack(">I", conn_id))  # conn ID
                        f.write(struct.pack(">I", len(data)))  # length
                        f.write(struct.pack(">I", 1 if name == "req" else 2))  # type
                        f.write(data)
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
        pass

os.system('openssl req -x509 -newkey rsa:2048 -keyout /tmp/sdk33_key.pem -out /tmp/sdk33_cert.pem -days 365 -nodes -subj "/CN=bilibili.com" 2>/dev/null')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", LISTEN_PORT))
server.listen(5)
print(f"MITM full proxy on port {LISTEN_PORT}")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle, args=(conn, addr)).start()
