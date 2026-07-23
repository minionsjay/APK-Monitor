import ssl, socket, json, os, sys, threading, time, datetime, struct

CERT_FILE = "/tmp/sdk33_cert.pem"
KEY_FILE = "/tmp/sdk33_key.pem"
LOG_FILE = "/tmp/forwarder_mitm_log2.txt"
BIN_LOG = "/tmp/forwarder_mitm_raw.bin"
LISTEN_PORT = 30151

CONTROL_NODES = ["106.53.12.54", "193.112.206.154", "8.138.41.144", "8.138.97.66"]
CONTROL_PORT = 30151

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def write_raw(data, tag):
    """Write raw binary data with a tag header for later analysis"""
    with open(BIN_LOG, "ab") as f:
        f.write(struct.pack(">I", len(tag)))
        f.write(tag.encode())
        f.write(struct.pack(">I", len(data)))
        f.write(data)

def handle_client(client_sock, client_addr):
    log(f"连接来自 {client_addr}")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    try:
        tls_sock = ctx.wrap_socket(client_sock, server_side=True)
        log(f"TLS 握手成功")
    except Exception as e:
        log(f"TLS 握手失败: {e}")
        client_sock.close()
        return

    request_data = b""
    while True:
        try:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            if len(request_data) > 10000:
                break
        except socket.timeout:
            break
        except:
            break

    if request_data:
        log(f"客户端请求 ({len(request_data)}B)")
        write_raw(request_data, "REQUEST")

    for node_ip in CONTROL_NODES:
        try:
            log(f"转发到 {node_ip}:{CONTROL_PORT}")
            upstream = socket.create_connection((node_ip, CONTROL_PORT), timeout=10)
            upstream_ctx = ssl.create_default_context()
            upstream_ctx.check_hostname = False
            upstream_ctx.verify_mode = ssl.CERT_NONE
            upstream_tls = upstream_ctx.wrap_socket(upstream, server_hostname="sdk33.01hd1.com")
            upstream_tls.sendall(request_data)

            response_data = b""
            while True:
                try:
                    chunk = upstream_tls.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 20000:
                        break
                except:
                    break

            upstream_tls.close()
            if response_data:
                log(f"服务端响应 ({len(response_data)}B)")
                write_raw(response_data, "RESPONSE")
                tls_sock.sendall(response_data)
                log(f"已将响应返回客户端")
                break
        except Exception as e:
            log(f"转发失败: {e}")

    tls_sock.close()
    client_sock.close()

def main():
    open(LOG_FILE, "w").close()
    open(BIN_LOG, "wb").close()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    server.settimeout(1)
    log(f"MITM 代理 v2 监听 0.0.0.0:{LISTEN_PORT} (二进制日志: {BIN_LOG})")
    try:
        while True:
            try:
                client_sock, client_addr = server.accept()
                client_sock.settimeout(15)
                t = threading.Thread(target=handle_client, args=(client_sock, client_addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        server.close()

if __name__ == "__main__":
    main()
