#!/usr/bin/env python3
"""
exdyfb forwarder control MITM 代理
在设备上用 iptables 重定向 30151 端口流量到本代理，
代理做 TLS 终止（自签名证书 CN=sdk33.01hd1.com），
记录明文请求和响应。

用法（在设备上运行）：
  python3 mitm_forwarder.py

或者从主机推送：
  adb push mitm_forwarder.py /data/local/tmp/
  adb shell "su -c 'python3 /data/local/tmp/mitm_forwarder.py'"
"""

import ssl, socket, json, os, sys, threading, time, datetime

CERT_FILE = "/tmp/sdk33_cert.pem"
KEY_FILE = "/tmp/sdk33_key.pem"
LOG_FILE = "/tmp/forwarder_mitm_log.txt"
LISTEN_PORT = 30151

# 控制面节点（真实服务器）
CONTROL_NODES = ["106.53.12.54", "193.112.206.154", "8.138.41.144", "8.138.97.66"]
CONTROL_PORT = 30151

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def handle_client(client_sock, client_addr):
    """处理客户端连接：TLS 终止 → 记录明文 → 转发到真实服务器"""
    log(f"连接来自 {client_addr}")

    # TLS 终止（用自签名证书）
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    try:
        tls_sock = ctx.wrap_socket(client_sock, server_side=True)
        log(f"TLS 握手成功 (客户端: {tls_sock.getpeername()})")
    except Exception as e:
        log(f"TLS 握手失败: {e}")
        client_sock.close()
        return

    # 读取客户端请求
    request_data = b""
    while True:
        try:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            # 如果是 HTTP，读到 \r\n\r\n 就够了
            if b"\r\n\r\n" in request_data or len(request_data) > 10000:
                break
        except socket.timeout:
            break
        except Exception as e:
            log(f"读取请求失败: {e}")
            break

    if request_data:
        log(f"客户端请求 ({len(request_data)}B):")
        log(f"  原始: {request_data[:500]}")
        # 尝试解析 JSON
        try:
            text = request_data.decode("utf-8", errors="replace")
            json_start = text.find("{")
            if json_start >= 0:
                j = json.loads(text[json_start:])
                log(f"  JSON: {json.dumps(j, indent=2, ensure_ascii=False)}")
        except:
            pass

    # 转发到真实控制面节点
    for node_ip in CONTROL_NODES:
        try:
            log(f"转发到 {node_ip}:{CONTROL_PORT}")
            upstream = socket.create_connection((node_ip, CONTROL_PORT), timeout=10)
            upstream_ctx = ssl.create_default_context()
            upstream_ctx.check_hostname = False
            upstream_ctx.verify_mode = ssl.CERT_NONE
            upstream_tls = upstream_ctx.wrap_socket(upstream, server_hostname="sdk33.01hd1.com")

            # 发送原始请求
            upstream_tls.sendall(request_data)

            # 读取响应
            response_data = b""
            while True:
                try:
                    chunk = upstream_tls.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 20000:
                        break
                except socket.timeout:
                    break
                except:
                    break

            upstream_tls.close()

            if response_data:
                log(f"服务端响应 ({len(response_data)}B):")
                log(f"  原始: {response_data[:500]}")
                # 尝试解析 JSON
                try:
                    text = response_data.decode("utf-8", errors="replace")
                    json_start = text.find("{")
                    if json_start >= 0:
                        j = json.loads(text[json_start:])
                        log(f"  JSON: {json.dumps(j, indent=2, ensure_ascii=False)}")
                except:
                    pass

                # 把响应返回给客户端
                tls_sock.sendall(response_data)
                log(f"已将响应返回客户端")
                break
            else:
                log(f"  服务端无响应")

        except Exception as e:
            log(f"转发到 {node_ip} 失败: {e}")

    tls_sock.close()
    client_sock.close()

def main():
    # 清空日志
    open(LOG_FILE, "w").close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(10)
    server.settimeout(1)

    log(f"MITM 代理监听 0.0.0.0:{LISTEN_PORT}")
    log(f"证书: {CERT_FILE}")
    log(f"等待连接...")

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
        log("停止")
        server.close()

if __name__ == "__main__":
    main()
