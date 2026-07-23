#!/usr/bin/env python3
"""二进制 MITM 代理 - 记录原始字节数据"""
import ssl, socket, threading, struct, os, time

CERT_FILE = "/tmp/sdk33_cert.pem"
KEY_FILE = "/tmp/sdk33_key.pem"
LISTEN_PORT = 30151
CONTROL_NODES = ["106.53.12.54", "193.112.206.154", "8.138.41.144"]
REMOTE_PORT = 30151

# 二进制日志
LOG_FILE = "/home/ninini/Agents/APK-Research/mitm_binary.log"

def handle(client_conn, addr):
    try:
        # TLS 握手（客户端侧）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        client_tls = ctx.wrap_socket(client_conn, server_side=True)
        
        # 连接服务端
        for node in CONTROL_NODES:
            try:
                server_conn = socket.create_connection((node, REMOTE_PORT), timeout=10)
                server_tls = ssl.create_default_context()
                server_tls.check_hostname = False
                server_tls.verify_mode = ssl.CERT_NONE
                server_tls = server_tls.wrap_socket(server_conn, server_hostname="sdk33.01hd1.com")
                break
            except:
                continue
        else:
            client_tls.close()
            return
        
        # 双向转发 + 记录
        def forward(src, dst, name):
            buf = b''
            while True:
                try:
                    data = src.read(65536)
                    if not data:
                        break
                    buf += data
                    # 检查是否是完整的 DEADBEEF 包
                    while len(buf) >= 8:
                        magic = struct.unpack(">I", buf[:4])[0]
                        if magic == 0xDEADBEEF:
                            sublen = struct.unpack(">H", buf[6:8])[0]
                            total = 8 + sublen
                            if len(buf) >= total:
                                # 完整的 DEADBEEF 包
                                packet = buf[:total]
                                buf = buf[total:]
                                # 记录到二进制日志
                                with open(LOG_FILE, "ab") as f:
                                    f.write(b"=== " + name.encode() + b" ===\n")
                                    f.write(b"len=" + str(len(packet)).encode() + b"\n")
                                    f.write(b"data=")
                                    f.write(packet)
                                    f.write(b"\n")
                                    f.write(b"hex=" + packet.hex().encode() + b"\n")
                                    # 也记录 ASCII 部分
                                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet)
                                    f.write(b"ascii=" + ascii_part.encode() + b"\n\n")
                                # 也打印到 stdout
                                print(f"[{name}] {len(packet)} bytes: {packet[:50].hex()}")
                                print(f"  ascii: {''.join(chr(b) if 32<=b<127 else '.' for b in packet[:80])}")
                                # 尝试解析子包为 JSON
                                subdata = packet[8:8+sublen]
                                try:
                                    import json
                                    j = json.loads(subdata)
                                    print(f"  JSON: {json.dumps(j, indent=2)}")
                                except:
                                    print(f"  子包不是 JSON ({sublen} bytes)")
                            else:
                                break  # 等更多数据
                        else:
                            # 非 DEADBEEF，直接记录
                            with open(LOG_FILE, "ab") as f:
                                f.write(b"=== " + name.encode() + b" (raw) ===\n")
                                f.write(b"data=" + buf + b"\n\n")
                            print(f"[{name} raw] {len(buf)} bytes: {buf[:50]}")
                            buf = b''
                            break
                    dst.write(data)
                except:
                    break
        
        t1 = threading.Thread(target=forward, args=(client_tls, server_tls, "请求"))
        t2 = threading.Thread(target=forward, args=(server_tls, client_tls, "响应"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        client_tls.close()
        server_tls.close()
    except Exception as e:
        print(f"错误: {e}")

def main():
    # 生成自签名证书
    os.system('openssl req -x509 -newkey rsa:2048 -keyout /tmp/sdk33_key.pem -out /tmp/sdk33_cert.pem -days 365 -nodes -subj "/CN=sdk33.01hd1.com" 2>/dev/null')
    
    # 清空日志
    open(LOG_FILE, "w").close()
    
    # 设置 iptables 重发
    os.system('adb -s 192.168.1.16:37405 shell "su -c \'iptables -t nat -A OUTPUT -p tcp --dport 30151 -j REDIRECT --to-port 30151\'"')
    print(f"MITM 代理监听 0.0.0.0:{LISTEN_PORT}")
    print(f"日志: {LOG_FILE}")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)
    
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle, args=(conn, addr)).start()
    except KeyboardInterrupt:
        pass
    finally:
        os.system('adb -s 192.168.1.16:37405 shell "su -c \'iptables -t nat -D OUTPUT -p tcp --dport 30151 -j REDIRECT --to-port 30151\'"')
        print("清理 iptables")

if __name__ == "__main__":
    main()
