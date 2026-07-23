#!/usr/bin/env python3
"""
MITM 代理：拦截 forwarder control 的 TLS 流量
forwarder control 用标准 crypto/tls（不是 uTLS）
所以 MITM 应该能成功

原理：
1. 在 PC 上创建 TLS 代理
2. adb reverse 将手机流量重定向到 PC
3. APP 连接控制面节点 → MITM 代理 → 控制面节点
4. MITM 代理生成自签名证书，APP 用 InsecureSkipVerify
5. 记录所有 TLS 解密后的数据
"""

import ssl
import socket
import threading
import json
import time
import os
import subprocess
from datetime import datetime

LISTEN_PORT = 30122  # 718c257 的端口
TARGET_IP = "159.75.108.175"  # 控制面节点
TARGET_PORT = 30122
LOG_FILE = "/home/ninini/Agents/APK-Research/forensics/fwd_ctrl_mitm.log"
CERT_DIR = "/home/ninini/Agents/APK-Research/forensics/certs"

os.makedirs(CERT_DIR, exist_ok=True)

def generate_cert():
    """生成自签名证书"""
    cert_file = f"{CERT_DIR}/mitm.crt"
    key_file = f"{CERT_DIR}/mitm.key"
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key_file, '-out', cert_file,
        '-days', '365', '-nodes',
        '-subj', f'/CN=bilibili.com',
        '-addext', f'subjectAltName=DNS:bilibili.com,DNS:music.163.com,DNS:share.note.youdao.com'
    ], capture_output=True, timeout=10)
    
    return cert_file, key_file

def log(msg, data=None):
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, 'a') as f:
        f.write(line + "\n")
        if data:
            if isinstance(data, bytes):
                f.write(f"  hex: {data.hex()[:200]}\n")
                try:
                    f.write(f"  text: {data.decode('utf-8', errors='replace')[:200]}\n")
                except:
                    pass
            elif isinstance(data, str):
                f.write(f"  data: {data[:200]}\n")

def handle_client(client_conn, cert_file, key_file):
    """处理客户端连接"""
    try:
        # 1. 和客户端做 TLS 握手（用我们的自签名证书）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        
        try:
            tls_conn = ctx.wrap_socket(client_conn, server_side=True)
        except ssl.SSLError as e:
            log(f"客户端 TLS 握手失败: {e}")
            return
        
        log(f"✅ 客户端 TLS 握手成功: {tls_conn.version()} {tls_conn.cipher()}")
        
        # 2. 连接真实服务端
        server_conn = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=10)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        server_ctx.check_hostname = False
        server_ctx.verify_mode = ssl.CERT_NONE
        
        try:
            server_tls = server_ctx.wrap_socket(server_conn, server_hostname="bilibili.com")
        except ssl.SSLError as e:
            log(f"服务端 TLS 握手失败: {e}")
            return
        
        log(f"✅ 服务端 TLS 握手成功: {server_tls.version()} {server_tls.cipher()}")
        
        # 3. 双向转发并记录
        def forward(src, dst, name):
            while True:
                try:
                    data = src.read(4096) if hasattr(src, 'read') else src.recv(4096)
                    if not data:
                        log(f"{name}: 连接关闭")
                        break
                    log(f"{name}: 收到 {len(data)} bytes", data)
                    if hasattr(dst, 'write'):
                        dst.write(data)
                    else:
                        dst.send(data)
                except Exception as e:
                    log(f"{name}: 错误 {e}")
                    break
        
        t1 = threading.Thread(target=forward, args=(tls_conn, server_tls, "客户端→服务端"))
        t2 = threading.Thread(target=forward, args=(server_tls, tls_conn, "服务端→客户端"))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=5)
        
    except Exception as e:
        log(f"处理错误: {e}")
    finally:
        try:
            client_conn.close()
        except:
            pass

def main():
    cert_file, key_file = generate_cert()
    log(f"MITM 代理启动: 监听端口 {LISTEN_PORT}")
    log(f"目标: {TARGET_IP}:{TARGET_PORT}")
    
    # 设置 adb reverse
    subprocess.run(['adb', '-s', '192.168.1.16:43351', 'reverse',
                    f'tcp:{LISTEN_PORT}', f'tcp:{LISTEN_PORT}'], capture_output=True, timeout=5)
    log(f"adb reverse: {LISTEN_PORT} → PC")
    
    # 设置 iptables
    subprocess.run(['adb', '-s', '192.168.1.16:43351', 'shell',
                    "su 0 -c 'iptables -t nat -A OUTPUT -p tcp --dport %d -j REDIRECT --to-port %d'" % (LISTEN_PORT, LISTEN_PORT)],
                   capture_output=True, timeout=5)
    log("iptables 重定向设置")
    
    # 启动监听
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(5)
    
    log(f"等待连接...")
    
    while True:
        try:
            client_conn, addr = server.accept()
            log(f"新连接: {addr}")
            t = threading.Thread(target=handle_client, args=(client_conn, cert_file, key_file))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"监听错误: {e}")
    
    # 清理
    subprocess.run(['adb', '-s', '192.168.1.16:43351', 'shell',
                    "su 0 -c 'iptables -t nat -D OUTPUT -p tcp --dport %d -j REDIRECT --to-port %d'" % (LISTEN_PORT, LISTEN_PORT)],
                   capture_output=True, timeout=5)

if __name__ == '__main__':
    main()
