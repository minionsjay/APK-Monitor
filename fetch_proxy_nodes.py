#!/usr/bin/env python3
"""
exdyfb forwarder control 协议模拟器
连接控制面节点获取代理节点列表（不运行 APP）

用法:
  python3 fetch_proxy_nodes.py
  python3 fetch_proxy_nodes.py --psk pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7
  python3 fetch_proxy_nodes.py --node 106.53.12.54 30151
"""

import argparse, base64, hashlib, hmac, json, os, ssl, struct, subprocess, sys, time, socket, urllib.request

# 已知常量（从 RSA 解密 bootstrap 获得）
AES_KEY = b"qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb"
PSK_CANDIDATE = "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7"

# 控制面节点（从 .dat 解密获得）
CONTROL_NODES = ["106.53.12.54:30151", "193.112.206.154:30151", "8.138.41.144:30151"]

def hmac_sha256_hex(key, msg):
    """HMAC-SHA256, 返回 hex 字符串"""
    if isinstance(key, str): key = key.encode()
    if isinstance(msg, str): msg = msg.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def try_tls_json_request(node_ip, node_port, psk, nonce=None):
    """
    尝试 TLS 连接到控制面节点，发送 JSON 请求，接收响应。
    尝试多种协议变体。
    """
    if nonce is None:
        nonce = os.urandom(16).hex()
    
    mac = hmac_sha256_hex(psk, nonce)
    
    # 尝试多种请求格式
    request_variants = [
        # 变体1: 纯 JSON {nonce, mac}
        json.dumps({"nonce": nonce, "mac": mac}).encode() + b"\n",
        # 变体2: 纯 JSON 不带换行
        json.dumps({"nonce": nonce, "mac": mac}).encode(),
        # 变体3: 带版本号
        json.dumps({"nonce": nonce, "mac": mac, "version": "4.0.1", "app_name": "dh151"}).encode() + b"\n",
        # 变体4: HTTP POST
        b"POST / HTTP/1.1\r\nHost: sdk33.01hd1.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(json.dumps({"nonce": nonce, "mac": mac}))).encode() + b"\r\n\r\n" + json.dumps({"nonce": nonce, "mac": mac}).encode(),
    ]
    
    # TLS 上下文（不验证证书，对应 forwarderTLSInsecure）
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for i, req_data in enumerate(request_variants):
        try:
            print(f"  变体{i+1}: {req_data[:80]}...")
            
            # TLS 连接
            sock = socket.create_connection((node_ip, int(node_port)), timeout=10)
            # SNI 用 sdk33.01hd1.com（真实证书 CN）
            tls_sock = ctx.wrap_socket(sock, server_hostname="sdk33.01hd1.com")
            
            # 发送请求
            tls_sock.sendall(req_data)
            
            # 接收响应
            response = b""
            while True:
                try:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 10000:
                        break
                except socket.timeout:
                    break
            
            tls_sock.close()
            
            if response:
                print(f"  响应 ({len(response)}B): {response[:200]}")
                return response
            else:
                print(f"  无响应")
                
        except Exception as e:
            print(f"  失败: {e}")
    
    return None

def try_raw_tcp_request(node_ip, node_port, psk):
    """尝试原始 TCP（不加密）连接"""
    nonce = os.urandom(16).hex()
    mac = hmac_sha256_hex(psk, nonce)
    
    request = json.dumps({"nonce": nonce, "mac": mac}).encode() + b"\n"
    
    try:
        sock = socket.create_connection((node_ip, int(node_port)), timeout=10)
        sock.sendall(request)
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        
        if response:
            print(f"  TCP 响应 ({len(response)}B): {response[:200]}")
            return response
        else:
            print(f"  TCP 无响应")
    except Exception as e:
        print(f"  TCP 失败: {e}")
    
    return None

def try_various_psk_combinations(node_ip, node_port):
    """尝试多种 PSK 组合"""
    psk_variants = [
        ("PSK 原始字符串", PSK_CANDIDATE),
        ("AES key 字符串", AES_KEY.decode()),
        ("PSK base64 解码", base64.b64decode(PSK_CANDIDATE + "=" * (-len(PSK_CANDIDATE) % 4)).hex()),
        ("AES key + PSK 拼接", AES_KEY.decode() + PSK_CANDIDATE),
        ("空 PSK", ""),
    ]
    
    for name, psk in psk_variants:
        print(f"\n  --- 尝试 {name} ---")
        result = try_tls_json_request(node_ip, node_port, psk)
        if result and b"app_line" in result:
            print(f"  ✅ 成功！PSK = {name}")
            return result, psk
    
    return None, None

def main():
    ap = argparse.ArgumentParser(description="exdyfb forwarder control 协议模拟器")
    ap.add_argument("--node", help="控制面节点 IP:端口，默认用 .dat 解密的")
    ap.add_argument("--psk", default=PSK_CANDIDATE, help="PSK 值")
    ap.add_argument("--port", default="30151", help="端口")
    args = ap.parse_args()
    
    # 解析控制面节点
    if args.node:
        nodes = [f"{args.node}:{args.port}" if ":" not in args.node else args.node]
    else:
        nodes = CONTROL_NODES
    
    print(f"=== exdyfb 代理节点获取器 ===")
    print(f"控制面节点: {nodes}")
    print(f"PSK: {args.psk}")
    print()
    
    for node in nodes:
        ip, port = node.split(":")
        print(f"\n=== 连接 {ip}:{port} ===")
        
        # 先试 TLS + JSON
        print("\n[TLS + JSON 尝试]")
        result = try_tls_json_request(ip, port, args.psk)
        
        if not result or b"app_line" not in (result or b""):
            # 尝试不同 PSK 组合
            print("\n[尝试不同 PSK 组合]")
            result, psk = try_various_psk_combinations(ip, port)
            if result:
                args.psk = psk
        
        if not result or b"app_line" not in (result or b""):
            # 试原始 TCP
            print("\n[原始 TCP 尝试]")
            result = try_raw_tcp_request(ip, port, args.psk)
        
        if result and b"app_line" in result:
            # 解析响应
            try:
                resp_text = result.decode("utf-8", errors="replace")
                # 找 JSON 部分
                json_start = resp_text.find("{")
                if json_start >= 0:
                    resp_json = json.loads(resp_text[json_start:])
                    print(f"\n✅ 成功获取代理节点！")
                    print(f"节点列表: {resp_json.get('app_line_ips', [])}")
                    print(f"端口: {resp_json.get('app_line_port', 30151)}")
                    
                    # 保存
                    with open("/home/ninini/Agents/APK-Research/proxy_nodes_result.json", "w") as f:
                        json.dump(resp_json, f, indent=2, ensure_ascii=False)
                    print(f"\n保存到 /home/ninini/Agents/APK-Research/proxy_nodes_result.json")
                    return
            except:
                pass
        
        print(f"\n❌ {ip}:{port} 未成功")
    
    print("\n❌ 所有控制面节点都未成功")
    print("\n可能原因：")
    print("1. PSK 值不正确（需要进一步逆向")
    print("2. 协议格式不对（可能不是简单的 JSON over TLS")
    print("3. 需要先做 TLS 握手协商（不是直接发 JSON")
    print("4. 控制面节点需要特定 client hello（uTLS 指纹")

if __name__ == "__main__":
    main()
