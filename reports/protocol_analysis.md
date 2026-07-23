# Forwarder Control 协议分析

## 关键发现

### 两个协议通道

1. **Forwarder Control** (DEADBEEF + JSON)
   - 返回 nodesA（控制面节点列表）
   - 明文 JSON: {"nodesA":["106.53.12.54:30151","193.112.206.154:30151","8.138.41.144:30151"]}
   - 只包含控制面节点，不包含代理节点
   - Ghidra 确认：json.Marshal + tls.Conn.Write（无加密）

2. **MTProto** (DEADBEEF + 二进制加密)
   - 推送 app_line_ips（代理节点列表）
   - 通过 onIpListReceived native 回调传递给 Java 层
   - 加密的二进制协议
   - MITM 拦截到的是这个协议的数据

### 代理节点来源
- 代理节点通过 MTProto 协议推送
- 不是通过 forwarder control 获取
- forwarder control 只返回控制面节点
- 代理节点缓存在 sdk_forwarder_fixed.json

### 离线获取代理节点的可行性
- forwarder control 可以离线实现（明文 JSON）
- 但只返回控制面节点，不返回代理节点
- 代理节点需要 MTProto 协议（加密的二进制协议）
- MTProto 是 Telegram 的协议，使用 AES-IGE 加密
- 要完全离线获取代理节点，需要实现 MTProto 握手 + 加密
