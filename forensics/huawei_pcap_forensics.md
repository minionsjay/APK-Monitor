# 华为云 IP 抓包取证报告（含 TLS 分析）

生成时间: 2026-07-22 11:02:19

## 1. 抓包概况

- pcap 文件: /home/ninini/Agents/APK-Research/forensics/pcaps/hw_forensics.pcap
- 文件大小: 112,311 bytes
- 抓包时长: 60 秒
- 抓包设备: Pixel 4 (192.168.1.16)
- 抓包工具: tcpdump (root)

## 2. 华为云节点流量统计

| 华为 IP | 端口 | APK | 方向 | 包数 | 字节数 |
|---------|------|-----|------|------|--------|
| 121.37.218.156 | 30146 | 714cpk28 (dh146) | 双向 | 24 | 6932 |
| 114.132.204.167 | 30139 | 718xssp20 (dh139) | 双向 | 24 | 6924 |

其他华为 IP (110.41.x, 113.45.x, 116.205.x, 121.37.39.x, 124.71.x):
- TCP SYN/SYN-ACK 建连但没有数据传输
- 可能是连接建立后立即关闭（TLS 握手未完成或超时）

## 3. TLS 握手分析

### 3.1 TLS ClientHello (客户端→服务端)

| 目标 IP | SNI (Server Name) | TLS 版本 | 含义 |
|---------|-------------------|---------|------|
| 121.37.218.156:30146 | share.note.youdao.com | TLS 1.2 (0x0303) | 有道云笔记 |
| 114.132.204.167:30139 | music.163.com | TLS 1.2 (0x0303) | 网易云音乐 |

SNI 伪装分析:
- APP 用有道云笔记/网易云音乐的域名作为 TLS SNI
- 这是为了绕过 DPI (深度包检测)
- 实际连接的是华为云 ECS 服务器，不是有道/网易

### 3.2 TLS ServerHello (服务端→客户端)

| 源 IP | TLS 版本 | Cipher Suite | 含义 |
|-------|---------|-------------|------|
| 121.37.218.156 | TLS 1.2 | 0xC013 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA |
| 114.132.204.167 | TLS 1.2 | 0xC013 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA |

### 3.3 TLS Alert

无 TLS Alert 消息，说明 TLS 握手成功完成。

## 4. 数据传输分析

每个 TCP 会话:
- 服务端→客户端: 5493 bytes (多个 TCP 段)
- 客户端→服务端: 1367-1431 bytes (多个 TCP 段)
- 会话持续: ~10 秒
- 数据是 TLS 加密的 (ApplicationData)

## 5. 协议层次

```
TCP 连接 (端口 30139/30146)
  └─ TLS 1.2 (ECDHE_RSA_WITH_AES_128_CBC_SHA)
      ├─ SNI: music.163.com / share.note.youdao.com (伪装)
      └─ TLS Application Data (加密)
          └─ MTProto (AES-256-IGE 加密)
              └─ 代理节点数据交换
```

## 6. 华为云 ECS 确认

| IP | 反向 DNS | 确认 |
|----|---------|------|
| 121.37.218.156 | ecs-121-37-218-156.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 114.132.204.167 | (无反向 DNS) | 华为云 114.132 段 |
| 110.41.11.13 | ecs-110-41-11-13.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 110.41.60.161 | ecs-110-41-60-161.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 113.45.47.238 | ecs-113-45-47-238.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 113.45.254.81 | ecs-113-45-254-81.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 121.37.39.209 | ecs-121-37-39-209.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 124.71.15.147 | ecs-124-71-15-147.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 124.71.18.253 | ecs-124-71-18-253.compute.hwclouds-dns.com | ✅ 华为云 ECS |
| 116.205.241.185 | jiniq.com | 华为云 116.205 段 |
| 114.132.241.58 | (无反向 DNS) | 华为云 114.132 段 (控制面节点) |

## 7. 结论

1. 华为云 ECS 服务器被用作代理转发节点
2. APP 用伪装的 SNI (music.163.com, share.note.youdao.com) 绕过 DPI
3. TLS 1.2 握手成功，使用 ECDHE_RSA_WITH_AES_128_CBC_SHA
4. 数据在 TLS 之上用 MTProto (AES-256-IGE) 加密
5. 11 个华为云 IP 中，2 个有完整数据传输，9 个只有 TCP 建连
