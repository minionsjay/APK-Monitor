# gateway_proxy — 手机全流量透明代理(方案B)

把 root 手机的**全部流量(含 tgnet 等 native socket)**在内核路由层强制导入国内 SOCKS5,
用于绕过反诈样本后端的"同一IP注册上限"风控。native socket 也被抓,靠内核 `ip rule`
(优先级9000,压过 Android fwmark 分流),**不是 App 层 VPN**(那个会被 native socket 绕过)。

## 组件
- `tun2socks-linux-arm64` — 静态ARM64,tun→SOCKS5 转发核心
- `curl` — 静态ARM64,手机上验证出口IP(Android无curl/DNS,用 --resolve 绕DNS)
- `proxy_up.sh <IP> <PORT> [user] [pass]` — 挂代理(建tun+起tun2socks+ip rule劫持)
- `proxy_down.sh` — 拆除,恢复直连
- `proxy_rotate.sh` — 秒拨换IP:重启tun2socks逼其对固定端点新建上游连接→新出口IP
- `proxy_verify.sh` — 打印当前出口公网IP+归属地
- `deploy.sh <IP> <PORT> [user] [pass]` — 宿主机一键:推文件+挂+对照挂前挂后IP
- `socks5_test.py` — 本地测试用SOCKS5(纯TCP,仅验证管路;真用要换国内秒拨)

## 已验证(2026-07-30, Pixel4/Android, Magisk root)
- 黑洞测试:掐掉SOCKS后 curl RC=52(断网)→ **全部TCP被捕获,零泄漏**
- `ip route get <目标> → dev tun0` 确认劫持生效
- LAN(192.168.1.0/24)被排除 → adb-over-WiFi 存活,不自锁
- tun2socks日志可见App自身流量(Facebook:443/DNS)被捕获 → native socket 确被抓

## 用法
```bash
# 一键(宿主机):
./deploy.sh <国内SOCKS_IP> <PORT> [user] [pass]
# 或手动:
adb push tun2socks-linux-arm64 curl proxy_*.sh /data/local/tmp/ ; adb shell chmod 755 ...
adb shell su -c 'sh /data/local/tmp/proxy_up.sh <IP> <PORT> [u] [p]'
adb shell su -c 'sh /data/local/tmp/proxy_verify.sh'   # 看出口IP
adb shell su -c 'sh /data/local/tmp/proxy_rotate.sh'   # 换IP
adb shell su -c 'sh /data/local/tmp/proxy_down.sh'     # 拆除
# 看门狗保险(防自锁死adb): WATCHDOG=300 sh proxy_up.sh ... → 300s后自动拆除
```

## 更新 2026-07-30:接入 58ip.top API,端到端全打通 ✅

实测结论:**58ip.top API 生成的代理可用**,给的是真·轮换国内出口 IP。
- 它们是 **HTTP 代理**(不是SOCKS5),tun2socks 用 `PROXY_URL=http://ip:port`。
- 混有境外出口(如日本),管理器自动过滤只留国内。
- **DNS(UDP53)已做直连**(iptables mark 0x35 → table 139 → 物理网卡),
  因为 HTTP 代理只转 TCP。`ping www.baidu.com` 实测能解析。
- **不能加 tun2socks `--interface`**(Android fwmark 下 SO_BINDTODEVICE 出站包被丢)。
- 实测:手机经隧道出口 = 代理国内IP(如123.138.24.112西安联通),
  native socket(APK的C2 :30139)被捕获,DNS正常。

### 代理轮换管理器 proxy_manager.py(宿主机)
```bash
python3 proxy_manager.py refill 20     # 调API拉批+并发探活+过滤国内,填池子(pool.txt)
python3 proxy_manager.py rotate        # 挑一个可用代理挂手机+验证出口(自动跳过坏的)
python3 proxy_manager.py status        # 看当前代理+池子
python3 proxy_manager.py verify        # 打印手机当前经隧道出口IP
python3 proxy_manager.py down          # 拆隧道
python3 proxy_manager.py check ip:port # 单测一个代理
# token 在脚本内 TOKEN=,或用环境变量 PROXY_TOKEN= 覆盖
```

### 批量循环(接进 fast_pipeline_pixel4.py)
装样本 → 起App → 等 sdk_forward json → pull → 卸载 →
`python3 proxy_manager.py rotate` → 下一个;没拿到json(限流)就再 rotate 重试。
```
