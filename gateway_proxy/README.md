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

## 待办 / 约束
- **代理必须支持 UDP ASSOCIATE**:否则 App 的 DNS(UDP53)走隧道失败。
  两条路:①买支持UDP的秒拨SOCKS5;②改脚本让 UDP53 直连、只隧道TCP
  (DNS从家宽IP出,但风控看的是TCP注册IP,通常可接受)。
- 真机务必用**支持UDP的国内秒拨SOCKS5**替换 127.0.0.1:1080(本地测试端点)。
- 手机adb建议USB(WSL需usbipd);WiFi也可,LAN已排除不自锁。
- 批量循环:装样本→起App→等sdk_forward json→pull→卸载→proxy_rotate→verify确认IP变→下一个;
  没拿到json(命中限流)就再rotate重试。
```
