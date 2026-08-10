# TCP Connection vs Forward File IP Comparison

## Technique

After obtaining `sdk_forwarder_fixed.json` (13 IPs, no port), also read `/proc/PID/net/tcp` to get actual ESTABLISHED TCP connections. Compare the two sets to verify forward file IPs are real proxy nodes.

## Implementation (added to pipeline_redroid.py install_worker)

```python
# After get_proxy_nodes() succeeds, before force-stop:
tcp_ips = set()
r_pid = run_adb(['shell', f'pidof {pkg}'], timeout=5)
pid = r_pid.stdout.strip()
if pid:
    r_tcp = run_adb(['shell', f'cat /proc/{pid}/net/tcp'], timeout=5)
    for line in r_tcp.stdout.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != '01': continue
        ip_hex, port_hex = parts[2].split(':')
        port = int(port_hex, 16)
        if port <= 100: continue
        if len(ip_hex) == 8:
            b = bytes.fromhex(ip_hex)
            ip = f'{b[3]}.{b[2]}.{b[1]}.{b[0]}'
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('172.'): continue
            tcp_ips.add(ip)

# Save comparison to artifacts
with open(f'{apk_artifact_dir}/tcp_connections.json', 'w') as f:
    json.dump({
        'forward_ips': nodes,           # 13 IPs from forward file (no port)
        'tcp_ips': sorted(tcp_ips),     # 3-4 IPs from /proc/net/tcp
        'common': sorted(set(nodes) & tcp_ips),      # ~1 IP in both
        'forward_only': sorted(set(nodes) - tcp_ips), # ~12 IPs only in forward
        'tcp_only': sorted(tcp_ips - set(nodes))      # ~2-3 IPs only in TCP
    }, f, indent=2)
```

## Full Production Results (2026-08-04, 53 APKs on Redroid/Tencent Cloud)

### Per-APK breakdown (all 25 proxy APKs showed identical pattern)

| APK | Forward IPs | TCP IPs | Common | Forward-only | TCP-only |
|-----|-------------|---------|--------|--------------|----------|
| 81du003.ye41r.top | 13 | 3 | 1 | 12 | 2 |
| 81du008.19lf9.top | 13 | 4 | 1 | 12 | 3 |
| 81du028.mmh3s.top | 13 | 4 | 1 | 12 | 3 |
| 81du033.8lvsf.top | 13 | 4 | 1 | 12 | 3 |
| 81du034.tktgy.top | 13 | 4 | 1 | 12 | 3 |
| 81du035.69kgx.top | 13 | 4 | 1 | 12 | 3 |
| 81du035.udqzt.top | 13 | 5 | 1 | 12 | 4 |
| 81du042.kuwf2.top | 13 | 3 | 1 | 12 | 2 |
| ... (all 25 proxy APKs follow same pattern) | | | | | |

### Aggregate statistics (53 APKs total, 25 with TCP comparison data)

| Metric | Value |
|--------|-------|
| APKs with tcp_connections.json | 53 |
| APKs with TCP IPs (APP was running) | 25 |
| Total forward IPs (across all APKs) | 312 |
| Total TCP IPs (across all APKs) | 89 |
| Total common IPs (in both forward AND TCP) | 24 |
| Total TCP-only IPs (not in forward) | 68 |

### TCP-only IPs (12 unique, not in any forward file)

| IP | Likely purpose |
|----|----------------|
| 47.113.75.144 | Alibaba Cloud — control plane / bootstrap |
| 47.113.75.192 | Alibaba Cloud — control plane / bootstrap |
| 8.138.47.195 | Alibaba Cloud — control plane / bootstrap |
| 8.138.95.190 | Alibaba Cloud — control plane / bootstrap |
| 47.99.137.104 | Alibaba Cloud — control plane / bootstrap |
| 120.26.47.228 | Alibaba Cloud — control plane / bootstrap |
| 218.91.113.207 | Jiangsu telecom — CDN or control plane |
| 117.88.33.209 | Jiangsu telecom — CDN or control plane |
| 117.88.33.247 | Jiangsu telecom — CDN or control plane |
| 14.215.183.199 | Guangdong telecom — CDN (Baidu CDN) |
| 121.14.45.21 | Guangdong telecom — CDN |
| 120.240.164.152 | Guangdong telecom — CDN |

## Analysis

1. **Forward file has 13 IPs, TCP only 3-5** — APP doesn't connect to all 13 nodes simultaneously; it picks 1-2 active proxy nodes and connects to them (load balancing)
2. **Every APK had exactly 1 IP in common** between forward file and TCP — confirms APP IS using forward file IPs for actual connections
3. **TCP-only IPs are control plane / CDN** — Alibaba Cloud IPs (47.113.x, 8.138.x) are likely the control plane server (123.207.40.186:30139 from reverse engineering) or initial bootstrap nodes. Telecom IPs (14.215.x, 121.14.x) are CDN connections for .dat file downloads.
4. **Forward-only IPs (12 of 13)** — These are the full proxy node pool from the control plane. APP hasn't connected to them yet — they're standby nodes.
5. **All 25 proxy APKs show the same 13 forward IPs** — same proxy infrastructure across the entire batch

## Conclusion

Forward file IPs are **real and valid** — APP connects to a subset of them (1 of 13 at any given moment). The TCP-only IPs are control plane / CDN / bootstrap connections, not proxy nodes. This validates that reading `sdk_forwarder_fixed.json` is the correct approach for extracting proxy node IPs (not TCP connections, which only show active connections and miss standby nodes).

**Key insight**: The 1:13 ratio means the APP does load balancing across 13 nodes, connecting to only 1 at any time. The forward file is the authoritative source for the complete node pool.
