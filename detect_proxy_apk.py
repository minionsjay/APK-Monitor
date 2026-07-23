#!/usr/bin/env python3
"""检测是否为代理转发类恶意 APK

特征：
1. 包含 libgojni.so（Go SDK 核心，~8.5MB）
2. 包含随机命名的 .so（tgnet/WebRTC，~23MB）
3. 壳的 classes.dex 很小（<5KB）
4. 包含 teamgram/tgnet/telegram 包结构
5. 包含 forwarder/proxy-system SDK 字符串
6. 壳的 Application 类（rmcme.g1md8jvlldb.maqrd.WgSnp 或类似混淆名）
7. RSA 私钥嵌入在 .so 中
8. 高危权限组合

使用方法：
  python3 detect_proxy_apk.py <apk_path>
  python3 detect_proxy_apk.py <directory>  # 批量扫描
"""

import sys, os, zipfile, re, hashlib, struct, json

def check_apk(apk_path):
    """检测单个 APK，返回检测结果"""
    result = {
        "file": os.path.basename(apk_path),
        "path": apk_path,
        "size_mb": round(os.path.getsize(apk_path) / 1024 / 1024, 1),
        "matches": [],
        "score": 0,
        "verdict": "未知",
        "details": {},
    }
    
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            
            # ===== 特征 1: libgojni.so =====
            gojni = [n for n in names if 'libgojni.so' in n]
            if gojni:
                so_data = zf.read(gojni[0])
                result["matches"].append("libgojni.so 存在")
                result["score"] += 30
                result["details"]["libgojni_size_mb"] = round(len(so_data) / 1024 / 1024, 1)
                
                # 特征 7: RSA 私钥嵌入
                if b'-----BEGIN RSA PRIVATE KEY-----' in so_data or b'LS0tLS1CRUdJTi' in so_data:
                    result["matches"].append("RSA 私钥嵌入在 .so 中")
                    result["score"] += 15
                
                # 特征 5: forwarder/proxy-system SDK
                for keyword in [b'forwarder', b'proxy-system', b'AppLineIPs', b'sdk_forwarder', b'DEADBEEF' if False else b'forwarder_control']:
                    if keyword in so_data:
                        result["matches"].append(f"Go SDK 含 {keyword.decode()}")
                        result["score"] += 5
                
                # 检查 SDK 字符串
                if b'proxysdk' in so_data:
                    result["matches"].append("proxysdk 符号")
                    result["score"] += 5
                if b'forwarder control' in so_data:
                    result["matches"].append("forwarder control 协议")
                    result["score"] += 10
                if b'app_line_ips' in so_data:
                    result["matches"].append("app_line_ips 字段")
                    result["score"] += 10
                if b'sdk_forwarder_fixed.json' in so_data:
                    result["matches"].append("sdk_forwarder_fixed.json 缓存")
                    result["score"] += 5
                if b'oss-accelerate.aliyuncs.com' in so_data or b'gz.bcebos.com' in so_data:
                    result["matches"].append("OSS CDN 地址")
                    result["score"] += 5
            
            # ===== 特征 2: 随机命名的 .so =====
            so_files = [n for n in names if n.endswith('.so') and 'lib/' in n]
            large_sos = []
            for so in so_files:
                info = zf.getinfo(so)
                if info.file_size > 5_000_000:  # >5MB
                    large_sos.append({"name": os.path.basename(so), "size_mb": round(info.file_size / 1024 / 1024, 1)})
            
            if large_sos:
                result["details"]["large_so_files"] = large_sos
                # 检查是否有 ~23MB 的 .so（tgnet/WebRTC）
                has_tgnet = any(s["size_mb"] > 15 for s in large_sos)
                if has_tgnet:
                    result["matches"].append("大型 .so (tgnet/WebRTC)")
                    result["score"] += 10
            
            # ===== 特征 3: 壳的 classes.dex 很小 =====
            dex_files = sorted([n for n in names if n.endswith('.dex')])
            if dex_files:
                dex_info = zf.getinfo(dex_files[0])
                if dex_info.file_size < 5000:
                    result["matches"].append(f"壳 dex 很小 ({dex_info.file_size} bytes)")
                    result["score"] += 15
                    result["details"]["shell_dex_size"] = dex_info.file_size
                result["details"]["dex_count"] = len(dex_files)
            
            # ===== 特征 4: teamgram/tgnet 包 =====
            for dex in dex_files:
                try:
                    data = zf.read(dex)
                    if b'teamgram' in data or b'tgnet' in data or b'org/telegram' in data:
                        result["matches"].append("teamgram/tgnet 包结构")
                        result["score"] += 10
                        break
                except:
                    pass
            
            # ===== 特征 6: 壳的 Application 类 =====
            if dex_files:
                try:
                    dex_data = zf.read(dex_files[0])
                    # 搜索 WgSnp 或 rmcme 类
                    if b'WgSnp' in dex_data or b'rmcme' in dex_data:
                        result["matches"].append("壳 Application 类 (WgSnp/rmcme)")
                        result["score"] += 10
                    # 搜索 TifMzURNarAMvQl 或类似的 native 方法
                    if b'TifMz' in dex_data:
                        result["matches"].append("壳 native 方法 TifMzURNarAMvQl")
                        result["score"] += 5
                except:
                    pass
            
            # ===== 特征 8: 权限组合 =====
            # 从 AndroidManifest.xml 中搜索（二进制格式）
            manifest = zf.read('AndroidManifest.xml') if 'AndroidManifest.xml' in names else b''
            dangerous_perms = []
            for perm in [b'CALL_PHONE', b'RECORD_AUDIO', b'FOREGROUND_SERVICE_CAMERA',
                        b'FOREGROUND_SERVICE_MICROPHONE', b'FOREGROUND_SERVICE_MEDIA_PROJECTION',
                        b'ACCESS_FINE_LOCATION', b'READ_CALL_LOG', b'GET_ACCOUNTS',
                        b'SYSTEM_ALERT_WINDOW', b'READ_PHONE_STATE']:
                if perm in manifest:
                    dangerous_perms.append(perm.decode())
            
            if len(dangerous_perms) >= 5:
                result["matches"].append(f"高危权限组合 ({len(dangerous_perms)} 个)")
                result["score"] += 10
                result["details"]["dangerous_perms"] = dangerous_perms
            
            # ===== 特征 9: SNI 伪造 =====
            if gojni:
                so_data = zf.read(gojni[0])
                sni_list = []
                for sni in [b'bilibili.com', b'mail.163.com', b'static.zhihu.com', 
                           b'www.bootcdn.cn', b'music.163.com', b'share.note.youdao.com']:
                    if sni in so_data:
                        sni_list.append(sni.decode())
                if sni_list:
                    result["matches"].append(f"SNI 伪造 ({len(sni_list)} 个)")
                    result["score"] += 10
                    result["details"]["sni_list"] = sni_list
            
            # ===== 特征 10: uTLS =====
            if gojni:
                so_data = zf.read(gojni[0])
                if b'refraction-networking/utls' in so_data or b'utls' in so_data:
                    result["matches"].append("uTLS 指纹伪造")
                    result["score"] += 5
    
    except Exception as e:
        result["error"] = str(e)
    
    # 判定
    if result["score"] >= 70:
        result["verdict"] = "🔴 确认恶意（代理转发 SDK）"
    elif result["score"] >= 40:
        result["verdict"] = "🟡 高度可疑"
    elif result["score"] >= 20:
        result["verdict"] = "🟠 可能可疑"
    else:
        result["verdict"] = "🟢 未检出"
    
    return result

def main():
    if len(sys.argv) < 2:
        print("使用方法: python3 detect_proxy_apk.py <apk_path|directory>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if os.path.isdir(target):
        # 批量扫描
        apks = sorted([f for f in os.listdir(target) if f.endswith('.apk')])
        if not apks:
            print(f"目录 {target} 中没有 APK 文件")
            return
        
        print(f"扫描 {len(apks)} 个 APK\n")
        results = []
        for apk in apks:
            apk_path = os.path.join(target, apk)
            r = check_apk(apk_path)
            results.append(r)
            print(f"{r['verdict']}  {r['file']}  (score={r['score']})")
            for m in r["matches"]:
                print(f"  → {m}")
            print()
        
        # 汇总
        malicious = [r for r in results if r["score"] >= 70]
        suspicious = [r for r in results if 40 <= r["score"] < 70]
        clean = [r for r in results if r["score"] < 40]
        
        print("=" * 60)
        print(f"汇总: {len(malicious)} 恶意, {len(suspicious)} 可疑, {len(clean)} 干净")
        
        # 保存 JSON 报告
        report_path = os.path.join(target, "detection_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"报告: {report_path}")
    
    else:
        # 单个 APK
        r = check_apk(target)
        print(f"\n{'='*60}")
        print(f"文件: {r['file']}  ({r['size_mb']} MB)")
        print(f"判定: {r['verdict']}  (score={r['score']}/100)")
        print(f"{'='*60}")
        print("\n匹配特征:")
        for m in r["matches"]:
            print(f"  → {m}")
        if r["details"]:
            print(f"\n详细信息:")
            for k, v in r["details"].items():
                print(f"  {k}: {v}")

if __name__ == '__main__':
    main()
