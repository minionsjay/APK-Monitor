#!/usr/bin/env python3
"""
自动点击弹窗中的"允许"按钮
持续监听UI变化，发现"允许"按钮就点击
"""
import subprocess, re, time, sys

ADB = "adb -s 192.168.1.16:38399"

def find_and_click():
    """查找并点击"允许"按钮"""
    subprocess.run(f"{ADB} shell uiautomator dump /sdcard/ui.xml".split(),
                  capture_output=True, timeout=10)
    subprocess.run(f"{ADB} pull /sdcard/ui.xml /tmp/ui_auto.xml".split(),
                  capture_output=True, timeout=5)
    try:
        with open("/tmp/ui_auto.xml") as f:
            ui = f.read()
        
        # 搜索所有"允许"按钮
        matches = re.findall(r'text="(允许)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
        if matches:
            _, x1, y1, x2, y2 = matches[0]
            cx = (int(x1) + int(x2)) // 2
            cy = (int(y1) + int(y2)) // 2
            subprocess.run(f"{ADB} shell input tap {cx} {cy}".split(),
                          capture_output=True, timeout=5)
            print(f"  点击允许 ({cx},{cy})", flush=True)
            return True
        
        # 也搜索英文"ALLOW"
        matches_en = re.findall(r'text="(ALLOW|Allow|allow)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
        if matches_en:
            _, x1, y1, x2, y2 = matches_en[0]
            cx = (int(x1) + int(x2)) // 2
            cy = (int(y1) + int(y2)) // 2
            subprocess.run(f"{ADB} shell input tap {cx} {cy}".split(),
                          capture_output=True, timeout=5)
            print(f"  点击ALLOW ({cx},{cy})", flush=True)
            return True
            
    except Exception as e:
        pass
    return False

def main():
    interval = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    
    print(f"自动点击器启动: 每{interval}秒检查, 持续{duration}秒", flush=True)
    
    start = time.time()
    clicked = 0
    while time.time() - start < duration:
        if find_and_click():
            clicked += 1
            time.sleep(2)  # 点击后等2秒
        else:
            time.sleep(interval)
    
    print(f"完成: 点击了{clicked}次", flush=True)

if __name__ == "__main__":
    main()
