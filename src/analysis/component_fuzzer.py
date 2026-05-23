import subprocess
import time
import re

class ComponentFuzzer:
    def __init__(self, device_manager, package_name):
        self.dm = device_manager
        self.pkg = package_name
        self.exported_activities = []
        self.vulnerabilities = []

    def run(self, apk_path):
        print("[*] Starting Component Fuzzing (Attack Surface)...")
        
        # 1. 静态分析：提取 exported Activity
        # 依赖 aapt 命令
        cmd = ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            # 如果失败，尝试使用绝对路径
            if res.returncode != 0:
                print("[INFO] Trying absolute path for aapt...")
                cmd = ["F:/Android/SDK/build-tools/36.1.0/aapt.exe", "dump", "xmltree", apk_path, "AndroidManifest.xml"]
                res = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            current_activity = None
            is_exported = False
            
            for line in res.stdout.split('\n'):
                line = line.strip()
                if "E: activity" in line:
                    current_activity = None
                    is_exported = False # 默认为 False (Android 12+) 或根据 targetSdk
                
                if "A: android:name" in line and "activity" in line:
                    # 提取 Activity 名称
                    parts = line.split('"')
                    if len(parts) > 1:
                        current_activity = parts[1]
                
                if "A: android:exported" in line:
                    if "0xffffffff" in line: # true
                        is_exported = True
                
                if current_activity and is_exported:
                    # 简单的逻辑，实际需处理 Activity 闭合标签，这里简化演示
                    if current_activity not in self.exported_activities:
                        self.exported_activities.append(current_activity)
                        # 重置以免重复添加
                        current_activity = None 

        except Exception as e:
            print(f"[!] Aapt error: {e}")
            return []

        print(f"[*] Found {len(self.exported_activities)} exported activities.")

        # 2. 动态 Fuzzing：尝试调起
        for activity in self.exported_activities:
            # 补全包名
            full_name = activity if "." in activity else f"{self.pkg}.{activity}"
            if activity.startswith("."): full_name = self.pkg + activity
            
            print(f"[*] Fuzzing: {full_name}")
            
            # 强制停止 App，确保是从外部冷启动
            self.dm.run_adb_command(f"shell am force-stop {self.pkg}")
            time.sleep(0.5)
            
            # 尝试启动
            # adb shell am start -n com.ex/.MainActivity
            cmd = f"shell am start -n {self.pkg}/{full_name}"
            code, out, err = self.dm.run_adb_command(cmd)
            
            time.sleep(2) # 等待启动
            
            # 3. 验证结果：检查当前前台 Activity 是否是目标
            current = self.dm.get_current_activity() # 需在 DeviceManager 中实现
            if current and full_name in current:
                print(f"\033[91m[VULN] Successfully launched exported activity: {full_name}\033[0m")
                self.vulnerabilities.append({
                    "type": "EXPORTED_ACTIVITY",
                    "activity": full_name,
                    "risk": "High",
                    "desc": "Sensitive activity can be launched by external apps."
                })
        
        return self.vulnerabilities
