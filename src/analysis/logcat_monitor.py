import subprocess
import threading
import re
import time
import json
import os

class LogcatMonitor:
    def __init__(self, output_file="logcat_leaks.jsonl"):
        self.process = None
        self.running = False
        self.output_file = output_file
        self.leaks = []
        
        # 敏感信息正则库 (针对日志优化)
        self.patterns = {
            "Token/Key": r"(?i)(token|api_key|secret|auth)[=:\s]+[a-zA-Z0-9\._-]{10,}",
            "Phone": r"(?<!\d)(1[3-9]\d{9})(?!\d)",
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Password": r"(?i)(password|pwd|passwd)[=:\s]+[^\s]+",
            "Location": r"(?i)(lat|lng|latitude|longitude)[=:\s]+[-+]?\d+\.\d+"
        }

    def start(self, target_pid):
        """启动日志监控线程"""
        if self.running: return
        self.running = True
        
        # 清理旧日志缓存
        subprocess.run(["adb", "logcat", "-c"])
        
        self.thread = threading.Thread(target=self._monitor_loop, args=(target_pid,))
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] Logcat monitor started for PID: {target_pid}")

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except: pass
        print(f"[*] Logcat monitor stopped. Found {len(self.leaks)} potential leaks.")

    def _monitor_loop(self, target_pid):
        # 启动 adb logcat，只筛选目标 PID 的日志 (Android 7.0+ 支持 --pid)
        cmd = ["adb", "logcat", "--pid", str(target_pid), "-v", "tag"]
        
        try:
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True, 
                errors='ignore',
                encoding='utf-8' # 确保处理中文日志
            )
            
            while self.running and self.process.poll() is None:
                line = self.process.stdout.readline()
                if not line: break
                
                self._analyze_line(line.strip())
                
        except Exception as e:
            print(f"[!] Logcat monitor error: {e}")

    def _analyze_line(self, line):
        # 忽略系统杂音
        if "I/Frida" in line or "D/Appium" in line: return

        for label, pattern in self.patterns.items():
            matches = re.findall(pattern, line)
            if matches:
                for match in matches:
                    # 过滤太短的误报
                    if len(str(match)) < 6: continue
                    
                    leak_entry = {
                        "type": "LOGCAT_LEAK",
                        "category": label,
                        "data": str(match),
                        "raw_log": line[:200], # 截取前200字符
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                    self.leaks.append(leak_entry)
                    
                    # 实时写入文件
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(leak_entry, ensure_ascii=False) + "\n")
                        
                    print(f"\033[91m[ALERT] Logcat Leak ({label}): {match}\033[0m")

    def get_leaks(self):
        """获取发现的泄露信息"""
        return self.leaks
