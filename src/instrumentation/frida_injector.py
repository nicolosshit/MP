import frida
import time
import sys
import os
import json

class FridaInjector:
    def __init__(self, device_id=None, output_dir="."):
        """
        初始化 Frida 注入器
        :param device_id: 指定设备 ID，如果为 None 则连接 USB 设备
        :param output_dir: 输出目录，用于存储日志文件
        """
        try:
            # 获取 USB 连接的设备
            # 必须确保模拟器中 frida-server 正在运行 [cite: 40]
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device.name} ({self.device.id})")
        except Exception as e:
            print(f"[!] Failed to connect to device. Ensure frida-server is running on the emulator.")
            print(f"    Error: {e}")
            sys.exit(1)

        self.session = None
        self.script = None
        self.canary_data = []
        self.hook_results = []
        self.output_dir = output_dir
        self.log_file = os.path.join(output_dir, "injection_logs.jsonl")
        self.leak_file = os.path.join(output_dir, "privacy_leaks.jsonl")
        # 初始化时清空旧日志
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        if os.path.exists(self.leak_file):
            os.remove(self.leak_file)

    def load_hook_script(self, script_path="config/frida_hooks.js"):
        """
        读取外部 JS 脚本内容
        :param script_path: 脚本路径
        :return: 脚本内容
        """
        try:
            # 确保路径相对于项目根目录
            if not os.path.exists(script_path):
                 # 尝试向上查找（兼容从 src 目录运行的情况）
                script_path = os.path.join("..", "..", script_path)
            
            with open(script_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            print(f"[!] Script file not found: {script_path}")
            sys.exit(1)

    def load_additional_scripts(self, script_paths):
        """
        加载额外的脚本（如 SSL Pinning 绕过）
        :param script_paths: 脚本路径列表
        :return: 合并后的脚本内容
        """
        additional_code = ""
        for script_path in script_paths:
            try:
                if not os.path.exists(script_path):
                    # 尝试向上查找
                    script_path = os.path.join("..", "..", script_path)
                
                with open(script_path, 'r', encoding='utf-8') as f:
                    additional_code += '\n' + f.read()
            except FileNotFoundError:
                print(f"[!] Additional script file not found: {script_path}")
        return additional_code
    
    def _log_injection(self, data):
        """将注入事件持久化到文件"""
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "api": data.get('api'),
            "canary": data.get('payload'),
            "stack_trace": data.get('stack_trace')
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def on_message(self, message, data):
        """
        处理来自 JavaScript 的 send() 消息 
        """
        if message['type'] == 'send':
            payload = message['payload']
            # 这里的 payload 就是我们在 JS 中定义的字典
            if isinstance(payload, dict):
                # 处理隐私泄露事件
                if payload.get('type') == 'privacy_leak':
                    print("\n" + "="*50)
                    print(f" [ALERT] Privacy Access Detected!")
                    print(f" API: {payload['api']}")
                    print(f" Injected Canary: {payload['payload']}")
                    print("-" * 20)
                    # 简单展示堆栈的前几行
                    stack = payload.get('stack_trace', '').split('\n')
                    print(f" Call Stack (Top 3):")
                    for line in stack[0:3]:
                        print(f"   {line.strip()}")
                    print("="*50 + "\n")
                    
                    # 将泄露事件写入到文件
                    leak_entry = {
                        'type': 'privacy_leak',
                        'api': payload['api'],
                        'evidence': payload['payload'],
                        'timestamp': time.time(),
                        'stack_trace': payload.get('stack_trace', '')
                    }
                    with open(self.leak_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(leak_entry, ensure_ascii=False) + "\n")
                
                # 处理金丝雀注入事件
                elif payload.get('type') == 'canary_injected':
                    canary_info = {
                        'api_name': payload.get('api'),
                        'canary_value': payload.get('payload'),
                        'timestamp': time.time(),
                        'stack_trace': payload.get('stack_trace')
                    }
                    self.canary_data.append(canary_info)
                    print(f"[\033[96mFRIDA\033[0m] 注入金丝雀 -> API: {payload['api']}")
                    self._log_injection(payload)
                
                # 处理其他 Hook 事件
                elif payload.get('type') == 'hook_event':
                    hook_info = {
                        'event_type': payload.get('event_type'),
                        'api_name': payload.get('api'),
                        'arguments': payload.get('arguments'),
                        'return_value': payload.get('return_value'),
                        'timestamp': time.time(),
                        'stack_trace': payload.get('stack_trace')
                    }
                    self.hook_results.append(hook_info)
                
                else:
                    print(f"[*] Message from App: {payload}")
        elif message['type'] == 'error':
            print(f"[!] Error in JS: {message['stack']}")

    def spawn_and_inject(self, package_name, additional_scripts=None):
        """
        以 Spawn 模式启动 App 并注入 (适合自动化审计)
        :param package_name: 包名
        :param additional_scripts: 额外的脚本路径列表
        :return: 进程 PID，如果失败则返回 None
        """
        print(f"[*] Spawning package: {package_name}")
        try:
            # 1. Spawn: 启动进程但不执行 (Suspended)
            pid = self.device.spawn([package_name])
            
            # 2. Attach: 附加到进程
            self.session = self.device.attach(pid)
            
            # 3. Create Script: 编译 JS 代码
            js_code = self.load_hook_script()
            
            # 4. 添加额外的脚本
            if additional_scripts:
                js_code += self.load_additional_scripts(additional_scripts)
            
            self.script = self.session.create_script(js_code)
            
            # 5. Register Callback: 绑定消息处理函数
            self.script.on('message', self.on_message)
            
            # 6. Load: 加载脚本
            self.script.load()
            
            # 7. Resume: 恢复进程运行
            self.device.resume(pid)
            print(f"[+] Injection successful. App is running with PID: {pid}")
            
            # [关键修改] 删除 sys.stdin.read()，让函数立即返回，以便 main.py 继续执行
            return pid 
            
        except frida.ServerNotRunningError:
            print("[!] Frida server is not running on the device.")
            return None
        except frida.ProcessNotFoundError:
            print(f"[!] Package not found: {package_name}")
            return None
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            print("[WARN] [*] Spawn mode failed, trying attach mode...")
            # 尝试使用 attach 模式
            return self.attach_and_inject(package_name, additional_scripts)
        finally:
            # 不要在这里 detach，因为我们需要保持会话活动
            # 会话将在外部通过 detach() 方法手动关闭
            pass

    def attach_and_inject(self, package_name, additional_scripts=None):
        """
        以 Attach 模式注入到运行中的 App
        :param package_name: 包名
        :param additional_scripts: 额外的脚本路径列表
        :return: 进程 PID，如果失败则返回 None
        """
        print(f"[*] Attaching to package: {package_name}")
        try:
            # 查找进程
            processes = self.device.enumerate_processes()
            target_process = None
            for process in processes:
                if process.name == package_name:
                    target_process = process
                    break
            
            if not target_process:
                print(f"[!] Process not found: {package_name}")
                return None
            
            # Attach 到进程
            try:
                self.session = self.device.attach(target_process.pid)
            except Exception as attach_error:
                print(f"[!] Failed to attach: {attach_error}")
                print("[WARN] Trying Gadget mode...")
                # 尝试使用 Gadget 模式
                try:
                    # 在 Gadget 模式下，我们需要等待 Gadget 被加载
                    print("[INFO] Waiting for Frida Gadget to be loaded...")
                    time.sleep(2)
                    # 尝试再次 attach，这次应该能找到 Gadget
                    self.session = self.device.attach(target_process.pid)
                except Exception as gadget_error:
                    print(f"[!] Gadget mode failed: {gadget_error}")
                    return None
            
            # 加载脚本
            js_code = self.load_hook_script()
            
            # 添加额外的脚本
            if additional_scripts:
                js_code += self.load_additional_scripts(additional_scripts)
            
            self.script = self.session.create_script(js_code)
            self.script.on('message', self.on_message)
            self.script.load()
            
            print(f"[+] Injection successful. Attached to PID: {target_process.pid}")
            
            # [关键修改] 删除 sys.stdin.read()，让函数立即返回，以便 main.py 继续执行
            return target_process.pid
            
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            return None
        finally:
            # 不要在这里 detach，因为我们需要保持会话活动
            # 会话将在外部通过 detach() 方法手动关闭
            pass

    def get_canary_data(self):
        """
        获取注入的金丝雀数据
        :return: 金丝雀数据列表
        """
        return self.canary_data

    def get_hook_results(self):
        """
        获取 Hook 结果
        :return: Hook 结果列表
        """
        return self.hook_results

    def clear_data(self):
        """
        清除数据
        """
        self.canary_data = []
        self.hook_results = []

    def detach(self):
        """
        分离会话
        """
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        self.script = None
        self.session = None

# 为了方便测试，如果直接运行此文件：
if __name__ == "__main__":
    # 使用 Android 设置应用作为测试靶场，因为它通常带有权限
    target_app = "com.android.settings" 
    injector = FridaInjector()
    
    # 加载 SSL Pinning 绕过脚本
    additional_scripts = ["src/instrumentation/ssl_unpinning.js"]
    
    # 注意：需确保 frida_hooks.js 路径正确，根据你运行的位置可能需要调整
    injector.spawn_and_inject(target_app, additional_scripts)
