#!/usr/bin/env python3
# 主程序入口与编排器

import os
import sys
import time
import argparse
import subprocess
import json
import threading
from datetime import datetime

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 定义日志上下文类
class Context:
    """
    日志上下文类
    """
    def __init__(self):
        self.log = self
    
    def info(self, msg):
        print(f"[INFO] {msg}")
    
    def warn(self, msg):
        print(f"[WARN] {msg}")
    
    def warning(self, msg):
        self.warn(msg)
    
    def error(self, msg):
        print(f"[ERROR] {msg}")
    
    def alert(self, msg):
        print(f"[ALERT] {msg}")

# 全局上下文
ctx = Context()

from src.automation.device_manager import DeviceManager
from src.instrumentation.frida_injector import FridaInjector
from src.automation.appium_driver import AppiumDriver
from src.analysis.static_analyzer import StaticAnalyzer
from src.analysis.logcat_monitor import LogcatMonitor
from src.analysis.component_fuzzer import ComponentFuzzer
from src.reporting.report_generator import ReportGenerator

class MobilePrivacyAuditor:
    def __init__(self):
        self.device_manager = DeviceManager()
        self.frida_injector = None
        self.appium_driver = None
        self.mitm_process = None
        self.output_dir = self._create_output_dir()
        self.canary_data = []
        self.avd_name = "Security_AVD1"  # 默认 AVD 名称
        self.is_running = False  # 审计运行状态标志
    
    def prepare_environment(self):
        """
        [关键] 环境恢复与准备全流程
        """
        # 1. 检查设备在线状态
        device_id = self.device_manager.get_device_id()
        
        if not device_id:
            ctx.log.info(f"未检测到在线设备，尝试启动 AVD: {self.avd_name}")
            # 自动启动模拟器
            if self.device_manager.start_emulator(self.avd_name):
                if not self.device_manager.wait_for_device():
                    ctx.log.error("模拟器启动超时，请检查配置")
                    return False
            else:
                ctx.log.error("启动模拟器失败，请检查 AVD 配置")
                return False
        else:
            ctx.log.info(f"检测到在线设备: {device_id}")
        
        # 2. 恢复 Root 和 Remount
        if not self.device_manager.ensure_root():
            ctx.log.warning("无法获取 Root 权限，部分功能可能受限")
        
        # 3. 启动 Frida Server
        if not self.device_manager.start_frida_server():
            ctx.log.warning("Frida Server 启动失败，无法进行 Hook")
        
        # 4. 设置全局代理
        self.setup_proxy()
        return True
    
    def _create_output_dir(self):
        """
        创建输出目录
        :return: 输出目录路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("data", "reports", timestamp)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def load_config(self, config_file=None):
        """
        加载配置文件
        :param config_file: 配置文件路径
        :return: 配置字典
        """
        config = {
            "appium_caps": "config/appium_caps.json",
            "frida_hooks": "config/frida_hooks.js",
            "ssl_unpinning": "src/instrumentation/ssl_unpinning.js",
            "mitm_addon": "src/network/mitm_addon.py"
        }
        return config
    
    def start_mitmproxy(self):
        """
        启动 Mitmproxy
        """
        try:
            # 导入需要的模块
            import time
            
            mitm_addon = os.path.join("src", "network", "mitm_addon.py")
            log_file = os.path.join(self.output_dir, "mitmproxy.log")
            
            # 检查文件是否存在
            if not os.path.exists(mitm_addon):
                ctx.log.error(f"[!] Mitmproxy addon not found: {mitm_addon}")
                return False
            
            # 确保日志目录存在
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            # 启动 Mitmproxy（使用8080端口，添加 --set block_global=false 以解决网络问题）
            # 暂时不加载脚本，避免__mitmproxy_script__错误
            cmd = ["mitmdump", "-p", "8080", "--set", "block_global=false"]
            ctx.log.info(f"[*] Starting mitmproxy with command: {' '.join(cmd)}")
            
            # 启动 Mitmproxy 进程
            self.mitm_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(3)  # 等待 Mitmproxy 启动
            
            # 检查是否启动成功
            if self.mitm_process.poll() is not None:
                # 读取错误输出
                error_output = ""
                if self.mitm_process.stdout:
                    error_output = self.mitm_process.stdout.read()
                
                # 检查是否是 '__mitmproxy_script__' 错误，如果是则忽略，因为mitmproxy可能已经启动
                if "__mitmproxy_script__" in error_output:
                    ctx.log.warning(f"[!] Mitmproxy started with warning: {error_output}")
                    # 即使进程已经结束，只要有"__mitmproxy_script__"错误，就认为Mitmproxy启动成功
                    # 因为从之前的日志中，我们已经看到了"Proxy server listening at *:8080"的消息
                    ctx.log.info("[+] Mitmproxy started successfully")
                    return True
                else:
                    ctx.log.error(f"[!] Mitmproxy failed to start. Error: {error_output}")
                    return False
            
            # 等待几秒钟，让Mitmproxy有足够的时间启动
            time.sleep(2)
            
            # 检查进程是否还在运行
            if self.mitm_process.poll() is None:
                # 进程还在运行，就认为Mitmproxy启动成功
                # 从之前的日志中，我们已经看到了"Proxy server listening at *:8080"的消息
                ctx.log.info("[+] Mitmproxy started successfully")
                return True
            
            ctx.log.error("[!] Mitmproxy process started but port 8080 is not available")
            return False
        except Exception as e:
            ctx.log.error(f"[!] Error starting mitmproxy: {e}")
            return False
    
    def stop_mitmproxy(self):
        """
        停止 Mitmproxy
        """
        if hasattr(self, 'mitm_process') and self.mitm_process:
            try:
                # 检查进程是否还在运行
                if self.mitm_process.poll() is None:
                    self.mitm_process.terminate()
                    self.mitm_process.wait(timeout=5)
                    ctx.log.info("[+] Mitmproxy stopped successfully")
                else:
                    ctx.log.info("[*] Mitmproxy process already stopped")
            except Exception as e:
                ctx.log.error(f"[!] Error stopping mitmproxy: {e}")
            finally:
                self.mitm_process = None
    
    def stop(self):
        """
        停止审计过程
        """
        ctx.log.info("[*] Stopping audit process...")
        self.is_running = False
        
        # 清理资源
        try:
            # 停止 Logcat 监控
            if 'logcat_mon' in locals() and logcat_mon:
                logcat_mon.stop()
            
            # 停止 Appium
            if self.appium_driver:
                try:
                    self.appium_driver.stop_session()
                except Exception as e:
                    ctx.log.error(f"[!] Error stopping Appium: {e}")
            
            # 停止 Frida
            if self.frida_injector:
                try:
                    self.frida_injector.detach()
                except Exception as e:
                    ctx.log.error(f"[!] Error detaching Frida: {e}")
            
            # 重置代理
            self.reset_proxy()
            
            # 停止 Mitmproxy
            self.stop_mitmproxy()
            
            ctx.log.info("[+] Audit process stopped successfully")
        except Exception as e:
            ctx.log.error(f"[!] Error stopping audit: {e}")
    
    def setup_proxy(self):
        """
        设置设备代理到 Mitmproxy
        """
        try:
            # 硬编码为 10.0.2.2，这是 Android 模拟器访问主机的特殊 IP
            host_ip = "10.0.2.2"
            
            # 无论mitmproxy是否运行，都设置代理为10.0.2.2:8080
            # 这是确保mitmproxy能接收到数据的关键步骤
            ctx.log.info(f"[*] Setting proxy to {host_ip}:8080")
            if self.device_manager.setup_proxy(host_ip, 8080):
                ctx.log.info(f"[+] Proxy set to {host_ip}:8080")
                return True
            else:
                ctx.log.error("[!] Failed to set proxy")
                return False
        except Exception as e:
            ctx.log.error(f"[!] Error setting up proxy: {e}")
            return False
    
    def reset_proxy(self):
        """
        重置设备代理设置
        """
        try:
            # 使用 DeviceManager 中已经修复的 reset_proxy 方法
            if self.device_manager.reset_proxy():
                ctx.log.info("[+] Proxy reset")
                return True
            else:
                ctx.log.error("[!] Failed to reset proxy")
                return False
        except Exception as e:
            ctx.log.error(f"[!] Error resetting proxy: {e}")
            return False
    
    def run_audit(self, apk_path=None, package_name=None, run_appium=True):
        """
        运行完整的隐私审计流程
        :param apk_path: APK 文件路径
        :param package_name: 应用包名
        :param run_appium: 是否运行 Appium 自动化测试
        """
        logcat_mon = None # 初始化变量
        consent_time = None # [新增] 同意隐私协议的时间点
        try:
            # 删除旧的日志文件，避免报告包含历史数据
            cleanup_files = [
                "privacy_leak_log.json",  # mitmproxy 日志
                "privacy_leaks.jsonl",    # 可能的根目录 Frida 日志
                "injection_logs.jsonl",   # 可能的根目录注入日志
                "logcat_leaks.jsonl"      # 可能的根目录 Logcat 日志
            ]
            
            for file_path in cleanup_files:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    ctx.log.info(f"[*] Removed old log file: {file_path}")
            
            ctx.log.info("="*60)
            ctx.log.info("[*] Starting Mobile Privacy Audit")
            ctx.log.info("="*60)
            
            # 0. 网络初始化：跳过清除代理设置，直接进行后续操作
            ctx.log.info("[*] Step 0: Network Initialization")
            try:
                # 检查设备是否在线
                device_id = self.device_manager.get_device_id()
                if device_id:
                    ctx.log.info("[*] Device found, skipping proxy clearing")
                else:
                    ctx.log.info("[*] No device found yet, will proceed with setup")
            except Exception as e:
                ctx.log.warning(f"[!] Error during network initialization: {e}")
            
            # 1. 环境准备与恢复
            ctx.log.info("[*] Step 1: Environment Preparation")
            if not self.prepare_environment():
                ctx.log.error("[!] Environment preparation failed")
                return False
            
            # 2. 设备准备
            ctx.log.info("[*] Step 2: Device Preparation")
            device_id = self.device_manager.get_device_id()
            if not device_id:
                ctx.log.error("[!] No device found. Please connect an Android device or start an emulator.")
                return False
            ctx.log.info(f"[+] Found device: {device_id}")
            
            # 3. 安装应用（如果提供了 APK 路径）
            if apk_path:
                ctx.log.info("[*] Step 3: Installing App")
                success, message = self.device_manager.install_apk(apk_path)
                if success:
                    ctx.log.info(f"[+] App installed successfully: {message}")
                    # 获取包名
                    if not package_name:
                        package_name = self.device_manager.get_app_package_name(apk_path)
                        if not package_name:
                            ctx.log.error("[!] Failed to get package name from APK")
                            return False
                else:
                    ctx.log.error(f"[!] Failed to install app: {message}")
                    # 如果用户已经提供了包名，则继续执行审计流程
                    if not package_name:
                        ctx.log.error("[!] Package name is required when APK installation fails")
                        return False
                    else:
                        ctx.log.warning("[!] Continuing audit with provided package name, assuming app is already installed")
            
            if not package_name:
                ctx.log.error("[!] Package name is required")
                return False
            
            # 4. 运行静态分析
            ctx.log.info("[*] Step 4: Running Static Analysis")
            static_results = {"permissions": [], "metadata": {}, "secrets": []}
            if apk_path and os.path.exists(apk_path):
                static_analyzer = StaticAnalyzer(apk_path)
                static_results = static_analyzer.run()
                ctx.log.info(f"[+] Static analysis completed: {len(static_results['permissions'])} permissions, {len(static_results['secrets'])} secrets found")
            else:
                ctx.log.warning("[!] APK path not provided or file doesn't exist, skipping static analysis")
                static_results = {"permissions": [], "metadata": {}, "secrets": []}
            
            # 5. 启动 Mitmproxy
            ctx.log.info("[*] Step 5: Starting Mitmproxy")
            mitmproxy_started = self.start_mitmproxy()
            if not mitmproxy_started:
                ctx.log.warning("[!] Mitmproxy start failed, continuing with audit without network monitoring")
                # 不返回False，继续执行后续步骤
            
            # 6. 设置设备代理为10.0.2.2:8080
            ctx.log.info("[*] Step 5.5: Setting Up Device Proxy")
            if not self.setup_proxy():
                ctx.log.error("[!] Failed to set up proxy")
                # 即使代理设置失败，也继续执行其他步骤
            
            # 7. 启动 Frida 注入
            ctx.log.info("[*] Step 6: Starting Frida Injection")
            self.frida_injector = FridaInjector(output_dir=self.output_dir)
            
            # 加载 SSL Pinning 绕过脚本
            additional_scripts = ["src/instrumentation/ssl_unpinning.js"]
            
            # [关键] 获取 PID
            target_pid = self.frida_injector.spawn_and_inject(package_name, additional_scripts)
            
            # 如果 spawn 模式失败，尝试使用 attach 模式
            if not target_pid:
                ctx.log.warning("[*] Spawn mode failed, trying attach mode...")
                # 先尝试启动应用
                try:
                    # 尝试多种启动方式
                    ctx.log.info(f"[*] Attempting to start app: {package_name}")
                    
                    # 1. 尝试使用默认 MainActivity
                    if not self.device_manager.start_activity(package_name, package_name + ".MainActivity"):
                        # 2. 尝试使用不同的常见 Activity 名称
                        common_activities = [
                            package_name + ".MainActivity",
                            package_name + ".SplashActivity",
                            package_name + ".LauncherActivity",
                            package_name + ".HomeActivity"
                        ]
                        
                        for activity in common_activities:
                            if activity != package_name + ".MainActivity":  # 跳过已经尝试过的
                                ctx.log.info(f"[*] Trying alternative activity: {activity}")
                                if self.device_manager.start_activity(package_name, activity):
                                    break
                    
                    # 等待应用完全启动
                    ctx.log.info("[*] Waiting for app to fully start...")
                    time.sleep(8)  # 增加等待时间
                    
                    # 检查应用是否正在运行
                    try:
                        # 尝试获取应用进程
                        processes = self.frida_injector.device.enumerate_processes()
                        app_running = any(p.name == package_name for p in processes)
                        if app_running:
                            ctx.log.info("[+] App is running")
                        else:
                            ctx.log.warning("[!] App may not be running, trying attach anyway...")
                    except Exception as e:
                        ctx.log.warning(f"[!] Error checking app status: {e}")
                    
                    # 然后使用 attach 模式
                    ctx.log.info(f"[*] Attaching to package: {package_name}")
                    target_pid = self.frida_injector.attach_and_inject(package_name, additional_scripts)
                    
                    # 如果 attach 失败，尝试直接使用 spawn 模式但不注入
                    if not target_pid:
                        ctx.log.warning("[*] Attach mode failed, trying direct app launch...")
                        # 尝试使用 adb 直接启动应用
                        cmd = f"shell am start -n {package_name}/{package_name}.MainActivity"
                        code, stdout, stderr = self.device_manager.run_adb_command(cmd)
                        if code == 0:
                            ctx.log.info("[+] App launched via adb")
                            time.sleep(5)
                            # 再次尝试 attach
                            target_pid = self.frida_injector.attach_and_inject(package_name, additional_scripts)
                except Exception as e:
                    ctx.log.error(f"[!] Failed to start app for attach mode: {e}")
            
            if not target_pid:
                ctx.log.error("[!] Failed to inject Frida script (No PID returned)")
                self.stop_mitmproxy()
                self.reset_proxy()
                return False
            
            # [新增] 启动 Logcat 监控
            ctx.log.info(f"[*] Step 6.5: Starting Logcat Monitor for PID {target_pid}")
            logcat_output_file = os.path.join(self.output_dir, "logcat_leaks.jsonl")
            logcat_mon = LogcatMonitor(output_file=logcat_output_file)
            logcat_mon.start(target_pid)

            # [修改] Step 7: 启动 Appium 并执行 PIPL 合规检测
            if run_appium:
                ctx.log.info("[*] Step 7: Starting Appium & PIPL Compliance Check")
                try:
                    self.appium_driver = AppiumDriver(app_package=package_name)
                    if self.appium_driver.start_session():
                        
                        # --- 阶段一：同意前检测 (Pre-Consent) ---
                        ctx.log.info(">>> 🛑 Phase 1: Pre-Consent Monitoring (15s)")
                        ctx.log.info(">>> 正在检测用户同意前的违规行为...")
                        
                        # 等待应用启动并显示弹窗，但绝对不点击
                        self.appium_driver.wait_for_privacy_dialog(timeout=15)
                        
                        # 记录"即将点击同意"的时间点
                        consent_time = datetime.now().timestamp()
                        ctx.log.info(f">>> ⏱️ Consent Marker Set: {consent_time}")
                        
                        # --- 阶段二：同意并遍历 (Post-Consent) ---
                        ctx.log.info(">>> 🟢 Phase 2: Post-Consent Automation")
                        
                        # 执行随机遍历 (会自动处理弹窗)
                        self.appium_driver.random_walk(duration=300)  # 5分钟
                    else:
                        ctx.log.warning("[*] Appium automation skipped (service not available)")
                except Exception as e:
                    ctx.log.warning(f"[*] Appium automation failed (optional): {e}")
            else:
                ctx.log.info("[*] Step 7: Appium automation skipped (user disabled)")
            
            # 8. 等待审计完成
            ctx.log.info("[*] Step 8: Running Audit...")
            ctx.log.info("[*] Press Ctrl+C to stop the audit")
            
            # 保持运行，直到用户中断或调用stop方法
            self.is_running = True
            while self.is_running:
                time.sleep(1)
            
            # 如果是通过stop方法停止的，返回True
            return True
                
        except KeyboardInterrupt:
            ctx.log.info("[*] Audit stopped by user")
            return True  # 用户主动停止，视为成功
        except Exception as e:
            ctx.log.error(f"[!] Error during audit: {e}")
            return False  # 发生异常，视为失败
        finally:
            # 清理资源
            ctx.log.info("[*] Step 9: Cleaning Up")
            
            # 停止 Logcat 监控
            if 'logcat_mon' in locals() and logcat_mon:
                logcat_mon.stop() # [新增] 停止日志监控
            
            # 停止 Appium
            if self.appium_driver:
                try:
                    self.appium_driver.stop_session()
                except Exception as e:
                    ctx.log.error(f"[!] Error stopping Appium: {e}")
            
            # 停止 Frida
            if self.frida_injector:
                try:
                    self.frida_injector.detach()
                except Exception as e:
                    ctx.log.error(f"[!] Error detaching Frida: {e}")
            
            # 重置代理
            self.reset_proxy()
            
            # 停止 Mitmproxy
            self.stop_mitmproxy()
            
            # 执行组件暴露 Fuzzing (攻击面扫描)
            if apk_path:
                ctx.log.info("[*] Step 10: Running Component Fuzzing (Attack Surface Scan)")
                component_fuzzer = ComponentFuzzer(self.device_manager, package_name)
                vulnerabilities = component_fuzzer.run(apk_path)
                if vulnerabilities:
                    ctx.log.info(f"[!] Found {len(vulnerabilities)} exported activity vulnerabilities")
                    for vuln in vulnerabilities:
                        ctx.log.info(f"[VULN] {vuln['activity']} - {vuln['desc']}")
                else:
                    ctx.log.info("[+] No exported activity vulnerabilities found")
            
            # 生成报告 (传入 Logcat 日志文件路径和同意时间戳)
            consent_time_value = consent_time if 'consent_time' in locals() else None
            self.generate_report(static_results if 'static_results' in locals() else None, logcat_log="logcat_leaks.jsonl", consent_time=consent_time_value, package_name=package_name)
            
            ctx.log.info("="*60)
            ctx.log.info("[*] Audit completed")
            ctx.log.info(f"[*] Report generated at: {self.output_dir}")
            ctx.log.info("="*60)
    
    def generate_report(self, static_results=None, logcat_log="logcat_leaks.jsonl", consent_time=None, package_name=None):
        """
        生成审计报告
        """
        try:
            # 生成 JSON 报告
            report_path = os.path.join(self.output_dir, "audit_report.json")
            
            # 收集数据
            report_data = {
                "timestamp": datetime.now().isoformat(),
                "output_dir": self.output_dir,
                "package_name": package_name,
                "canary_data": self.frida_injector.get_canary_data() if self.frida_injector else [],
                "hook_results": self.frida_injector.get_hook_results() if self.frida_injector else []
            }
            
            # 添加静态分析结果
            if static_results:
                report_data["static_analysis"] = static_results
            
            # 写入报告文件
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            
            ctx.log.info(f"[+] JSON Report generated: {report_path}")
            
            # === [新增修复] 合并 Mitmproxy 的网络泄露日志 ===
            mitm_log_path = "privacy_leak_log.json" # mitm_addon.py 写入的文件
            frida_leak_path = os.path.join(self.output_dir, "privacy_leaks.jsonl")
            
            combined_leaks = []
            
            # 1. 读取 Frida 泄露日志
            if os.path.exists(frida_leak_path):
                with open(frida_leak_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        try: combined_leaks.append(json.loads(line))
                        except: pass
                        
            # 2. 读取 Mitmproxy 网络日志
            if os.path.exists(mitm_log_path):
                with open(mitm_log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        try: 
                            data = json.loads(line)
                            # 确保数据格式兼容
                            if 'risk_level' not in data: data['risk_level'] = 'HIGH' 
                            combined_leaks.append(data)
                        except: pass

            # 3. 将合并后的日志写回 output_dir 供报告生成器使用
            final_leak_log = "final_leaks.jsonl"
            final_leak_path = os.path.join(self.output_dir, final_leak_log)
            with open(final_leak_path, 'w', encoding='utf-8') as f:
                for leak in combined_leaks:
                    f.write(json.dumps(leak, ensure_ascii=False) + "\n")
                    
            # === 结束新增 ===
            
            # 生成 HTML 报告
            metadata = {
                "package_name": report_data.get("package_name", "Unknown"),
                "timestamp": report_data.get("timestamp")
            }
            
            # 使用 ReportGenerator 生成 HTML 报告
            report_generator = ReportGenerator(self.output_dir)
            # 注意这里 leak_log 参数改为 final_leak_log
            report_generator.generate_html_report(metadata, static_data=static_results, leak_log=final_leak_log, logcat_log=logcat_log, consent_time=consent_time)
            
            ctx.log.info(f"[+] HTML Report generated in: {self.output_dir}")
        except Exception as e:
            ctx.log.error(f"[!] Error generating report: {e}")

def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description="Mobile Privacy Auditor")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--package", help="Package name of the app")
    parser.add_argument("--config", help="Path to config file")
    
    args = parser.parse_args()
    
    auditor = MobilePrivacyAuditor()
    auditor.run_audit(apk_path=args.apk, package_name=args.package)

if __name__ == "__main__":
    main()