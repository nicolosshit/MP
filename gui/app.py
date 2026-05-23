#!/usr/bin/env python3
# GUI 主应用 - 现代化美化版

import os
import sys
import threading
import queue
import time
import customtkinter as ctk  # 引入现代化 UI 库
from tkinter import filedialog, messagebox

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.automation.device_manager import DeviceManager
from src.main import MobilePrivacyAuditor

# 设置外观模式和默认颜色主题
ctk.set_appearance_mode("Dark")  # 模式: "System" (默认), "Dark", "Light"
ctk.set_default_color_theme("dark-blue")  # 主题: "blue" (默认), "green", "dark-blue"

class PrivacyAuditGUI(ctk.CTk):
    """隐私审计系统 GUI - 现代化版本"""
    
    def __init__(self):
        super().__init__()

        # 1. 基础窗口设置
        self.title("移动应用隐私审计系统 Pro")
        self.geometry("1100x700")
        
        # 配置网格布局 (1x2)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 初始化逻辑组件
        self.log_queue = queue.Queue()
        self.device_manager = DeviceManager()
        self.auditor = None
        self.audit_thread = None
        self.is_auditing = False
        self.is_preparing_env = False

        # 2. 创建 UI 组件
        self.create_sidebar()
        self.create_main_area()

        # 3. 启动后台任务
        self.start_log_thread()
        self.after(1000, self.refresh_devices)  # 启动后1秒自动刷新设备
        self.after(2000, self.prepare_environment)  # 启动后2秒自动准备环境

    def create_sidebar(self):
        """创建左侧侧边栏 (配置区)"""
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)  # 让底部留空

        # 标题
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ 隐私审计系统", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # --- 设备选择 ---
        self.device_label = ctk.CTkLabel(self.sidebar_frame, text="目标设备:", anchor="w")
        self.device_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.device_combo = ctk.CTkOptionMenu(self.sidebar_frame, dynamic_resizing=False, values=["正在扫描..."])
        self.device_combo.grid(row=2, column=0, padx=20, pady=(5, 10), sticky="ew")
        
        self.refresh_btn = ctk.CTkButton(self.sidebar_frame, text="🔄 刷新设备列表", command=self.refresh_devices, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.refresh_btn.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")

        # --- 应用配置 ---
        self.app_label = ctk.CTkLabel(self.sidebar_frame, text="应用配置:", anchor="w", font=ctk.CTkFont(weight="bold"))
        self.app_label.grid(row=4, column=0, padx=20, pady=(10, 0), sticky="w")

        # APK 路径选择
        self.apk_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.apk_frame.grid(row=5, column=0, padx=20, pady=(5, 5), sticky="ew")
        
        self.apk_entry = ctk.CTkEntry(self.apk_frame, placeholder_text="选择 APK 文件路径...")
        self.apk_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.browse_btn = ctk.CTkButton(self.apk_frame, text="📂", width=40, command=self.browse_apk)
        self.browse_btn.pack(side="right")

        # 包名输入
        self.pkg_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="输入包名 (例如 com.example.app)")
        self.pkg_entry.grid(row=6, column=0, padx=20, pady=(5, 10), sticky="ew")

        # Appium 功能选择
        self.appium_var = ctk.BooleanVar(value=True)
        self.appium_checkbox = ctk.CTkCheckBox(self.sidebar_frame, text="运行 Appium 自动化测试", variable=self.appium_var)
        self.appium_checkbox.grid(row=7, column=0, padx=20, pady=(5, 10), sticky="w")

        # --- 审计控制 ---
        self.start_btn = ctk.CTkButton(self.sidebar_frame, text="▶ 开始审计", command=self.start_audit, fg_color="#2CC985", hover_color="#229A65", text_color="white", font=ctk.CTkFont(size=16, weight="bold"), height=40)
        self.start_btn.grid(row=8, column=0, padx=20, pady=10, sticky="ew")

        self.stop_btn = ctk.CTkButton(self.sidebar_frame, text="⏹ 停止审计", command=self.stop_audit, state="disabled", fg_color="#E04F5F", hover_color="#B33A46")
        self.stop_btn.grid(row=9, column=0, padx=20, pady=(0, 20), sticky="nEW")

        # --- 底部 ---
        self.report_btn = ctk.CTkButton(self.sidebar_frame, text="📄 查看最近报告", command=self.view_reports, fg_color="transparent", border_width=1)
        self.report_btn.grid(row=10, column=0, padx=20, pady=(0, 10), sticky="ew")
        
        # 版本号
        self.version_label = ctk.CTkLabel(self.sidebar_frame, text="v1.0.0 Alpha", text_color="gray50")
        self.version_label.grid(row=11, column=0, padx=20, pady=10)

    def create_main_area(self):
        """创建右侧主区域 (日志终端)"""
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # 状态栏头部
        self.header_frame = ctk.CTkFrame(self.main_frame, height=50, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(self.header_frame, text="系统就绪", font=ctk.CTkFont(size=16), anchor="w")
        self.status_label.pack(side="left")
        
        self.clear_log_btn = ctk.CTkButton(self.header_frame, text="清除日志", width=80, height=24, command=self.clear_logs, fg_color="gray", hover_color="gray30")
        self.clear_log_btn.pack(side="right")

        # 日志终端窗口
        self.log_textbox = ctk.CTkTextbox(self.main_frame, font=("Consolas", 14), activate_scrollbars=True)
        self.log_textbox.grid(row=1, column=0, sticky="nsew")
        
        # 初始化欢迎语
        self.log("=== 移动应用隐私审计系统已启动 ===", "info")
        self.log("请在左侧选择设备并配置 APK...", "info")

    def prepare_environment(self):
        """准备环境（包括启动模拟器）"""
        if self.is_preparing_env:
            return
        
        self.is_preparing_env = True
        self.log("开始准备环境...", "info")
        
        # 启动环境准备线程
        self.env_prep_thread = threading.Thread(target=self._do_prepare_environment)
        self.env_prep_thread.daemon = True
        self.env_prep_thread.start()

    def _do_prepare_environment(self):
        """实际执行环境准备的方法"""
        try:
            # 创建审计器实例
            auditor = MobilePrivacyAuditor()
            
            # 准备环境
            success = auditor.prepare_environment()
            
            if success:
                self.log("环境准备完成", "success")
            else:
                self.log("环境准备失败", "error")
            
            # 刷新设备列表
            self.after(0, self.refresh_devices)
        except Exception as e:
            self.log(f"环境准备过程中发生错误: {e}", "error")
        finally:
            self.is_preparing_env = False

    # --- 业务逻辑 (保持原有逻辑框架，适配新UI组件) ---

    def refresh_devices(self):
        """刷新设备列表"""
        self.log("正在扫描设备...", "info")
        try:
            # 这里调用真实的 DeviceManager
            code, stdout, stderr = self.device_manager.run_adb_command("devices")
            devices = []
            if code == 0:
                for line in stdout.strip().split('\n')[1:]:
                    if line.strip() and "device" in line:
                        devices.append(line.split('\t')[0])
            
            if devices:
                self.device_combo.configure(values=devices)
                self.device_combo.set(devices[0])
                self.log(f"发现 {len(devices)} 台设备", "success")
            else:
                self.device_combo.configure(values=["未检测到设备"])
                self.device_combo.set("未检测到设备")
                self.log("未检测到在线设备，请检查连接或启动模拟器", "warn")
        except Exception as e:
            self.log(f"设备扫描出错: {e}", "error")

    def browse_apk(self):
        file_path = filedialog.askopenfilename(filetypes=[("APK 文件", "*.apk")])
        if file_path:
            self.apk_entry.delete(0, "end")
            self.apk_entry.insert(0, file_path)
            # 尝试自动提取包名 (简单文件名处理)
            filename = os.path.basename(file_path)
            if "_" in filename:  # 假设文件名类似于 com.app_v1.apk
                pkg = filename.split("_")[0] 
                if "." in pkg:
                    self.pkg_entry.delete(0, "end")
                    self.pkg_entry.insert(0, pkg)

    def start_audit(self):
        device = self.device_combo.get()
        apk = self.apk_entry.get()
        pkg = self.pkg_entry.get()

        if "未检测" in device or not device:
            messagebox.showerror("错误", "请先连接有效设备")
            return
        if not pkg and not apk:
            messagebox.showerror("错误", "必须提供 APK 路径或包名")
            return

        self.is_auditing = True
        self.update_ui_state(auditing=True)
        self.status_label.configure(text=f"正在审计: {pkg}...", text_color="#2CC985")
        
        self.log_textbox.delete("1.0", "end")  # 清空日志
        self.log("开始审计流程...", "info")
        
        # 启动线程
        self.audit_thread = threading.Thread(target=self.run_audit_thread, args=(apk, pkg, device, self.appium_var.get()))
        self.audit_thread.daemon = True
        self.audit_thread.start()

    def run_audit_thread(self, apk, pkg, device, run_appium):
        """线程内部运行逻辑"""
        try:
            # 创建审计器实例
            auditor = MobilePrivacyAuditor()
            self.auditor = auditor
            
            # 运行审计
            success = auditor.run_audit(apk_path=apk, package_name=pkg, run_appium=run_appium)
            
            if success:
                self.log("审计流程结束，报告已生成。", "success")
            else:
                self.log("审计流程失败。", "error")
            
        except Exception as e:
            self.log(f"审计异常: {e}", "error")
        finally:
            self.is_auditing = False
            self.after(0, lambda: self.update_ui_state(auditing=False))
            self.after(0, lambda: self.status_label.configure(text="审计结束", text_color="gray"))

    def stop_audit(self):
        if self.is_auditing:
            self.log("正在发送停止信号...", "warn")
            # 调用 auditor.stop() 停止审计过程
            if hasattr(self, 'auditor') and self.auditor:
                try:
                    self.auditor.stop()
                    self.log("停止信号已发送，正在清理资源...", "info")
                except Exception as e:
                    self.log(f"停止审计时发生错误: {e}", "error")
            self.is_auditing = False

    def update_ui_state(self, auditing):
        if auditing:
            self.start_btn.configure(state="disabled", text="审计进行中...")
            self.stop_btn.configure(state="normal")
            self.apk_entry.configure(state="disabled")
            self.pkg_entry.configure(state="disabled")
        else:
            self.start_btn.configure(state="normal", text="▶ 开始审计")
            self.stop_btn.configure(state="disabled")
            self.apk_entry.configure(state="normal")
            self.pkg_entry.configure(state="normal")

    def view_reports(self):
        report_dir = os.path.join("data", "reports")
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        try:
            os.startfile(report_dir) if sys.platform == "win32" else os.system(f"open {report_dir}")
        except:
            messagebox.showinfo("路径", f"报告目录: {report_dir}")

    def clear_logs(self):
        self.log_textbox.delete("1.0", "end")

    # --- 日志系统 ---
    def log(self, message, level="info"):
        self.log_queue.put((message, level))

    def start_log_thread(self):
        self.after(100, self.process_log_queue)

    def process_log_queue(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                timestamp = time.strftime("[%H:%M:%S]")
                
                # 定义颜色标签
                tag = "INFO"
                color = "white"
                if level == "success": color = "#2CC985"
                elif level == "warn": color = "orange"
                elif level == "error": color = "#E04F5F"
                
                # 插入带颜色的文本
                self.log_textbox.insert("end", f"{timestamp} ", "timestamp")
                self.log_textbox.insert("end", f"[{level.upper()}] {msg}\n", level)
                
                # 配置 Tag 样式
                self.log_textbox.tag_config("timestamp", foreground="gray50")
                self.log_textbox.tag_config(level, foreground=color)
                
                self.log_textbox.see("end")
        except queue.Empty:
            pass
        self.after(100, self.process_log_queue)

def main():
    """主函数，供 start_gui.py 调用"""
    app = PrivacyAuditGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
