#!/usr/bin/env python3
# UI 自动化控制逻辑 - 增强版

import os
import time
import random
import json
import subprocess
import socket
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common.exceptions import NoSuchElementException
from appium.options.android import UiAutomator2Options

class AppiumDriver:
    def __init__(self, app_package=None, app_activity=None):
        self.driver = None
        self.app_package = app_package
        self.app_activity = app_activity
        self.appium_caps = self.load_appium_caps()
        self.session_start_time = None
        self.appium_process = None
        
        # 扩展的自动点击关键词
        self.auto_accept_keywords = [
            "允许", "Allow", "同意", "Agree", "确定", "OK", 
            "仅使用期间允许", "While using the app", "始终允许", "Always allow",
            "跳过", "Skip", "我知道了", "I know", "下一步", "Next", "完成", "Done"
        ]
        self.auto_deny_keywords = [
            "取消", "Cancel", "以后再说", "Later", "不更新", "Not now", "拒绝", "Deny"
        ]
        
        # 敏感功能关键词 (用于主动诱导)
        self.sensitive_keywords = [
            "扫一扫", "Scan", "相机", "Camera", "相册", "Album", "Gallery",
            "位置", "Location", "地图", "Map", "通讯录", "Contacts",
            "我的", "Me", "Profile", "设置", "Settings"
        ]

    def load_appium_caps(self):
        caps_file = os.path.join("config", "appium_caps.json")
        try:
            with open(caps_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {
                "platformName": "Android",
                "automationName": "UiAutomator2",
                "deviceName": "Android Device",
                "noReset": True,
                "newCommandTimeout": 600
            }
    
    def is_appium_running(self, port=4723):
        """检查Appium服务是否在运行"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(("localhost", port))
            sock.close()
            return result == 0
        except:
            return False
    
    def start_appium_service(self):
        """启动Appium服务"""
        if self.is_appium_running():
            print("[+] Appium service is already running")
            return True
        
        # 尝试启动Appium服务
        try:
            print("[*] Starting Appium service...")
            # 启动Appium服务，使用--log参数指定日志文件
            log_file = os.path.join("data", "logs", "appium.log")
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            # 尝试使用直接命令启动Appium服务
            appium_command = None
            
            # 首先尝试直接使用appium命令
            try:
                subprocess.run(["appium", "--version"], capture_output=True, check=True)
                appium_command = ["appium", "--log", log_file]
                print("[+] Using direct appium command")
            except (subprocess.SubprocessError, FileNotFoundError):
                # 如果直接命令失败，尝试使用npx
                try:
                    subprocess.run(["npx", "appium", "--version"], capture_output=True, check=True)
                    appium_command = ["npx", "appium", "--log", log_file]
                    print("[+] Using npx appium command")
                except (subprocess.SubprocessError, FileNotFoundError):
                    print("[!] Appium command not found in system path")
                    print("[!] Appium service is not running")
                    print("[!] Please start Appium service manually using: appium")
                    return False
            
            # 启动Appium服务进程
            self.appium_process = subprocess.Popen(
                appium_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # 等待服务启动
            print("[*] Waiting for Appium service to start...")
            for _ in range(30):  # 最多等待30秒
                if self.is_appium_running():
                    print("[+] Appium service started successfully")
                    return True
                time.sleep(1)
            
            print("[!] Appium service failed to start within timeout")
            self.stop_appium_service()
            return False
        except Exception as e:
            print(f"[!] Error starting Appium service: {e}")
            self.stop_appium_service()
            return False
    
    def stop_appium_service(self):
        """停止Appium服务"""
        if self.appium_process:
            try:
                self.appium_process.terminate()
                self.appium_process.wait(timeout=5)
                print("[+] Appium service stopped")
            except Exception as e:
                print(f"[!] Error stopping Appium service: {e}")
            finally:
                self.appium_process = None
    
    def start_session(self):
        try:
            # 检查Appium服务是否已经在运行
            if not self.is_appium_running():
                # 如果服务未运行，尝试启动
                if not self.start_appium_service():
                    print("[!] Failed to start Appium service")
                    return False
            else:
                print("[+] Using existing Appium service")
            
            print("[*] Starting Appium session...")
            # 强制开启自动授权
            self.appium_caps["autoGrantPermissions"] = True
            
            # 如果提供了包名和Activity，使用它们
            if self.app_package:
                self.appium_caps["appPackage"] = self.app_package
                if self.app_activity:
                    self.appium_caps["appActivity"] = self.app_activity
                else:
                    # 如果没有提供Activity，尝试使用默认的启动Activity
                    self.appium_caps["appActivity"] = self.app_package + ".MainActivity"
                    print(f"[*] Using default activity: {self.appium_caps['appActivity']}")
            
            # 🟢 新代码（去掉 /wd/hub）：
            options = UiAutomator2Options().load_capabilities(self.appium_caps)
            self.driver = webdriver.Remote("http://localhost:4723", options=options)
            self.session_start_time = time.time()
            print("[+] Appium session started successfully")
            return True
        except Exception as e:
            print(f"[!] Error starting Appium session: {e}")
            return False
    
    def handle_system_dialogs(self):
        """处理系统弹窗和常见干扰"""
        try:
            # 查找标准对话框按钮
            buttons = self.driver.find_elements(AppiumBy.CLASS_NAME, "android.widget.Button")
            for btn in buttons:
                text = btn.text
                if any(k in text for k in self.auto_accept_keywords):
                    print(f"[*] 自动同意/跳过: {text}")
                    btn.click()
                    return True
                elif any(k in text for k in self.auto_deny_keywords):
                    print(f"[*] 自动拒绝/关闭: {text}")
                    btn.click()
                    return True
            
            # 处理一些非 Button 类型的点击项 (TextView)
            text_views = self.driver.find_elements(AppiumBy.CLASS_NAME, "android.widget.TextView")
            for tv in text_views:
                text = tv.text
                if text in ["跳过", "Skip", "关闭", "Close"]:
                    print(f"[*] 自动点击文本按钮: {text}")
                    tv.click()
                    return True
        except:
            pass
        return False
    
    def stop_session(self):
        if self.driver:
            try:
                self.driver.quit()
                print("[+] Appium session stopped")
            except: pass
        
        # 停止Appium服务
        self.stop_appium_service()
    
    def random_walk(self, duration=300):
        """智能随机遍历"""
        if not self.driver: return
        
        end_time = time.time() + duration
        actions_count = 0
        print(f"[*] Starting smart UI walk for {duration} seconds")
        
        while time.time() < end_time:
            try:
                # 1. 优先处理弹窗
                if self.handle_system_dialogs():
                    time.sleep(1)
                    continue
                
                # 2. 获取元素
                elements = self._get_clickable_elements()
                
                if elements:
                    # 3. 智能选择：优先点击包含敏感关键词的元素 (诱导权限)
                    target_element = None
                    random.shuffle(elements) # 先打乱
                    
                    for elem in elements:
                        try:
                            text = elem.text or elem.get_attribute("content-desc") or ""
                            if any(k in text for k in self.sensitive_keywords):
                                print(f"[*] Found sensitive target: {text}, clicking to induce permission...")
                                target_element = elem
                                break
                        except: pass
                    
                    # 如果没找到敏感元素，随机选一个
                    if not target_element:
                        target_element = random.choice(elements)
                    
                    self._safe_click(target_element)
                    actions_count += 1
                    time.sleep(random.uniform(1.0, 3.0))
                else:
                    # 4. 没元素时随机滑动
                    self.swipe(random.choice(["up", "down", "left", "right"]))
                    time.sleep(1.0)
                    
            except Exception as e:
                print(f"[!] Walk error: {e}")
                self._safe_back()
    
    def _get_clickable_elements(self):
        try:
            return self.driver.find_elements(AppiumBy.XPATH, "//*[@clickable='true' or @enabled='true']")
        except: return []
    
    def _safe_click(self, element):
        try:
            element.click()
        except: pass
    
    def _safe_back(self):
        try:
            self.driver.back()
        except: pass
    
    def swipe(self, direction="up"):
        try:
            size = self.driver.get_window_size()
            w, h = size['width'], size['height']
            if direction == "up":
                self.driver.swipe(w/2, h*0.75, w/2, h*0.25, 500)
            elif direction == "down":
                self.driver.swipe(w/2, h*0.25, w/2, h*0.75, 500)
            elif direction == "left":
                self.driver.swipe(w*0.8, h/2, w*0.2, h/2, 500)
            elif direction == "right":
                self.driver.swipe(w*0.2, h/2, w*0.8, h/2, 500)
        except: pass

    # 简单的登录场景尝试 (可根据具体 APP 定制)
    def login_scenario(self):
        print("[*] Attempting basic login scenario...")
        # 查找常见的登录输入框 ID
        user_fields = ["username", "account", "mobile", "phone", "email"]
        pwd_fields = ["password", "pwd", "code"]
        
        # 此处逻辑需根据具体 APP 调整，这里仅作演示
        self.fill_form({"phone": "13800138000", "password": "Password123"})
    
    def fill_form(self, form_data):
        """填充表单数据（简单实现）"""
        try:
            # 遍历表单数据
            for field_name, value in form_data.items():
                # 尝试通过 ID 查找元素
                try:
                    element = self.driver.find_element(AppiumBy.ID, f"{field_name}")
                    element.clear()
                    element.send_keys(value)
                    print(f"[*] Filled {field_name} with {value}")
                except:
                    # 尝试通过 XPath 查找包含该字段名的元素
                    try:
                        elements = self.driver.find_elements(AppiumBy.XPATH, f"//*[contains(@text, '{field_name}') or contains(@content-desc, '{field_name}')]")
                        for elem in elements:
                            if elem.is_displayed() and elem.is_enabled():
                                elem.clear()
                                elem.send_keys(value)
                                print(f"[*] Filled {field_name} with {value}")
                                break
                    except:
                        pass
        except Exception as e:
            print(f"[!] Error filling form: {e}")
    
    def wait_for_privacy_dialog(self, timeout=10):
        """仅等待隐私弹窗出现 (不点击)"""
        print(f"[*] Waiting {timeout}s for privacy dialog (Pre-consent check)...")
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                # 检查是否存在常见的"同意"按钮，作为应用已完全启动的标志
                source = self.driver.page_source
                if any(k in source for k in ["同意", "Agree", "Accept", "进入", "Enter"]):
                    print("[*] Privacy dialog detected.")
                    return True
            except: pass
            time.sleep(1)
        print("[*] Pre-consent wait finished.")
        return False
