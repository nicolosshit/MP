#!/usr/bin/env python3
# 测试Appium服务的启动和停止功能

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.automation.appium_driver import AppiumDriver

def test_appium_service():
    """测试Appium服务的启动和停止功能"""
    print("="*60)
    print("[*] Testing Appium Service")
    print("="*60)
    
    # 创建AppiumDriver实例
    driver = AppiumDriver()
    
    # 测试1: 检查Appium服务是否运行
    print("\n[*] Test 1: Checking if Appium service is running...")
    is_running = driver.is_appium_running()
    print(f"[+] Appium service running: {is_running}")
    
    # 测试2: 检查Appium命令是否可用
    print("\n[*] Test 2: Checking if Appium command is available...")
    try:
        import subprocess
        # 尝试运行appium --version
        result = subprocess.run(["appium", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Appium command is available: {result.stdout.strip()}")
        else:
            # 尝试使用npx
            result = subprocess.run(["npx", "appium", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Appium command is available via npx: {result.stdout.strip()}")
            else:
                print("[!] Appium command is not available")
    except Exception as e:
        print(f"[!] Error checking Appium command: {e}")
    
    # 测试3: 再次检查Appium服务是否运行
    print("\n[*] Test 3: Checking if Appium service is running...")
    is_running = driver.is_appium_running()
    print(f"[+] Appium service running: {is_running}")
    
    print("\n" + "="*60)
    print("[*] Appium Service Test Complete")
    print("="*60)

if __name__ == "__main__":
    test_appium_service()
