#!/usr/bin/env python3
# 隐私审计系统测试脚本

import os
import sys
import unittest
import tempfile
from unittest.mock import Mock, patch

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.automation.device_manager import DeviceManager
from src.instrumentation.frida_injector import FridaInjector
from src.network.mitm_addon import PrivacyAuditAddon

class TestDeviceManager(unittest.TestCase):
    """测试设备管理器"""
    
    def setUp(self):
        self.device_manager = DeviceManager()
    
    def test_run_adb_command(self):
        """测试运行 ADB 命令"""
        # 测试获取设备 ID 命令
        code, stdout, stderr = self.device_manager.run_adb_command("devices")
        self.assertEqual(code, 0)
        self.assertIn("List of devices attached", stdout)
    
    def test_get_device_id(self):
        """测试获取设备 ID"""
        device_id = self.device_manager.get_device_id()
        # 这里不断言具体值，因为可能没有设备连接
        print(f"[*] Device ID: {device_id}")

class TestFridaInjector(unittest.TestCase):
    """测试 Frida 注入器"""
    
    def setUp(self):
        self.injector = FridaInjector()
    
    def test_load_hook_script(self):
        """测试加载 Hook 脚本"""
        script = self.injector.load_hook_script()
        self.assertIsInstance(script, str)
        self.assertGreater(len(script), 0)
    
    def test_attach_to_process(self):
        """测试附加到进程"""
        # 这里不实际运行，因为需要目标进程
        print("[*] Frida injector initialized")

class TestMitmAddon(unittest.TestCase):
    """测试 Mitmproxy 插件"""
    
    def setUp(self):
        # 创建一个临时的 canary 文件
        self.temp_dir = tempfile.TemporaryDirectory()
        self.canary_file = os.path.join(self.temp_dir.name, "canary_values.json")
        
        # 写入测试金丝雀值
        import json
        with open(self.canary_file, "w") as f:
            json.dump(["test_canary_123"], f)
        
        # 创建插件实例
        self.addon = PrivacyAuditAddon()
        self.addon.canary_values = ["test_canary_123"]
    
    def tearDown(self):
        self.temp_dir.cleanup()
    
    def test_search_canary_values(self):
        """测试搜索金丝雀值"""
        text = "This is a test with test_canary_123"
        found_canaries = self.addon.search_canary_values(text)
        self.assertEqual(len(found_canaries), 1)
        self.assertEqual(found_canaries[0], "test_canary_123")
    
    def test_search_sensitive_data(self):
        """测试搜索敏感数据"""
        text = "Phone: 13800138000, Email: test@example.com"
        sensitive_data = self.addon.search_sensitive_data(text)
        self.assertIn("phone", sensitive_data)
        self.assertIn("email", sensitive_data)
    
    def test_luhn_check(self):
        """测试 Luhn 算法"""
        # 有效的信用卡号
        valid_cc = "4111111111111111"
        self.assertTrue(self.addon.luhn_check(valid_cc))
        
        # 无效的信用卡号
        invalid_cc = "4111111111111112"
        self.assertFalse(self.addon.luhn_check(invalid_cc))

if __name__ == '__main__':
    unittest.main()
