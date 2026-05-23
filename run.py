#!/usr/bin/env python3
# 综合启动程序

import os
import sys
import argparse
import subprocess
import importlib

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def check_dependencies():
    """检查依赖项"""
    print("[*] 检查依赖项...")
    
    # 检查关键依赖项
    critical_packages = [
        "frida",
        "mitmproxy",
        "requests"
    ]
    
    missing_packages = []
    for package in critical_packages:
        try:
            # 尝试导入包
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"[ERROR] 缺少以下关键依赖项: {', '.join(missing_packages)}")
        print("[INFO] 请运行: pip install -r requirements.txt")
        return False
    
    # 检查 ADB 是否可用（使用 device_manager.py 中的 ADB 路径）
    try:
        from src.automation.device_manager import DeviceManager
        device_manager = DeviceManager()
        # 直接使用 device_manager 中的 ADB 路径
        adb_path = device_manager.adb_path
        result = subprocess.run([adb_path, "version"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] ADB 不可用，请确保已安装 Android SDK 并正确配置 ADB 路径")
            return False
        else:
            print("[INFO] ADB 已就绪")
    except Exception as e:
        print(f"[ERROR] ADB 检查失败: {e}")
        return False
    
    # 检查 Frida 服务器是否可访问（可选）
    try:
        result = subprocess.run(["frida", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("[INFO] Frida 已就绪")
        else:
            print("[WARN] Frida 命令行工具不可用，但核心功能可能仍可正常工作")
    except FileNotFoundError:
        print("[WARN] Frida 命令行工具未找到，但核心功能可能仍可正常工作")
    
    print("[INFO] 所有依赖项检查完成")
    return True

def start_command_line(args):
    """启动命令行模式"""
    print("[*] 启动命令行模式...")
    
    try:
        from src.main import main as main_cli
        # 构造命令行参数
        cli_args = []
        if args.apk:
            cli_args.extend(["--apk", args.apk])
        if args.package:
            cli_args.extend(["--package", args.package])
        if args.config:
            cli_args.extend(["--config", args.config])
        
        # 调用主程序
        sys.argv = ["main.py"] + cli_args
        main_cli()
    except Exception as e:
        print(f"[ERROR] 启动命令行模式失败: {e}")
        import traceback
        traceback.print_exc()

def start_gui():
    """启动 GUI 模式"""
    print("[*] 启动 GUI 模式...")
    
    try:
        from gui.app import main as main_gui
        try:
            main_gui()
        except KeyboardInterrupt:
            print("\n[*] 用户中断了程序")
            print("[*] 正在清理资源...")
            print("[*] 程序已退出")
    except ImportError as e:
        print(f"[ERROR] 导入 GUI 模块失败: {e}")
        print("[INFO] 请确保 GUI 目录存在且包含 app.py 文件")
    except Exception as e:
        print(f"[ERROR] 启动 GUI 模式失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主函数"""
    try:
        # 创建参数解析器
        parser = argparse.ArgumentParser(
            description="移动应用隐私审计系统启动程序",
            formatter_class=argparse.RawTextHelpFormatter
        )
        
        # 模式选择
        parser.add_argument(
            "--mode", 
            choices=["cli", "gui"],
            default="gui",
            help="启动模式: cli (命令行) 或 gui (图形界面)"
        )
        
        # 命令行模式参数
        parser.add_argument(
            "--apk", 
            help="APK 文件路径"
        )
        
        parser.add_argument(
            "--package", 
            help="应用包名"
        )
        
        parser.add_argument(
            "--config", 
            help="配置文件路径"
        )
        
        parser.add_argument(
            "--skip-deps", 
            action="store_true",
            help="跳过依赖项检查"
        )
        
        # 解析参数
        args = parser.parse_args()
        
        # 打印欢迎信息
        print("=" * 60)
        print("移动应用隐私审计系统")
        print("=" * 60)
        print("功能: 检测移动应用的隐私数据泄露行为")
        print("使用方法:")
        print("  命令行模式: python run.py --mode cli --apk <apk_path> --package <package_name>")
        print("  GUI 模式: python run.py --mode gui")
        print("=" * 60)
        
        # 检查依赖项
        if not args.skip_deps:
            if not check_dependencies():
                print("[ERROR] 依赖项检查失败，无法启动")
                return
        
        # 启动相应模式
        if args.mode == "cli":
            start_command_line(args)
        else:
            start_gui()
    except KeyboardInterrupt:
        print("\n[*] 用户中断了程序")
        print("[*] 正在清理资源...")
        # 这里可以添加更多的清理操作，如停止正在运行的进程等
        print("[*] 程序已优雅退出")
    except Exception as e:
        print(f"[!] 错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
