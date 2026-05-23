#!/usr/bin/env python3
# 启动 GUI 应用

import os
import sys

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    # 导入并运行 GUI 应用
    from gui.app import main
    main()
except ImportError as e:
    print(f"导入错误: {e}")
    print("请确保已安装所有依赖项")
    print("运行: pip install -r requirements.txt")
except Exception as e:
    print(f"启动错误: {e}")
    import traceback
    traceback.print_exc()
