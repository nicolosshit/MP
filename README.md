# **移动应用隐私审计系统**

一个强大的移动应用隐私合规审计工具，集成静态分析、动态Hook、网络监控、UI自动化和日志分析，为移动应用提供全方位的隐私安全评估，特别支持PIPL（个人信息保护法）合规检测。

## 📋 项目简介

移动隐私审计器是一款专为移动应用开发者、安全研究人员和隐私合规审计人员设计的工具，旨在帮助识别和评估移动应用中的隐私数据泄露风险。通过自动化的审计流程，该工具能够快速发现应用中的隐私安全问题，并生成详细的审计报告，包括风险评分和可视化数据流向图谱。

## ✨ 功能特性

### 1. 静态分析
- **权限分析**：提取并分析应用申请的所有权限
- **元数据提取**：获取应用的包名、版本等基本信息
- **硬编码密钥扫描**：检测应用中硬编码的API密钥、Token等敏感信息

### 2. 动态分析
- **Frida Hook**：拦截并监控应用对隐私数据的访问
- **金丝雀注入**：向应用注入标记数据，追踪数据流向
- **SSL Pinning 绕过**：自动绕过应用的SSL证书固定，确保网络流量可被监控

### 3. 网络监控
- **Mitmproxy 集成**：拦截并分析应用的所有网络请求
- **数据泄露检测**：识别网络传输中的隐私数据泄露
- **关联分析**：将网络请求与数据来源关联，提供完整的数据流追踪

### 4. UI自动化
- **Appium 集成**：自动启动应用并执行随机UI遍历
- **系统弹窗处理**：自动处理权限请求等系统弹窗
- **会话管理**：自动管理Appium会话的启动和停止
- **PIPL 合规检测**：监控用户同意前/后应用的行为，检测违规数据收集

### 5. Logcat监控
- **实时日志分析**：监控应用的系统日志
- **敏感信息检测**：识别日志中的Token、手机号、邮箱等敏感信息
- **日志泄露报告**：在审计报告中展示发现的日志泄露

### 6. 组件暴露Fuzzing
- **攻击面扫描**：检测应用中可被外部调用的组件
- **安全风险评估**：识别潜在的组件暴露漏洞

### 7. 报告生成
- **隐私安全评分**：基于发现的问题计算0-100的安全评分
- **HTML 报告**：生成包含详细信息的交互式HTML报告
- **数据流向可视化**：使用ECharts生成数据流向图谱，支持显示Logcat中的敏感信息
- **风险分布统计**：展示不同风险等级的问题分布
- **PIPL 违规标记**：标记用户同意前的违规数据收集行为

## 🛠️ 系统要求

### 软件依赖
- Python 3.7+
- Android SDK (包括adb)
- Frida 16.0+ (包括frida-server)
- Appium 2.0+
- Mitmproxy 9.0+
- Node.js (用于运行Appium)

### 硬件要求
- 至少 4GB RAM
- 至少 10GB 可用磁盘空间
- Android 7.0+ 设备或模拟器

### 网络要求
- 可访问互联网（用于下载依赖和更新）
- 局域网连接（用于设备与主机通信）

## 📦 安装步骤

### 1. 克隆项目
```bash
git clone https://github.com/yourusername/mobile-privacy-auditor.git
cd mobile-privacy-auditor
```

### 2. 安装Python依赖
```bash
pip install -r requirements.txt
```

### 3. 配置Android环境
- 安装Android SDK并配置环境变量
- 确保adb命令可在终端中执行
- 配置至少一个Android模拟器（推荐使用API 28+）

### 4. 安装Frida
```bash
pip install frida-tools
# 下载对应设备架构的frida-server并推送到设备
# 例如：adb push frida-server-16.0.0-android-arm64 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
```

### 5. 安装Appium
```bash
npm install -g appium
# 安装UIAutomator2驱动
appium driver install uiautomator2
```

### 6. 安装Mitmproxy
```bash
pip install mitmproxy
```

## 🚀 使用方法

### 基本用法
```bash
# 运行完整审计（使用APK文件）
python src/main.py --apk path/to/your/app.apk

# 运行完整审计（使用包名）
python src/main.py --package com.example.app
```

### 可选参数
- `--apk`：APK文件路径
- `--package`：应用包名
- `--config`：配置文件路径（可选）

### 示例
```bash
# 审计示例应用
python src/main.py --apk samples/test_app.apk

# 审计已安装的应用
python src/main.py --package com.android.settings
```

### 审计流程
1. **环境准备**：启动模拟器（如果需要），确保设备在线，恢复Root和Remount
2. **设备准备**：检测并连接Android设备
3. **静态分析**：分析APK文件，提取权限和元数据
4. **启动服务**：启动Mitmproxy（使用8080端口，添加`--set block_global=false`参数）、设置设备代理
5. **动态注入**：使用Frida注入Hook脚本（支持spawn和attach模式，包含三级重试机制）
6. **日志监控**：启动Logcat监控，捕获敏感信息
7. **UI自动化**：使用Appium执行PIPL合规检测（同意前/后行为监控）
8. **网络监控**：拦截并分析网络请求
9. **组件Fuzzing**：检测应用的攻击面和潜在漏洞
10. **生成报告**：停止服务并生成审计报告

### 代理设置说明
- 默认使用8080端口作为Mitmproxy监听端口
- 设备代理自动设置为`10.0.2.2:8080`（Android模拟器访问主机的特殊IP）
- 代理设置已优化，直接设置代理而不清除网络服务，提高连接稳定性

## 📁 项目结构

```
mobile-privacy-auditor/
├── src/                  # 源代码目录
│   ├── analysis/         # 分析模块
│   │   ├── static_analyzer.py    # 静态分析器
│   │   ├── logcat_monitor.py     # Logcat监控器
│   │   ├── component_fuzzer.py   # 组件暴露Fuzzer
│   │   └── trace_analyzer.py     # 堆栈追踪分析器
│   ├── automation/       # 自动化模块
│   │   ├── device_manager.py     # 设备管理器
│   │   └── appium_driver.py       # Appium驱动
│   ├── instrumentation/  # 插桩模块
│   │   ├── frida_injector.py     # Frida注入器
│   │   └── ssl_unpinning.js      # SSL Pinning绕过脚本
│   ├── network/          # 网络模块
│   │   └── mitm_addon.py          # Mitmproxy插件
│   ├── reporting/        # 报告模块
│   │   └── report_generator.py    # 报告生成器
│   └── main.py           # 主程序入口
├── config/               # 配置文件目录
│   ├── frida_hooks.js    # Frida Hook脚本
│   ├── appium_caps.json  # Appium 配置
│   └── mitmproxy_config.yaml # Mitmproxy配置
├── data/                 # 数据目录
│   └── reports/          # 报告存储目录
├── tests/                # 测试目录
├── requirements.txt      # Python依赖
├── run.py                # 快捷运行脚本
└── README.md             # 项目说明文档
```

## 🔧 配置说明

### Frida Hook 配置
编辑 `config/frida_hooks.js` 文件，添加或修改Hook点，以监控特定的API调用。

### Appium 配置
编辑 `config/appium_caps.json` 文件，配置Appium的启动参数，如设备名称、平台版本等。

### Mitmproxy 配置
编辑 `config/mitmproxy_config.yaml` 文件，配置Mitmproxy的行为，如端口、证书等。

## 📱 设备准备

### 使用模拟器
1. 在Android Studio中创建一个Android模拟器（推荐API 28+）
2. 启动模拟器并确保adb可以连接
3. 运行 `adb root` 获取Root权限（如果需要）
4. 推送并启动frida-server
5. 在模拟器中安装Mitmproxy的CA证书，可通过访问 `http://mitm.it` 下载并安装

### 使用真实设备
1. 启用设备的开发者选项和USB调试
2. 通过USB连接设备并确保adb可以识别
3. 运行 `adb root` 获取Root权限（如果需要）
4. 推送并启动frida-server
5. 在设备中安装Mitmproxy的CA证书，可通过访问 `http://mitm.it` 下载并安装

## 🚨 常见问题

### 1. Frida-server 启动失败
- **问题**：`Failed to start frida-server`
- **解决方案**：检查设备是否已Root，确保frida-server文件权限正确（`chmod 755`），尝试使用与设备架构匹配的frida-server版本

### 2. Appium 服务不可用
- **问题**：`Appium automation skipped (service not available)`
- **解决方案**：手动启动Appium服务（`appium`），确保Node.js和Appium已正确安装，检查端口是否被占用

### 3. Mitmproxy 证书未安装
- **问题**：网络请求无法被拦截
- **解决方案**：在设备上安装Mitmproxy的CA证书，可通过访问 `http://mitm.it` 下载并安装

### 4. 应用崩溃
- **问题**：注入Frida脚本后应用崩溃
- **解决方案**：检查frida_hooks.js脚本是否有语法错误，尝试减少Hook点数量，确保使用与应用架构匹配的frida-server版本

### 5. 报告包含历史数据
- **问题**：审计报告中包含之前审计的内容
- **解决方案**：工具会自动清理旧的日志文件，确保报告只包含当前审计的数据

### 6. Mitmproxy 代理连接问题
- **问题**：设置代理后设备无法联网
- **解决方案**：
  1. 确保主机网络连接正常
  2. 检查8080端口是否被其他进程占用（可使用 `netstat -ano | findstr :8080` 查看）
  3. 确保防火墙允许8080端口的入站/出站连接
  4. 尝试重启模拟器或设备

### 7. 端口冲突
- **问题**：`Address already in use` 错误
- **解决方案**：使用 `netstat -ano | findstr :8080` 查找占用端口的进程，然后使用 `taskkill /PID <PID> /F` 终止该进程

### 8. Mitmproxy 启动错误
- **问题**：`No module named '__mitmproxy_script__'`
- **解决方案**：工具已优化Mitmproxy启动命令，暂时不加载脚本以避免此错误，确保Mitmproxy能够正常启动和监听

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

---

**免责声明**：本工具仅用于合法的安全测试和隐私合规审计，请勿用于任何恶意目的。使用本工具时，请遵守相关法律法规和道德准则。
