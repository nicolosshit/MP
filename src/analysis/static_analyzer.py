import os
import re
import subprocess
import zipfile

class StaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.aapt_path = "aapt" # 假设环境变量中已有，或指定绝对路径
        
        # 敏感信息正则库 (Hardcoded Secrets)
        self.secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Generic API Key": r"(?i)api_key\s*=\s*['\"][a-zA-Z0-9]{32,}['\"]",
            "Private Key": r"-----BEGIN PRIVATE KEY-----",
            "Internal IP": r"192\.168\.\d{1,3}\.\d{1,3}",
            "Oss/S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com"
        }

    def run(self):
        """执行完整静态分析"""
        print("[*] Starting Static Analysis...")
        results = {
            "permissions": self._get_permissions(),
            "metadata": self._get_metadata(),
            "secrets": self._scan_secrets()
        }
        return results

    def _get_permissions(self):
        """使用 aapt 提取权限列表"""
        perms = []
        try:
            cmd = [self.aapt_path, "dump", "permissions", self.apk_path]
            # 注意：在 Windows 上可能需要 shell=True 或处理编码
            res = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            for line in res.stdout.split('\n'):
                if line.startswith("uses-permission:"):
                    perm = line.split("name='")[1].split("'")[0]
                    perms.append(perm)
        except Exception as e:
            print(f"[!] Error getting permissions: {e}")
        return perms

    def _get_metadata(self):
        """提取包名、版本等元数据"""
        meta = {}
        try:
            cmd = [self.aapt_path, "dump", "badging", self.apk_path]
            res = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            for line in res.stdout.split('\n'):
                if line.startswith("package:"):
                    # package: name='com.example' versionCode='1' ...
                    parts = line.split(" ")
                    for part in parts:
                        if part.startswith("name='"):
                            meta['package_name'] = part.split("='")[1].rstrip("'")
                        elif part.startswith("versionName='"):
                            meta['version'] = part.split("='")[1].rstrip("'")
                elif line.startswith("application-label:"):
                    meta['app_name'] = line.split(":")[1].strip().strip("'")
        except Exception as e:
            print(f"[!] Error getting metadata: {e}")
        return meta

    def _scan_secrets(self):
        """解压 APK 并扫描硬编码敏感信息 (简易版)"""
        found_secrets = []
        try:
            # 简单遍历 APK 中的文件 (实际上应扫描 classes.dex，这里简化演示扫描资源文件)
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for filename in z.namelist():
                    # 跳过图片和二进制库，聚焦配置文件和脚本
                    if filename.endswith(('.xml', '.json', '.properties', '.js', '.html')):
                        try:
                            content = z.read(filename).decode('utf-8', errors='ignore')
                            for name, pattern in self.secret_patterns.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    for m in matches[:3]: # 每个类型最多记录3个
                                        found_secrets.append({
                                            "type": name,
                                            "file": filename,
                                            "match": m[:30] + "..." # 截断显示
                                        })
                        except Exception:
                            pass
        except Exception as e:
            print(f"[!] Error scanning secrets: {e}")
        return found_secrets
