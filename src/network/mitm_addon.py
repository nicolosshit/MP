# Mitmproxy 插件脚本 - 流量解析与隐私泄露检测

import json
import re
import base64
import gzip
import io
from mitmproxy import ctx
from mitmproxy.http import HTTPFlow

# 导入 Protobuf/Gzip 解码器
from .proto_decoder import ProtoDecoder

class PrivacyAuditAddon:
    def __init__(self):
        self.canary_values = []  # 存储从 Frida 注入的金丝雀值
        self.sensitive_patterns = self.load_sensitive_patterns()
        self.proto_decoder = ProtoDecoder()  # 初始化 Protobuf 解码器
        print("[*] Privacy Audit Addon initialized")
    
    def load_sensitive_patterns(self):
        """
        加载敏感数据的正则表达式模式
        """
        patterns = {
            # 手机号
            "phone": r"1[3-9]\d{9}",
            # 邮箱
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            # 身份证号
            "id_card": r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
            # 信用卡号（简单匹配，后续用 Luhn 算法验证）
            "credit_card": r"\d{13,16}"
        }
        return patterns
    
    def luhn_check(self, card_number):
        """
        使用 Luhn 算法验证信用卡号
        :param card_number: 信用卡号字符串
        :return: 是否有效
        """
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        checksum = sum(digits[-1::-2])
        for d in digits[-2::-2]:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0
    
    def add_canary_value(self, canary_value):
        """
        添加金丝雀值到检测列表
        :param canary_value: 金丝雀值
        """
        if canary_value not in self.canary_values:
            self.canary_values.append(canary_value)
            print(f"[+] Added canary value: {canary_value}")
    
    def extract_body(self, flow):
        """
        提取并解码 HTTP 请求/响应体
        :param flow: HTTPFlow 对象
        :return: 解码后的文本
        """
        body = ""
        
        # 处理请求体
        if flow.request.content:
            body += self.decode_content(flow.request.content, flow.request.headers)
        
        # 处理响应体
        if flow.response and flow.response.content:
            body += self.decode_content(flow.response.content, flow.response.headers)
        
        return body
    
    def decode_content(self, content, headers):
        """
        解码内容（处理压缩、Base64、Protobuf 等）
        :param content: 原始内容
        :param headers: HTTP 头部
        :return: 解码后的文本
        """
        try:
            # 检查是否是 Base64 编码
            if 'base64' in headers.get('Content-Transfer-Encoding', '').lower():
                content = base64.b64decode(content)
            
            # 使用 ProtoDecoder 处理可能的 Gzip 压缩和 Protobuf 编码
            decoded_data = self.proto_decoder.decode_data(content)
            
            # 将解码后的数据转换为字符串
            if isinstance(decoded_data, dict):
                # 如果是字典（Protobuf 解码结果），转换为 JSON 字符串
                return json.dumps(decoded_data, ensure_ascii=False)
            elif isinstance(decoded_data, str):
                # 如果已经是字符串，直接返回
                return decoded_data
            else:
                # 其他类型，尝试转换为字符串
                return str(decoded_data)
        except Exception as e:
            print(f"[*] Error decoding content: {e}")
            return ""
    
    def search_canary_values(self, text):
        """
        在文本中搜索金丝雀值
        :param text: 要搜索的文本
        :return: 找到的金丝雀值列表
        """
        found_canaries = []
        for canary in self.canary_values:
            if canary in text:
                found_canaries.append(canary)
        return found_canaries
    
    def search_sensitive_data(self, text):
        """
        搜索敏感数据（被动模式）
        :param text: 要搜索的文本
        :return: 找到的敏感数据字典
        """
        found_data = {}
        
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # 对于信用卡号，使用 Luhn 算法验证
                if pattern_name == "credit_card":
                    valid_cards = [card for card in matches if self.luhn_check(card)]
                    if valid_cards:
                        found_data[pattern_name] = valid_cards
                else:
                    found_data[pattern_name] = matches
        
        return found_data
    
    def detect_privacy_leak(self, flow):
        """
        检测隐私泄露
        :param flow: HTTPFlow 对象
        """
        # 提取流量内容
        body = self.extract_body(flow)
        if not body:
            return
        
        # 1. 主动模式：搜索金丝雀值
        found_canaries = self.search_canary_values(body)
        if found_canaries:
            for canary in found_canaries:
                print(f"[ALERT] Canary value found in traffic! -> {canary}")
                print(f"  URL: {flow.request.pretty_url}")
                print(f"  Method: {flow.request.method}")
                
                # 记录详细信息到日志
                self.log_leak_details(flow, "canary", canary)
        
        # 2. 被动模式：搜索敏感数据
        found_sensitive = self.search_sensitive_data(body)
        if found_sensitive:
            for data_type, values in found_sensitive.items():
                for value in values[:3]:  # 只显示前 3 个匹配项
                    print(f"[WARN] Sensitive data found: {data_type} -> {value}")
                    
                # 记录详细信息到日志
                self.log_leak_details(flow, "sensitive", found_sensitive)
    
    def log_leak_details(self, flow, leak_type, data):
        """
        记录泄露详细信息
        :param flow: HTTPFlow 对象
        :param leak_type: 泄露类型
        :param data: 泄露数据
        """
        details = {
            "type": leak_type,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "data": data,
            "timestamp": flow.request.timestamp_start
        }
        
        # 写入日志文件
        with open("privacy_leak_log.json", "a", encoding="utf-8") as f:
            json.dump(details, f, ensure_ascii=False)
            f.write("\n")
    
    def request(self, flow):
        """
        处理 HTTP 请求
        """
        self.detect_privacy_leak(flow)
    
    def response(self, flow):
        """
        处理 HTTP 响应
        """
        self.detect_privacy_leak(flow)
    
    def load(self, entry):
        """
        插件加载时调用
        """
        print("[*] Privacy Audit Addon loaded")
    
    def done(self):
        """
        插件卸载时调用
        """
        print("[*] Privacy Audit Addon unloaded")

# 注册插件
addons = [
    PrivacyAuditAddon()
]
