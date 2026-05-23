#!/usr/bin/env python3
# Protobuf/Gzip 解码器

import gzip
import io
import struct
import json
from google.protobuf import message
from google.protobuf.json_format import MessageToDict

class ProtoDecoder:
    def __init__(self):
        self.proto_files = []
    
    def is_gzip_compressed(self, data):
        """
        检测数据是否为 Gzip 压缩
        :param data: 要检测的数据
        :return: 是否为 Gzip 压缩
        """
        if not data or len(data) < 2:
            return False
        # Gzip 魔法数字：1f 8b
        return data[0] == 0x1f and data[1] == 0x8b
    
    def decompress_gzip(self, data):
        """
        解压缩 Gzip 数据
        :param data: Gzip 压缩的数据
        :return: 解压缩后的数据
        """
        try:
            buffer = io.BytesIO(data)
            with gzip.GzipFile(fileobj=buffer, mode='rb') as f:
                decompressed_data = f.read()
            return decompressed_data
        except Exception as e:
            print(f"Error decompressing gzip: {e}")
            return None
    
    def is_protobuf(self, data):
        """
        检测数据是否为 Protobuf 编码
        :param data: 要检测的数据
        :return: 是否为 Protobuf 编码
        """
        if not data or len(data) == 0:
            return False
        
        # Protobuf 格式检测
        # 1. 检查长度前缀（如果有）
        # 2. 检查字段标签格式
        try:
            # 尝试解析前几个字节作为 Protobuf varint
            pos = 0
            while pos < len(data):
                if pos >= len(data):
                    break
                byte = data[pos]
                pos += 1
                if not (byte & 0x80):
                    # 找到一个 varint 结束
                    if pos < len(data):
                        # 检查下一个字节是否可能是字段类型
                        field_type = data[pos] & 0x07
                        if field_type in (0, 1, 2, 3, 5):
                            return True
                    break
        except Exception:
            pass
        
        return False
    
    def decode_protobuf(self, data, proto_message=None):
        """
        解码 Protobuf 数据
        :param data: Protobuf 编码的数据
        :param proto_message: Protobuf 消息类型（可选）
        :return: 解码后的数据
        """
        if not data:
            return None
        
        try:
            if proto_message and isinstance(proto_message, type) and issubclass(proto_message, message.Message):
                # 使用指定的消息类型解码
                message_instance = proto_message()
                message_instance.ParseFromString(data)
                return MessageToDict(message_instance, preserving_proto_field_name=True)
            else:
                # 尝试通用解码（有限支持）
                return self._generic_protobuf_decode(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return None
    
    def _generic_protobuf_decode(self, data):
        """
        通用 Protobuf 解码（有限支持）
        :param data: Protobuf 编码的数据
        :return: 解码后的数据
        """
        result = {}
        pos = 0
        
        try:
            while pos < len(data):
                # 解析字段标签
                tag, pos = self._read_varint(data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x07
                
                # 解析字段值
                if wire_type == 0:  # Varint
                    value, pos = self._read_varint(data, pos)
                    result[f"field_{field_number}"] = value
                elif wire_type == 1:  # 64-bit
                    if pos + 8 <= len(data):
                        value = struct.unpack('<Q', data[pos:pos+8])[0]
                        result[f"field_{field_number}"] = value
                        pos += 8
                elif wire_type == 2:  # Length-delimited
                    length, pos = self._read_varint(data, pos)
                    if pos + length <= len(data):
                        value = data[pos:pos+length]
                        # 尝试递归解码嵌套消息
                        if self.is_protobuf(value):
                            nested = self._generic_protobuf_decode(value)
                            result[f"field_{field_number}"] = nested
                        else:
                            # 尝试转换为字符串
                            try:
                                result[f"field_{field_number}"] = value.decode('utf-8')
                            except:
                                result[f"field_{field_number}"] = value.hex()
                        pos += length
                elif wire_type == 3:  # Start group (deprecated)
                    # 跳过组
                    while pos < len(data):
                        tag, pos = self._read_varint(data, pos)
                        if tag == (field_number << 3) | 4:  # End group
                            break
                elif wire_type == 4:  # End group (deprecated)
                    pass
                elif wire_type == 5:  # 32-bit
                    if pos + 4 <= len(data):
                        value = struct.unpack('<I', data[pos:pos+4])[0]
                        result[f"field_{field_number}"] = value
                        pos += 4
        except Exception as e:
            print(f"Error in generic protobuf decode: {e}")
        
        return result
    
    def _read_varint(self, data, pos):
        """
        读取 Protobuf varint
        :param data: 数据
        :param pos: 起始位置
        :return: (值, 新位置)
        """
        value = 0
        shift = 0
        while pos < len(data):
            byte = data[pos]
            value |= (byte & 0x7f) << shift
            pos += 1
            if not (byte & 0x80):
                break
            shift += 7
        return value, pos
    
    def decode_data(self, data):
        """
        解码数据（自动检测并处理压缩和编码）
        :param data: 原始数据
        :return: 解码后的数据
        """
        if not data:
            return None
        
        # 检测并处理 Gzip 压缩
        if self.is_gzip_compressed(data):
            print("[*] Detected Gzip compressed data")
            decompressed = self.decompress_gzip(data)
            if decompressed:
                data = decompressed
        
        # 检测并处理 Protobuf 编码
        if self.is_protobuf(data):
            print("[*] Detected Protobuf encoded data")
            decoded = self.decode_protobuf(data)
            if decoded:
                return decoded
        
        # 尝试转换为字符串
        try:
            return data.decode('utf-8')
        except:
            # 如果不是字符串，返回十六进制表示
            return data.hex()
    
    def load_proto_files(self, proto_files):
        """
        加载 Protobuf 定义文件
        :param proto_files: Protobuf 文件路径列表
        """
        self.proto_files = proto_files
        # 这里可以添加加载 Protobuf 定义的逻辑
        # 例如使用 protoc 编译或使用 dynamic message
    
    def decode_http_body(self, body):
        """
        解码 HTTP 请求/响应体
        :param body: HTTP 体数据
        :return: 解码后的数据
        """
        if not body:
            return None
        
        # 处理不同类型的 body
        if isinstance(body, bytes):
            return self.decode_data(body)
        elif isinstance(body, str):
            # 尝试解析为 JSON
            try:
                return json.loads(body)
            except:
                return body
        else:
            return body
