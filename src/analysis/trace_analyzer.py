import re

class StackTraceAnalyzer:
    def __init__(self):
        # 扩展的 SDK 特征库 - 覆盖国内外主流 SDK
        self.sdk_signatures = {
            # --- 广告联盟 (Ads) ---
            "com.google.android.gms.ads": "Google AdMob",
            "com.facebook.ads": "Facebook Audience Network",
            "com.unity3d.ads": "Unity Ads",
            "com.bytedance.sdk": "Pangle (穿山甲)",
            "com.kwad.sdk": "Kuaishou Ads (快手)",
            "com.qq.e.ads": "Tencent GDT (优量汇)",
            "com.mbridge.msdk": "Mintegral",
            "com.vungle.warren": "Vungle",
            "com.applovin": "AppLovin",
            "com.ironsource": "IronSource",
            "com.inmobi": "InMobi",
            "com.sigmob": "Sigmob",
            
            # --- 推送服务 (Push) ---
            "cn.jpush.android": "JPush (极光推送)",
            "com.getui": "GeTui (个推)",
            "com.igexin": "GeTui (个推 Core)",
            "com.xiaomi.push": "MiPush (小米推送)",
            "com.huawei.hms": "Huawei HMS (华为推送)",
            "com.meizu.cloud": "Meizu Push (魅族推送)",
            "com.vivo.push": "Vivo Push (vivo 推送)",
            "com.heytap.msp": "Oppo Push (OPPO 推送)",
            "com.tencent.android.tpush": "Tencent Push (信鸽)",
            
            # --- 统计分析 (Analytics/Tracking) ---
            "com.umeng": "Umeng (友盟)",
            "com.talkingdata": "TalkingData",
            "cn.com.analysys": "Analysys (易观)",
            "com.gridsum": "Gridsum (国双)",
            "com.tendcloud": "TalkingData (Core)",
            "com.appsflyer": "AppsFlyer",
            "com.adjust.sdk": "Adjust",
            "com.flurry": "Flurry",
            
            # --- 社交与支付 (Social & Payment) ---
            "com.tencent.mm.opensdk": "WeChat SDK (微信)",
            "com.sina.weibo": "Weibo SDK (微博)",
            "com.alipay.sdk": "Alipay SDK (支付宝)",
            "com.tencent.tauth": "Tencent Open Platform (QQ)",
            
            # --- 地图定位 (Map/Location) ---
            "com.baidu.location": "Baidu Location (百度定位)",
            "com.baidu.mapapi": "Baidu Map (百度地图)",
            "com.amap.api": "AutoNavi (高德地图/定位)",
            "com.tencent.map": "Tencent Map (腾讯地图)",
            
            # --- 基础设施与风控 (Infra & Security) ---
            "com.tencent.bugly": "Bugly (崩溃分析)",
            "com.aliyun": "Aliyun SDK",
            "com.netease.nis": "NetEase YiDun (网易易盾)",
            "cn.shuzilm.core": "ShuMei (数美风控)",
            "io.flutter": "Flutter Engine",
            "com.airbnb.lottie": "Lottie Animation"
        }

    def analyze(self, stack_trace):
        """
        分析堆栈，返回 (调用者类型, 详细归因)
        类型: 'SDK' 或 'App'
        """
        if not stack_trace:
            return "Unknown", "No Stack Trace"

        lines = stack_trace.strip().split('\n')
        
        # 1. 自底向上遍历堆栈，寻找第一个非系统类
        relevant_frame = None
        for line in lines:
            # 跳过 Android 系统、Java 基础类、Frida 注入代码
            if any(x in line for x in [
                "android.", "java.", "javax.", "com.android.internal", 
                "dalvik.", "io.frida", "de.robv.android.xposed",
                "org.json"
            ]):
                continue
            relevant_frame = line.strip()
            break
        
        if not relevant_frame:
            return "System", "Android Framework"

        # 2. 匹配 SDK 指纹
        for package_prefix, sdk_name in self.sdk_signatures.items():
            if package_prefix in relevant_frame:
                return "Third-Party SDK", sdk_name

        # 3. 如果不是已知 SDK，默认为 App 自身代码
        match = re.search(r'at\s+([a-zA-Z0-9_$.]+)', relevant_frame)
        caller = match.group(1) if match else relevant_frame
        return "App Business Logic", caller

    def correlate(self, injection_logs, leak_logs):
        """
        关联分析：将 Frida 的注入记录与 Mitmproxy 的泄露记录匹配
        """
        correlated_report = []
        
        # 将注入日志转为字典，Key 为金丝雀值
        injections = {entry['canary']: entry for entry in injection_logs}

        for leak in leak_logs:
            # 检查泄露数据中是否包含已知的金丝雀
            leak_data_str = str(leak.get('data', ''))
            matched_canary = None
            
            for canary_val in injections.keys():
                if canary_val in leak_data_str:
                    matched_canary = canary_val
                    break
            
            report_item = {
                "risk_level": "HIGH" if matched_canary else "MEDIUM",
                "leak_type": leak['type'],
                "network_info": {
                    "url": leak.get('url', 'Unknown'),
                    "method": leak.get('method', 'Unknown'),
                    "host": leak.get('host', 'Unknown')
                },
                "evidence": leak['data']
            }

            if matched_canary:
                # 关联成功！这是确凿的证据
                injection_info = injections[matched_canary]
                attribution_type, owner = self.analyze(injection_info.get('stack_trace'))
                
                report_item['source_analysis'] = {
                    "api_called": injection_info['api'],
                    "caller_type": attribution_type,
                    "caller_owner": owner, # 具体是哪个 SDK
                    "call_time": injection_info['timestamp']
                }
                report_item['description'] = f"检测到 {owner} 调用了 {injection_info['api']} 并通过网络明文(或可解密)传输。"
            else:
                report_item['description'] = "检测到疑似敏感数据传输 (正则匹配)。"
                report_item['source_analysis'] = None

            correlated_report.append(report_item)
            
        return correlated_report
