import os
import json
import sys
import math
# 引入新的分析器
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.trace_analyzer import StackTraceAnalyzer

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.analyzer = StackTraceAnalyzer()

    def calculate_score(self, report_items, static_data, logcat_leaks, fuzzing_data=None):
        """计算隐私安全评分 (100分制)"""
        score = 100
        
        # 1. 动态流量泄露扣分
        high_risk_leaks = len([x for x in report_items if x['risk_level'] == 'HIGH'])
        score -= (high_risk_leaks * 15) # 每个实锤泄露扣15分
        
        # 2. 静态高危权限扣分
        if static_data:
            dangerous_perms = [
                "ACCESS_FINE_LOCATION", "READ_CONTACTS", "READ_SMS", 
                "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "READ_PHONE_STATE"
            ]
            perms = static_data.get('permissions', [])
            for p in perms:
                if any(dp in p for dp in dangerous_perms):
                    score -= 3
        
        # 3. 硬编码密钥扣分
        if static_data:
            secrets = static_data.get('secrets', [])
            score -= (len(secrets) * 5)
            
        # 4. 日志泄露扣分
        score -= (len(logcat_leaks) * 3)

        # 5. 组件暴露扣分
        if fuzzing_data:
            score -= (len(fuzzing_data) * 5)

        return max(0, score) # 最低0分

    def generate_html_report(self, metadata, leak_log="privacy_leaks.jsonl", injection_log="injection_logs.jsonl", static_data=None, logcat_log="logcat_leaks.jsonl", fuzzing_log="fuzzing_vulns.json", consent_time=None):
        # 读取各类日志
        leaks = self._read_jsonl(leak_log)
        injections = self._read_jsonl(injection_log)
        logcat_leaks = self._read_jsonl(logcat_log)
        
        # 尝试读取 Fuzzing 结果 (如果存在)
        fuzzing_data = []
        # 注意：这里假设 fuzzing 结果可能以列表形式传入，或者需要从文件读取
        # 为了兼容性，这里暂时只处理传入参数的情况，或者您可以扩展从文件读取
        
        # [新增] PIPL 违规标记逻辑
        if consent_time:
            for inj in injections:
                try:
                    # Frida记录的时间戳通常是秒(float)，这里做兼容处理
                    inj_time = inj.get('timestamp', 0)
                    if isinstance(inj_time, str): continue # 跳过格式错误
                    if 0 < inj_time < consent_time:
                        inj['is_pre_consent'] = True
                except: pass

        # 关联分析
        correlated_data = self.analyzer.correlate(injections, leaks)
        
        # 生成动态图谱数据
        graph_data = self._generate_graph_data(correlated_data, injections, logcat_leaks)

        # 生成 HTML
        self._write_html_pro(metadata, correlated_data, static_data, logcat_leaks, consent_time, graph_data, fuzzing_data)

    def _read_jsonl(self, filepath):
        data = []
        full_path = os.path.join(self.output_dir, filepath) if not os.path.isabs(filepath) else filepath
        
        if os.path.exists(full_path):
            with open(full_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try: data.append(json.loads(line))
                    except: pass
        return data

    def _generate_graph_data(self, correlated_data, injections, logcat_leaks):
        """生成真实的 ECharts 关系图数据"""
        nodes = []
        links = []
        node_ids = set()
        
        def add_node(name, category, value=10):
            if name not in node_ids:
                color_map = {
                    "API": "#3498db",      # 蓝色
                    "SDK": "#f39c12",      # 橙色
                    "Network": "#9b59b6",  # 紫色
                    "Data": "#e74c3c",     # 红色
                    "App": "#2ecc71",      # 绿色
                    "Logcat": "#1abc9c"     # 青色
                }
                nodes.append({
                    "name": name, 
                    "category": category,
                    "value": value,
                    "symbolSize": value * 2 + 20,
                    "itemStyle": {"color": color_map.get(category, "#95a5a6")}
                })
                node_ids.add(name)

        # 中心节点
        add_node("Target App", "App", 20)

        # 1. 处理 API 调用链 (从注入日志)
        for inj in injections:
            api_name = inj.get('api', 'Unknown API')
            # 简化 API 名称
            simple_api = api_name.split('.')[-1] if '.' in api_name else api_name
            add_node(simple_api, "API", 5)
            links.append({"source": "Target App", "target": simple_api})

        # 2. 处理网络泄露链 (从关联分析)
        for item in correlated_data:
            # 提取信息
            evidence = item.get('evidence', 'Unknown Data')[:15] # 截断数据显示
            # 尝试从 network_info 中获取 host，如果没有则直接从 item 中获取 (Mitmproxy 日志格式)
            host = item.get('network_info', {}).get('host', item.get('host', 'Unknown Host'))
            
            add_node(host, "Network", 15)
            add_node(evidence, "Data", 8)
            
            # 建立连接: Data -> Host
            links.append({"source": evidence, "target": host})

            # 如果有溯源信息: API -> SDK -> Data
            if 'source_analysis' in item and item['source_analysis']:
                sa = item['source_analysis']
                caller = sa.get('caller_owner', 'App Logic')
                api_called = sa.get('api_called', 'Unknown API')
                simple_api = api_called.split('.')[-1] if '.' in api_called else api_called

                add_node(caller, "SDK", 12)
                
                # 链接: API -> SDK -> Data
                # 注意：这里逻辑上稍微简化，为了图表好看
                links.append({"source": simple_api, "target": caller})
                links.append({"source": caller, "target": evidence})
            else:
                # 没有溯源，直接 App -> Data
                links.append({"source": "Target App", "target": evidence})

        # 3. 处理 Logcat 泄露 (从 Logcat 日志)
        for leak in logcat_leaks:
            category = leak.get('category', 'Unknown')
            data = leak.get('data', 'Unknown Data')[:15]  # 截断数据显示
            
            # 添加 Logcat 节点
            add_node(f"Logcat:{category}", "Logcat", 10)
            add_node(data, "Data", 8)
            
            # 建立连接: App -> Logcat -> Data
            links.append({"source": "Target App", "target": f"Logcat:{category}"})
            links.append({"source": f"Logcat:{category}", "target": data})

        return {"nodes": nodes, "links": links}

    def _write_html_pro(self, metadata, report_items, static_data, logcat_leaks, consent_time, graph_data, fuzzing_data):
        # PIPL 警告
        pipl_warning = ""
        pre_consent_issues = [x for x in report_items if x.get('source_analysis', {}).get('is_pre_consent')]
        if pre_consent_issues:
            rows = ""
            for item in pre_consent_issues:
                rows += f"<li><strong>{item['source_analysis']['api_called']}</strong> 被 <strong>{item['source_analysis']['caller_owner']}</strong> 调用 (在同意隐私协议前)</li>"
            
            pipl_warning = f"""
            <div class="card" style="border-left: 5px solid #E04F5F;">
                <h2>🚨 PIPL 合规严重违规 (同意前偷跑)</h2>
                <p>检测到 App 在用户点击同意隐私协议之前，就已经获取了以下敏感权限或数据：</p>
                <ul>{rows}</ul>
            </div>
            """

        # 静态分析 - 权限列表
        static_perms_html = "<p>未提供静态分析数据</p>"
        if static_data and 'permissions' in static_data:
            dangerous = ["LOCATION", "CONTACTS", "SMS", "AUDIO", "CAMERA", "PHONE"]
            perm_items = ""
            for p in static_data['permissions']:
                is_danger = any(d in p for d in dangerous)
                risk_category = "高危权限" if is_danger else "普通权限"
                style = "color: #e74c3c; font-weight: bold;" if is_danger else "color: #7f8c8d;"
                perm_items += f"<span style='display:inline-block; margin:2px; padding:2px 5px; border:1px solid #ddd; border-radius:3px; font-size:12px; {style}'>{p} <span class='tag bg-blue'>{risk_category}</span></span>"
            static_perms_html = f"<div style='margin-bottom:15px;'>{perm_items}</div>"

        # 静态分析 - 密钥列表
        static_secrets_html = ""
        if static_data and 'secrets' in static_data and static_data['secrets']:
            rows = ""
            for s in static_data['secrets']:
                rows += f"<tr><td>{s['type']}</td><td><code>{s['file']}</code></td><td><code>{s['match']}</code></td><td><span class='tag bg-red'>硬编码密钥</span></td></tr>"
            static_secrets_html = f"""
            <h3>🔑 发现硬编码敏感信息</h3>
            <table style="width:100%; border-collapse: collapse; font-size: 13px;">
                <tr style="background:#f8f9fa; text-align:left;"><th style="padding:8px;">类型</th><th>文件</th><th>内容片段</th><th>风险类别</th></tr>
                {rows}
            </table>
            """

        # 动态流量列表
        network_rows = ""
        if report_items:
            for item in report_items:
                source_info = "未知来源"
                if item.get('source_analysis'):
                    sa = item['source_analysis']
                    source_info = f"<span class='tag bg-blue'>{sa['caller_owner']}</span> 调用 {sa['api_called']}"
                
                # 确定风险类别
                risk_category = ""
                if item.get('risk_level') == 'HIGH':
                    risk_category = "<span class='tag bg-red'>高危泄露</span>"
                elif item.get('risk_level') == 'MEDIUM':
                    risk_category = "<span class='tag bg-orange'>中危泄露</span>"
                elif item.get('risk_level') == 'LOW':
                    risk_category = "<span class='tag bg-green'>低危泄露</span>"
                
                network_rows += f"""
                <div style="border-bottom: 1px solid #eee; padding: 10px 0;">
                    <div style="display:flex; justify-content:space-between;">
                        <div>{risk_category} <strong>{item['network_info']['host']}</strong></div>
                        <div style="font-size:12px; color:gray;">{item['network_info']['method']} {item['network_info']['url'][:50]}...</div>
                    </div>
                    <div style="margin-top:5px; font-size:13px;">
                        <div>🕵️ <strong>溯源:</strong> {source_info}</div>
                        <div style="margin-top:2px;">📦 <strong>泄露数据:</strong> <code>{item['evidence']}</code></div>
                        <div style="margin-top:2px; color:#666;">📝 <strong>说明:</strong> {item.get('description', '')}</div>
                    </div>
                </div>
                """
        else:
            network_rows = "<p>✅ 未检测到敏感数据网络传输</p>"

        # 生成 ECharts JSON
        graph_json = json.dumps(graph_data)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>隐私审计报告 - {metadata.get('package_name')}</title>
            <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
            <style>
                body {{ font-family: 'Segoe UI', Roboto, sans-serif; background: #f4f6f9; padding: 20px; color: #2c3e50; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; border-radius: 15px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .card {{ background: white; border-radius: 12px; padding: 25px; margin-top: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
                .card h2 {{ margin-top: 0; border-bottom: 2px solid #f0f2f5; padding-bottom: 10px; font-size: 18px; color: #34495e; }}
                .tag {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; color: white; font-weight: 500; }}
                .bg-red {{ background: #e74c3c; }} .bg-blue {{ background: #3498db; }} .bg-orange {{ background: #f39c12; }} .bg-green {{ background: #2ecc71; }} .bg-purple {{ background: #9b59b6; }}
                code {{ background: #f8f9fa; color: #c0392b; padding: 2px 5px; border-radius: 3px; font-family: Consolas, monospace; }}
                #graph-container {{ width: 100%; height: 600px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div>
                        <h1>🛡️ 移动应用隐私合规审计报告</h1>
                        <p style="opacity: 0.8; margin-top: 5px;">应用包名: {metadata.get('package_name')} | 审计时间: {metadata.get('timestamp')}</p>
                    </div>
                </div>

                {pipl_warning}

                <div class="card">
                    <h2>📊 1. 静态风险分析 (Static Analysis)</h2>
                    <p style="font-size:13px; color:gray;">分析 APK 文件申请的权限及硬编码的敏感信息。</p>
                    <strong>申请权限:</strong>
                    {static_perms_html}
                    {static_secrets_html}
                </div>

                <div class="card">
                    <h2>🕸️ 2. 动态数据流向图谱 (Dynamic Data Flow)</h2>
                    <p style="font-size:13px; color:gray;">基于 Frida Hook 与网络抓包生成的实时数据流向拓扑。</p>
                    <div id="graph-container"></div>
                </div>

                <div class="card">
                    <h2>📡 3. 隐私数据传输详情 ({len(report_items)})</h2>
                    {network_rows}
                </div>

                <div class="card">
                    <h2>📝 4. Logcat 敏感日志 ({len(logcat_leaks)})</h2>
                    <ul>
                    {''.join([f"<li><span class='tag bg-blue'>{x['category']}</span> <code>{x['data']}</code><br><small style='color:gray'>{x['raw_log']}</small></li>" for x in logcat_leaks])}
                    </ul>
                    {'<p style="color:#aaa; font-style:italic;">未发现 Logcat 泄露</p>' if not logcat_leaks else ''}
                </div>
            </div>
            
            <script>
                var chart = echarts.init(document.getElementById('graph-container'));
                var graphData = {graph_json};
                
                var option = {{
                    title: {{ text: '隐私数据溯源图谱', top: 'bottom', left: 'right' }},
                    tooltip: {{}},
                    legend: [{{ data: ['App', 'API', 'SDK', 'Data', 'Network', 'Logcat'] }}],
                    series: [{{
                        type: 'graph',
                        layout: 'force',
                        animation: false,
                        label: {{ show: true, position: 'right', formatter: '{{b}}' }},
                        draggable: true,
                        data: graphData.nodes.map(function (node) {{
                            return {{
                                name: node.name,
                                value: node.value,
                                symbolSize: node.symbolSize,
                                itemStyle: node.itemStyle,
                                category: ['App', 'API', 'SDK', 'Data', 'Network', 'Logcat'].indexOf(node.category)
                            }};
                        }}),
                        categories: [
                            {{ name: 'App' }}, {{ name: 'API' }}, {{ name: 'SDK' }}, {{ name: 'Data' }}, {{ name: 'Network' }}, {{ name: 'Logcat' }}
                        ],
                        force: {{
                            edgeLength: 120,
                            repulsion: 400,
                            gravity: 0.1
                        }},
                        edges: graphData.links
                    }}]
                }};
                chart.setOption(option);
                window.onresize = function() {{ chart.resize(); }};
            </script>
        </body>
        </html>
        """

        output_path = os.path.join(self.output_dir, "audit_report.html")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[SUCCESS] 审计报告已生成: {output_path}")
