import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import json
import os
import shutil
import platform
import argparse
import sys
import subprocess
import re
from pathlib import Path

_COMMON_PYTHON_DIR = Path(__file__).resolve().parents[1] / "python"
if str(_COMMON_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_PYTHON_DIR))

if platform.system() == "Windows":
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None

from secflow_common.ai_client import AIClient
from secflow_common.packet_analysis import (
    analysis_indicates_threat,
    apply_firewall_action,
    build_llm_disabled_analysis,
    build_packet_result,
    build_rule_based_analysis,
    parse_llm_analysis_response,
)
from secflow_common.packet_payloads import describe_payload
from secflow_common.packet_rules import quick_threat_check

class FirewallManager:
    def __init__(self):
        self.system = platform.system()
        self.allow_internal = os.getenv("ALLOW_INTERNAL_BLOCK", "1") == "1"
        self.iptables_path = shutil.which("iptables") or "/usr/sbin/iptables"
        self.conntrack_path = shutil.which("conntrack")
        # === 白名单 (防止误封锁) ===
        # 请在此处添加: 网关IP, 本机IP, DNS服务器, 测试手机的IP等
        self.whitelist = [
            "127.0.0.1", "localhost", "0.0.0.0", 
            "192.168.1.1", "192.168.0.1", "192.168.31.1", # 常见路由器
            "8.8.8.8", "1.1.1.1", "114.114.114.114"       # 公共DNS
        ]
        self.blocked_ips = set() # 内存记录，防止重复执行命令

    def block_ip(self, ip_address):
        """调用系统命令封锁指定IP"""
        # 1. 基础检查
        if not ip_address or ip_address == "N/A":
            return False, "无效ip"
        
        if ip_address in self.whitelist:
            return False, "目标已列入白名单"
        
        if ip_address in self.blocked_ips:
            return False, "已被阻止"

        # 2. 简单的内网IP保护 (可通过 ALLOW_INTERNAL_BLOCK=0 开启安全模式)
        if (not self.allow_internal) and (ip_address.startswith("192.168.") or ip_address.startswith("10.")):
            return False, "内部 IP 被忽略（安全模式）"

        command = ""
        try:
            if self.system == "Windows":
                rule_name = f"Block_AI_Detected_{ip_address}"
                command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            elif self.system == "Linux":
                chains = ["DOCKER-USER", "FORWARD", "INPUT"]
                has_rule = False
                for chain in chains:
                    command = [self.iptables_path, "-I", chain, "1", "-s", ip_address, "-j", "DROP"]
                    result = subprocess.run(command, capture_output=True, text=True)
                    if result.returncode != 0:
                        stderr = (result.stderr.strip() or result.stdout.strip())
                        if "No chain/target/match" in stderr or "does not exist" in stderr:
                            continue
                        return False, f"{chain} 失败: {stderr}"
                    has_rule = True

                if not has_rule:
                    return False, "未找到可用链"

                if self.conntrack_path:
                    subprocess.run([self.conntrack_path, "-D", "-s", ip_address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            else:
                return False, f"Unsupported OS: {self.system}"

            self.blocked_ips.add(ip_address)
            return True, "成功阻止"

        except Exception as e:
            return False, f"Error: {str(e)}"

# ==========================================
# 数据包分析器类
# ==========================================
class PacketAnalyzer:
    def __init__(self):
        self.is_capturing = False
        self.interface_mapping = {}
        self.interfaces = self.get_network_interfaces()
        self.fw_manager = FirewallManager()
        self.ai_client = None

    def get_network_interfaces(self):
        interfaces = []
        self.interface_mapping = {}
        
        if platform.system() == "Windows" and get_windows_if_list:
            try:
                win_interfaces = get_windows_if_list()
                for iface in win_interfaces:
                    simplified_name = iface.get('description') or iface.get('name')
                    raw_interface_name = iface.get('name')
                    
                    counter = 1
                    original_name = simplified_name
                    while simplified_name in interfaces:
                        simplified_name = f"{original_name} ({counter})"
                        counter += 1
                    
                    interfaces.append(simplified_name)
                    self.interface_mapping[simplified_name] = raw_interface_name
            except Exception:
                raw_interfaces = scapy.get_if_list()
                interfaces.extend(raw_interfaces)
                for iface in raw_interfaces:
                    self.interface_mapping[iface] = iface
        else:
            raw_interfaces = scapy.get_if_list()
            for iface in raw_interfaces:
                if 'wlan' in iface.lower() or 'wifi' in iface.lower():
                    simplified_name = "Wi-Fi"
                elif 'eth' in iface.lower():
                    simplified_name = "Ethernet"
                elif 'lo' in iface.lower():
                    simplified_name = "Loopback"
                else:
                    simplified_name = iface
                
                counter = 1
                original_name = simplified_name
                while simplified_name in interfaces:
                    simplified_name = f"{original_name} ({counter})"
                    counter += 1
                
                interfaces.append(simplified_name)
                self.interface_mapping[iface] = iface
        return interfaces

    def list_interfaces(self):
        print("可用的网络接口:")
        if not self.interfaces:
            print("没有找到接口")
            return
        for i, iface_name in enumerate(self.interfaces):
            raw_name = self.interface_mapping.get(iface_name, iface_name)
            print(f"  {i+1}: {iface_name} (Raw Name: {raw_name})")

    def quick_threat_check(self, packet_dict):
        return quick_threat_check(packet_dict)


    def packet_to_dict(self, packet):
        packet_info = {
            "time": float(packet.time),
            "src": packet.getlayer(IP).src if packet.haslayer(IP) else "N/A",
            "dst": packet.getlayer(IP).dst if packet.haslayer(IP) else "N/A",
            "proto": packet.getlayer(IP).proto if packet.haslayer(IP) else "N/A",
            "len": len(packet),
            "summary": packet.summary()
        }

        if packet.haslayer(TCP):
            packet_info["sport"] = packet[TCP].sport
            packet_info["dport"] = packet[TCP].dport
            packet_info["flags"] = str(packet[TCP].flags)

            # 提取 TCP payload
            if packet.haslayer(scapy.Raw):
                packet_info.update(describe_payload(packet[scapy.Raw].load))

        elif packet.haslayer(UDP):
            packet_info["sport"] = packet[UDP].sport
            packet_info["dport"] = packet[UDP].dport

            if packet.haslayer(scapy.Raw):
                packet_info.update(describe_payload(packet[scapy.Raw].load))

        return packet_info




    def analyze_packet_with_llm(self, packet_dict):
        try:
            key_info = {
                "src": packet_dict.get("src"),
                "dst": packet_dict.get("dst"),
                "sport": packet_dict.get("sport"),
                "dport": packet_dict.get("dport"),
                "proto": packet_dict.get("proto"),
                "flags": packet_dict.get("flags"),
                "payload": packet_dict.get("payload", "")[:500],  # 只取前 500 字符
                "summary": packet_dict.get("summary")
            }

            prompt = f'''分析此网络数据包，检测威胁（SQL注入/命令注入/XSS/路径遍历/端口扫描）。

返回 JSON 格式：
{{"is_threat": true/false, "threat_type": "威胁类型", "reason": "原因", "summary": "摘要", "confidence": "高/中/低"}}

数据包：
{json.dumps(key_info, ensure_ascii=False)}'''

            system_prompt = "You are a security expert. Respond ONLY with valid JSON."
            content = self.ai_client.chat(prompt, system_prompt)

            # 清洗 markdown 标记
            if "```" in content:
                match = re.search(r'```(?:json)?\s*(.*?)```', content, re.DOTALL)
                if match:
                    content = match.group(1)
                else:
                    content = content.replace("```json", "").replace("```", "")

            return content.strip()

        except Exception as e:
            return json.dumps({
                "is_threat": False,
                "threat_type": "LLM Error",
                "reason": str(e),
                "summary": "Error calling LLM analysis",
                "confidence": "低"
            })

    def _resolve_packet_analysis(self, packet_dict):
        status, threat_type, reason = self.quick_threat_check(packet_dict)
        if status in {"threat", "safe"}:
            return build_rule_based_analysis(
                status,
                threat_type,
                reason,
                summary=packet_dict.get("summary", ""),
            )
        if self.ai_client is None:
            return build_llm_disabled_analysis()
        llm_result_str = self.analyze_packet_with_llm(packet_dict)
        return parse_llm_analysis_response(llm_result_str)

    def _enforce_firewall(self, packet_dict, analysis):
        if not analysis_indicates_threat(analysis):
            return apply_firewall_action(analysis, "None"), False, "None"

        target_ip = packet_dict.get("src")
        success, msg = self.fw_manager.block_ip(target_ip)
        if success:
            firewall_action = "Blocked"
            return apply_firewall_action(analysis, firewall_action, append_block_reason=True), True, firewall_action

        firewall_action = f"Skipped ({msg})"
        return apply_firewall_action(analysis, firewall_action), True, firewall_action

    def analyze_single_packet(self, packet_dict, packet_id):
        llm_result = self._resolve_packet_analysis(packet_dict)
        llm_result, _, _ = self._enforce_firewall(packet_dict, llm_result)
        return build_packet_result(packet_id, packet_dict, llm_result)

    def capture_and_analyze(self, interface_name, packet_count, port_filter=None,
                            provider='ollama', api_key=None, model=None, api_base=None):
        # 初始化 AI 客户端
        if provider != "off":
            self.ai_client = AIClient(
                provider=provider,
                api_key=api_key,
                model=model,
                api_base=api_base
            )
        else:
            self.ai_client = None
        raw_interface_name = self.interface_mapping.get(interface_name, interface_name)

        print(json.dumps({"info": f"Starting capture on {raw_interface_name}..."}), flush=True)

        self.is_capturing = True
        packet_counter = [0]  # 使用列表以便在闭包中修改

        def packet_callback(packet):
            if not self.is_capturing:
                return

            packet_counter[0] += 1
            packet_id = packet_counter[0]

            try:
                packet_dict = self.packet_to_dict(packet)
                llm_result = self._resolve_packet_analysis(packet_dict)
                llm_result, is_actually_threat, firewall_action = self._enforce_firewall(packet_dict, llm_result)
                result = build_packet_result(packet_id, packet_dict, llm_result)

                json_output = json.dumps(result)

                if is_actually_threat:
                    print(f"\033[91m{json_output}\033[0m", flush=True)
                    sys.stderr.write(f"\033[91m⚠️  威胁检测！来源: {result['src']} | 类型: {llm_result.get('threat_type')} | 动作: {firewall_action}\033[0m\n")
                    sys.stderr.flush()
                else:
                    print(json_output, flush=True)

            except Exception as e:
                print(json.dumps({"error": f"Packet processing error: {str(e)}"}), flush=True)

        try:
            bpf_filter = None
            if port_filter:
                bpf_filter = f"port {port_filter}"

            scapy.sniff(
                iface=raw_interface_name,
                filter=bpf_filter,
                count=packet_count,
                prn=packet_callback,
                stop_filter=lambda p: not self.is_capturing
            )

        except (PermissionError, OSError) as e:
            print(json.dumps({"error": f"Permission denied: {e}. Please run as Administrator."}), flush=True)
        except Exception as e:
            print(json.dumps({"error": f"Unexpected error: {e}"}), flush=True)
        finally:
            self.is_capturing = False

def main():
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(json.dumps({"warning": "Not running as Admin. Firewall actions will fail."}), flush=True)

    analyzer = PacketAnalyzer()

    parser = argparse.ArgumentParser(description="Packet Analyzer with AI-powered threat detection")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list-interfaces")

    parser_test = subparsers.add_parser("test-connection", help="Test AI API connection")
    parser_test.add_argument("--provider", type=str, default="ollama", 
                            choices=["ollama", "openai", "deepseek", "nvidia", "custom", "off"],
                            help="AI provider: ollama, openai, deepseek, nvidia, custom, off")
    parser_test.add_argument("--api-key", type=str, help="API key for cloud providers")
    parser_test.add_argument("--api-base", type=str, help="API base URL (for ollama/custom)")
    parser_test.add_argument("--model", type=str, help="Model name to use")

    parser_capture = subparsers.add_parser("capture")
    parser_capture.add_argument("-i", "--interface", required=True)
    parser_capture.add_argument("-c", "--count", type=int, default=10)
    parser_capture.add_argument("-p", "--port", type=int)
    parser_capture.add_argument("--provider", type=str, default="ollama",
                               choices=["ollama", "openai", "deepseek", "nvidia", "custom", "off"],
                               help="AI provider: ollama, openai, deepseek, nvidia, custom, off")
    parser_capture.add_argument("--api-key", type=str, help="API key for cloud providers")
    parser_capture.add_argument("--api-base", type=str, help="API base URL (for ollama/custom)")
    parser_capture.add_argument("--model", type=str, help="Model name to use")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.command == "list-interfaces":
        analyzer.list_interfaces()
    elif args.command == "test-connection":
        # 测试 API 连接
        client = AIClient(
            provider=args.provider,
            api_key=args.api_key,
            model=args.model,
            api_base=args.api_base
        )
        result = client.test_connection()
        print(json.dumps(result), flush=True)
    elif args.command == "capture":
        # 优雅处理 Ctrl+C
        def signal_handler(sig, frame):
            if analyzer.is_capturing:
                analyzer.is_capturing = False
            sys.exit(0)
        
        import signal
        signal.signal(signal.SIGINT, signal_handler)

        analyzer.capture_and_analyze(
            args.interface, 
            args.count, 
            args.port, 
            provider=args.provider,
            api_key=args.api_key,
            model=args.model,
            api_base=args.api_base
        )

if __name__ == "__main__":
    main()
