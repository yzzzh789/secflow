#!/usr/bin/env python3
"""
网卡流量监控 WebSocket 服务
提供实时流量数据和历史数据查询
"""
import json
import sys
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional

import psutil

# 导入现有的 nic_monitor 模块
from nic_monitor.storage import SQLiteStorage, TrafficRow
from nic_monitor.state import SharedState, RatePoint
from nic_monitor.collector import TrafficCollector, CollectorConfig
from nic_monitor.utils import utc_now_epoch_s, format_local_ts, parse_local_ts, bps_to_mbps


class NICMonitorServer:
    def __init__(self, db_path: str = "data/nic_traffic.sqlite"):
        self.db_path = Path(db_path)
        self.storage = SQLiteStorage(self.db_path)
        self.state = SharedState(live_keep_seconds=3600)
        self.collector = TrafficCollector(
            storage=self.storage,
            state=self.state,
            config=CollectorConfig(interval_s=1.0)
        )
        self.running = False

    def start_collector(self):
        """启动流量采集"""
        if not self.running:
            self.collector.start()
            self.running = True
            self._send_message("info", "流量采集已启动")

    def stop_collector(self):
        """停止流量采集"""
        if self.running:
            self.collector.stop()
            self.running = False
            self._send_message("info", "流量采集已停止")

    def get_available_nics(self) -> List[Dict]:
        """获取所有可用的网卡"""
        nics = []
        stats = psutil.net_io_counters(pernic=True)
        for name, io in stats.items():
            nics.append({
                "name": name,
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv
            })
        return nics

    def get_realtime_data(self, nics: List[str]) -> Dict:
        """获取实时数据"""
        current = self.state.get_current(nics)
        data = {}
        for nic, point in current.items():
            data[nic] = {
                "timestamp": point.ts,
                "rx_bps": point.rx_bps,
                "tx_bps": point.tx_bps,
                "total_bps": point.rx_bps + point.tx_bps,
                "rx_mbps": bps_to_mbps(point.rx_bps),
                "tx_mbps": bps_to_mbps(point.tx_bps),
                "total_mbps": bps_to_mbps(point.rx_bps + point.tx_bps)
            }
        return data

    def get_live_series(self, nics: List[str], seconds: int = 600) -> Dict:
        """获取实时时间序列数据"""
        series = self.state.get_live_series(nics, last_seconds=seconds)
        data = {}
        for nic, points in series.items():
            data[nic] = [
                {
                    "ts": p.ts,
                    "rx_bps": p.rx_bps,
                    "tx_bps": p.tx_bps,
                    "total_bps": p.rx_bps + p.tx_bps
                }
                for p in points
            ]
        return data

    def get_history_data(self, nics: List[str], start_ts: int, end_ts: int) -> Dict:
        """获取历史数据"""
        rows = self.storage.query_range(nics=nics, ts_start=start_ts, ts_end=end_ts)

        # 按网卡分组
        data = {nic: [] for nic in nics}
        for row in rows:
            if row.nic in data:
                data[row.nic].append({
                    "ts": row.ts,
                    "rx_bps": row.rx_bps,
                    "tx_bps": row.tx_bps,
                    "total_bps": row.rx_bps + row.tx_bps
                })

        return data

    def get_statistics(self, nics: List[str], start_ts: int, end_ts: int) -> Dict:
        """获取统计数据"""
        rows = self.storage.query_range(nics=nics, ts_start=start_ts, ts_end=end_ts)

        stats = {}
        for nic in nics:
            nic_rows = [r for r in rows if r.nic == nic]
            if not nic_rows:
                continue

            rx_values = [r.rx_bps for r in nic_rows]
            tx_values = [r.tx_bps for r in nic_rows]
            total_values = [r.rx_bps + r.tx_bps for r in nic_rows]

            stats[nic] = {
                "rx": {
                    "max": max(rx_values) if rx_values else 0,
                    "min": min(rx_values) if rx_values else 0,
                    "avg": sum(rx_values) / len(rx_values) if rx_values else 0,
                    "total_bytes": sum(rx_values) * 1  # 假设1秒采样间隔
                },
                "tx": {
                    "max": max(tx_values) if tx_values else 0,
                    "min": min(tx_values) if tx_values else 0,
                    "avg": sum(tx_values) / len(tx_values) if tx_values else 0,
                    "total_bytes": sum(tx_values) * 1
                },
                "total": {
                    "max": max(total_values) if total_values else 0,
                    "min": min(total_values) if total_values else 0,
                    "avg": sum(total_values) / len(total_values) if total_values else 0,
                    "total_bytes": sum(total_values) * 1
                },
                "sample_count": len(nic_rows)
            }

        return stats

    def _send_message(self, msg_type: str, message: str, data: Optional[Dict] = None):
        """发送消息到stdout"""
        output = {
            "type": msg_type,
            "message": message,
            "timestamp": utc_now_epoch_s()
        }
        if data:
            output["data"] = data
        print(json.dumps(output, ensure_ascii=False), flush=True)

    def run_realtime_mode(self, nics: List[str], interval: float = 1.0):
        """实时模式：持续发送实时数据"""
        self.start_collector()

        try:
            while True:
                data = self.get_realtime_data(nics)
                self._send_message("realtime_data", "实时数据", data)
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stop_collector()

    def handle_command(self, command: Dict):
        """处理命令"""
        action = command.get("action")

        if action == "list_nics":
            nics = self.get_available_nics()
            self._send_message("nic_list", "网卡列表", {"nics": nics})

        elif action == "start":
            self.start_collector()

        elif action == "stop":
            self.stop_collector()

        elif action == "realtime":
            nics = command.get("nics", [])
            data = self.get_realtime_data(nics)
            self._send_message("realtime_data", "实时数据", data)

        elif action == "live_series":
            nics = command.get("nics", [])
            seconds = command.get("seconds", 600)
            data = self.get_live_series(nics, seconds)
            self._send_message("live_series", "实时序列数据", data)

        elif action == "history":
            nics = command.get("nics", [])
            start_ts = command.get("start_ts", 0)
            end_ts = command.get("end_ts", utc_now_epoch_s())
            data = self.get_history_data(nics, start_ts, end_ts)
            self._send_message("history_data", "历史数据", data)

        elif action == "statistics":
            nics = command.get("nics", [])
            start_ts = command.get("start_ts", 0)
            end_ts = command.get("end_ts", utc_now_epoch_s())
            stats = self.get_statistics(nics, start_ts, end_ts)
            self._send_message("statistics", "统计数据", stats)


def main():
    parser = argparse.ArgumentParser(description="网卡流量监控服务")
    parser.add_argument("--db", default="data/nic_traffic.sqlite", help="数据库路径")
    parser.add_argument("--mode", choices=["realtime", "interactive"], default="interactive",
                        help="运行模式：realtime(实时推送) 或 interactive(命令交互)")
    parser.add_argument("--nics", nargs="+", help="要监控的网卡列表")
    parser.add_argument("--interval", type=float, default=1.0, help="实时模式的更新间隔(秒)")

    args = parser.parse_args()

    server = NICMonitorServer(db_path=args.db)

    if args.mode == "realtime":
        # 实时模式：持续推送数据
        nics = args.nics or []
        if not nics:
            # 如果没有指定网卡，获取所有网卡
            all_nics = server.get_available_nics()
            nics = [n["name"] for n in all_nics]

        server.run_realtime_mode(nics, args.interval)

    else:
        # 交互模式：从stdin读取命令
        server.start_collector()
        server._send_message("info", "服务已启动，等待命令...")

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    command = json.loads(line)
                    server.handle_command(command)
                except json.JSONDecodeError as e:
                    server._send_message("error", f"JSON解析错误: {e}")
                except Exception as e:
                    server._send_message("error", f"处理命令时出错: {e}")

        except KeyboardInterrupt:
            pass
        finally:
            server.stop_collector()


if __name__ == "__main__":
    main()
