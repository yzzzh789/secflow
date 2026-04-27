# 网卡流量监控工具（Python）

特点：
- 每秒采集一次所有网络接口（网卡）流量（RX/TX）
- 简单图形界面：多选网卡，查看当前速率与历史折线图
- 数据持续写入 SQLite，支持按时间范围查询
- 低 CPU：采集 1Hz，图表刷新 0.5Hz

## 依赖安装

```bash
pip install -r requirements-nic-monitor.txt
```

## 运行

```bash
python run_nic_monitor.py
# 或
python -m nic_monitor
```

默认数据库文件：`nic_traffic.sqlite`（会持续记录全部网卡，界面选择仅影响显示与查询）

存储字段：
- `ts`：UTC 时间戳（epoch seconds）
- `nic`：网卡名称
- `rx_bps`：接收速率（bytes/sec）
- `tx_bps`：发送速率（bytes/sec）

## 使用说明

- 左侧选择网卡（可多选）→ 点击“应用选择”
- “实时”模式：显示最近 10 分钟折线图（可在代码中修改 `UIConfig.live_window_s`）
- “历史”模式：填写开始/结束时间（本地时间，格式 `YYYY-mm-dd HH:MM:SS`）→ 点击“加载”
- “曲线指标”：`total` / `rx` / `tx`
