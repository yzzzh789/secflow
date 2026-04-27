# traffic_monitor 收敛边界（第二轮）

## 目标

在不破坏当前主链路的前提下，先把 `traffic_monitor/` 从“黑箱目录”变成“有边界的兼容区”。

## 当前结论

- 根服务当前仍依赖：
  - `traffic_monitor/nic_monitor_server_enhanced.py`
- 其余内容大多为历史实现、兼容脚本或运行产物上下文。

## 本轮已落地

1. 在 `traffic_monitor/README_LEGACY_BOUNDARY.md` 增加了目录边界说明。
2. 明确“先标记、后迁移、最后删除”的节奏，避免直接删目录导致回归。

## 冻结要求（本阶段）

1. 不改 `main.go` 对 `nic_monitor_server_enhanced.py` 的现有调用路径。
2. 不删除 `traffic_monitor/` 目录。
3. 不在本轮重写 NIC 监控协议。

## 下一轮建议

1. 先完成调用点审计（入口、参数、stdout/stderr 协议）。
2. 增加适配层，隔离脚本路径。
3. 再做目录归档与历史文件清理。
