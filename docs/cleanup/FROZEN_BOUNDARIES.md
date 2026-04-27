# 当前冻结边界

这些边界在当前整理阶段应保持稳定。

## 暂时不要移动

- `main.go`
- `static/`
- `packet_analyzer/improved_packet_analyzer.py`
- `scripts/traffic_analyzer.py`
- `scripts/lan_behavior_monitor.py`
- `traffic_monitor/nic_monitor_server_enhanced.py`
- `nic_monitor/`
- `website_security_backend.go`

## 暂时不要改动

- `main.go` 暴露的现有 HTTP 路由
- 静态页面 URL 和相对资源路径
- Go 调用 Python 的脚本路径
- Python 运行时使用的 stdin/stdout 协议
- 当前运行所依赖的 SQLite 文件位置
- 网站安全模块使用的 JSON 状态结构

## 为什么这些边界要冻结

如果在这个阶段提前动它们，最容易出现以下回归：

- 任务无法启动
- 页面路由失效
- 脚本找不到
- 本地数据加载失败
- Go 与 Python 之间出现静默不匹配

## 在迁移前安全可做的事

- 写清楚边界
- 写清楚职责
- 把运行产物排除出版本控制
- 准备 GitHub 上传口径
- 建立后续迁移清单

## 未来迁移前必须确认

1. 所有调用点都已查清
2. 文件路径已经集中或完成审计
3. 启动命令已经验证
4. 前端引用关系已经验证
5. 存在回滚路径
