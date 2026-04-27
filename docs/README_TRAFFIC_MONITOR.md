# traffic_monitor 历史子模块说明

## 说明

这份文档描述的是仓库中 `traffic_monitor/` 目录对应的历史流量监控子模块。

它不是当前整个 SecFlow 仓库的总说明，也不代表当前主线产品的唯一架构入口。

当前仓库主线请优先参考：

- `README.md`
- `docs/PROJECT_ARCHITECTURE.md`

## 当前定位

`traffic_monitor/` 目录目前属于：

- 历史独立流量监控方案
- 兼容资源保留区
- 局部仍被主线复用的子模块目录

当前主线仍会直接复用其中的：

- `nic_monitor_server_enhanced.py`

但该目录中的其他内容，如旧 Go 服务、旧 HTML 和历史部署痕迹，并不应再被理解为当前项目唯一正式入口。

## 目录中常见内容

该目录当前可能包含：

- 旧独立 Go 服务实现
- 旧 Python NIC 监控脚本
- 历史前端页面
- 本地运行产生的缓存、profile 和二进制

因此，在整理仓库时，需要先区分：

1. 仍被主线复用的文件
2. 单纯历史保留的文件
3. 运行态产物

## 当前建议

如果你的目标是理解或整理当前主线项目，应优先从以下入口开始：

- `main.go`
- `website_security_backend.go`
- `static/`
- `packet_analyzer/`
- `scripts/`
- `nic_monitor/`
- `traffic_monitor/nic_monitor_server_enhanced.py`

而不是从 `traffic_monitor/` 内部旧独立服务开始。

## 后续整理原则

后续如果继续收敛该目录，建议遵循以下原则：

1. 先标记主线依赖文件
2. 再隔离旧实现与兼容资源
3. 再处理运行产物和缓存
4. 不要在未确认依赖关系前大规模删除文件
