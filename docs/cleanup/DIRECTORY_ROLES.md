# 目录角色说明

## 当前判断

这个仓库当前的问题不是“文件太多”，而是“目录职责混在一起”。源代码、遗留内容、运行产物、部署文件和文档离得太近，导致仓库阅读成本偏高。

## 当前角色划分

### 当前主链路

- `main.go`
  当前整合后产品的主 Go 服务入口。
- `static/`
  当前前端页面和浏览器静态资源。
- `packet_analyzer/`
  威胁抓包与分析模块。
- `scripts/traffic_analyzer.py`
  行为分析模块。
- `scripts/lan_behavior_monitor.py`
  局域网监控模块。
- `nic_monitor/`
  NIC 采集、状态和存储的公共层。
- `traffic_monitor/nic_monitor_server_enhanced.py`
  当前主系统仍在使用的 NIC 运行时文件。
- `website_security_backend.go`
  网站安全后端逻辑。

### 混合遗留区

- `traffic_monitor/`
  这个目录已经不是当前项目的总入口，但里面仍然保留了一个被当前主链路依赖的运行时文件。因此它应被视为“遗留区 + 局部仍被依赖”，而不是可以直接当作独立模块或直接删除的目录。

### 支撑与交付层

- `docs/`
  项目说明、架构文档和整理文档。
- `start_monitor.bat`

### 运行产物层

- `data/`
  本地数据库和状态文件。
- `.gocache/`
  本地 Go 构建缓存。
- `traffic_monitor/__chrome_profile/`
- `traffic_monitor/__edge_profile/`
- `traffic_monitor/.gocache_traffic/`
- 任意 `__pycache__/`
- 任意 `*.exe`

## 当前最安全的目录策略

现在适合做的：

- 保持主链路路径不变
- 先把目录职责写清楚
- 继续把运行产物排除在版本控制之外
- 把遗留目录明确标识出来

后续再做的：

- 等路径依赖审计完成后，再考虑把 Go 入口移到 `cmd/`
- 把 Go 内部逻辑拆到 `internal/`
- 把 Python 业务模块归并到统一父目录
- 等 `traffic_monitor/` 的当前依赖完全解除后，再独立迁出或收口

## 实际工作规则

在路径审计完成前：

- 不要把 `traffic_monitor/` 当成可以直接删掉的目录
- 不要把根目录文件默认都当成唯一真相来源
- 当前应把 `main.go` + `static/` + 现有 Python 主模块视为真实交付路径
