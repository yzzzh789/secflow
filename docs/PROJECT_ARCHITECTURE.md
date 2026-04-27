# SecFlow 项目结构说明

这份文档用于说明当前仓库中哪些部分属于主线产品，哪些部分属于历史遗留，哪些部分属于运行态数据或产物，避免后续整理时误判边界。

## 1. 当前主线

### 后端主线

- `main.go`
  负责：
  - 静态文件分发
  - 产品总览接口
  - 任务启动/停止
  - 运行状态恢复
  - WebSocket 转发
  - 多模块数据聚合

- `website_security_backend.go`
  负责网站安全监测的状态管理、定时检测、威胁记录和日志落盘。

### 前端主线

- `static/index.html`
  当前总览页
- `static/analyzer.html`
  威胁检测页
- `static/report.html`
  行为分析页
- `static/lan_monitor.html`
  局域网监控页
- `static/nic_traffic.html`
  网卡流量页
- `static/traffic_monitor.html`
  历史兼容流量页，当前仍可访问
- `static/website_security.html`
  网站安全页
- `static/settings.html`
  AI 配置页

以上页面都由主服务直接分发。

### Python 主线模块

- `packet_analyzer/improved_packet_analyzer.py`
  威胁检测与抓包分析
- `scripts/traffic_analyzer.py`
  行为分析
- `scripts/lan_behavior_monitor.py`
  局域网监控
- `traffic_monitor/nic_monitor_server_enhanced.py`
  当前主线使用的 NIC 流量服务

### Python 公共层

- `nic_monitor/collector.py`
  网卡流量采集
- `nic_monitor/state.py`
  实时状态与时间序列缓存
- `nic_monitor/storage.py`
  NIC 历史数据 SQLite 存储
- `nic_monitor/__main__.py`
  独立 Tk UI 入口，不是当前主产品主入口

## 2. 历史遗留与兼容区域

### `traffic_monitor/`

该目录仍有价值，但不应再被误认为全项目唯一主入口。

当前它同时包含：

- 旧独立 Go 服务实现
- 旧 NIC 流量监控脚本
- 历史部署相关文件与说明
- 历史 HTML 与兼容资源
- 本地运行产生的缓存、profile 和二进制

当前主线仍直接复用其中的 `nic_monitor_server_enhanced.py`，因此这个目录目前属于“遗留区 + 局部仍被主线依赖”的混合区域。

在未完成收敛前，不建议直接删除整个目录。

## 3. 运行态数据与产物

以下内容属于运行态数据、缓存或编译产物，不应被视为主线源码：

- `data/`
  - `packet_analyzer.sqlite`
  - `nic_traffic.sqlite`
  - `website_security_state.json`
- `.gocache/`
- `__pycache__/`
- `*.exe`
- 浏览器 profile 目录
- Crash dump / `.dmp` / `.pma`

这些内容在认知上应与源码隔离。

## 4. 当前主存储现状

当前主线存储并未统一到单一数据库：

- 主服务数据：SQLite
- NIC 历史数据：独立 SQLite
- 网站安全状态：JSON 文件

## 5. 当前最需要治理的部分

### 文档口径

目前最需要先统一的是：

- 主入口是谁
- 默认端口是 `9090` 还是历史材料中的 `8080`
- 当前主存储是 SQLite/JSON
- `traffic_monitor/` 的真实角色

### 目录边界

需要明确区分：

- 主线产品代码
- 遗留/兼容代码
- 运行产物
- 文档

### 重复实现

当前已确认的重复点包括：

- `AIClient` 在多个 Python 脚本中重复实现
- NIC 监控前端存在两套页面与 JS
- `traffic_monitor/` 中同时保留了旧独立方案和当前主线依赖文件

## 6. 当前建议的整理顺序

1. 先整理文档口径
2. 再做目录角色标注
3. 再列运行产物清单
4. 再列命名债和重复债清单
5. 最后锁定暂时不能动的稳定边界

## 7. 当前不应优先改动的边界

在结构收敛前，以下内容应暂时视为稳定边界：

- `main.go` 中现有 HTTP 路由集合
- 主服务到 Python 脚本的启动参数协议
- `traffic_monitor/nic_monitor_server_enhanced.py` 的 stdin / stdout 命令协议
- 当前 SQLite 表结构
- 网站安全 JSON 状态文件结构
- 前端页面对现有 API 与 WebSocket 的依赖关系

后续整理应优先做“澄清和收敛”，而不是先做行为改写。
