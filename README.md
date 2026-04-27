# SecFlow

SecFlow 是一个本地化网络安全分析平台，采用 Go + Python 的组合架构，提供统一 Web 界面，用于抓包威胁检测、上网行为分析、局域网资产监测、网卡流量监控和网站安全巡检。

默认访问地址：

```text
http://localhost:9090
```

当前主入口：

```powershell
go run ./cmd/secflow
```

兼容入口：

```powershell
go run .
```


功能介绍

### 1. 威胁检测

- 选择网卡后实时抓包
- 对报文进行基础解析和风险判断
- 展示源 IP、目标 IP、协议、摘要、详情等信息
- 支持威胁事件汇总和可视化展示

页面入口：

- `static/analyzer.html`

### 2. 上网行为分析

- 对访问会话进行聚合分析
- 展示实时会话、网页日志、搜索日志、违规统计
- 支持生成周报、月报
- 可结合 AI 配置进行更深层的行为识别

页面入口：

- `static/report.html`

### 3. 局域网监测

- 识别内网 IP 的访问模式
- 统计设备风险分、请求数、域名数量、活跃时间
- 展示分类统计、高频域名、风险事件
- 用于发现异常主机和高风险资产

页面入口：

- `static/lan_monitor.html`

### 4. 网卡流量监控

- 监控一个或多个网卡的实时 RX / TX / 总流量
- 查看时间窗口内趋势曲线
- 支持历史数据加载、统计汇总、CSV 导出
- `static/nic_traffic.html` 为当前推荐入口

页面入口：

- `static/nic_traffic.html`
- `static/traffic_monitor.html`（兼容入口）

### 5. 网站安全巡检

- 添加待监测网站
- 检查可用性、页面篡改、恶意脚本、敏感内容、暴露入口、安全基线
- 保存网站状态、威胁事件和日志
- 适合做轻量的站点安全巡检

页面入口：

- `static/website_security.html`

### 6. 统一总览与配置

- 首页统一展示各模块运行状态
- 汇总威胁分布、资产风险、近期事件、趋势数据
- 支持 AI 参数配置

页面入口：

- `static/index.html`
- `static/settings.html`

目录结构

```text
secflow/
├─ cmd/
│  └─ secflow/                Go 主入口
├─ internal/
│  └─ app/                    Go 核心服务与业务逻辑
├─ static/                    前端页面与脚本
├─ scripts/                   Python 分析脚本与运行时入口
├─ packet_analyzer/           报文分析相关脚本
├─ nic_monitor/               网卡监控共享层
├─ traffic_monitor/           兼容保留区，仍含 NIC 相关依赖
├─ data/                      运行期数据
├─ docs/                      架构与清理文档
├─ legacy/                    历史遗留代码
├─ main.go                    兼容入口
├─ go.mod
└─ README.md
```

运行环境

建议环境：

- Go 1.23 或更高版本
- Python 3.10 及以上
- Windows 或 Linux

Python 依赖至少包括：

```text
psutil>=5.9
matplotlib>=3.7
```

安装方式：

```powershell
pip install -r requirements-nic-monitor.txt
```

如果威胁检测、行为分析脚本还依赖其他本地库，需要按实际报错继续补装。

快速开始

### 方式 A：本机开发/测试部署

这是当前最直接、最推荐的方式。

#### 1. 获取代码

```powershell
git clone <your-repo-url>
cd secflow
```

#### 2. 安装 Go 依赖

```powershell
go mod download
```

#### 3. 安装 Python 依赖

```powershell
pip install -r requirements-nic-monitor.txt
```

如果你使用虚拟环境，建议先创建并激活虚拟环境再安装：

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-nic-monitor.txt
```

#### 4. 启动服务

```powershell
go run ./cmd/secflow
```

启动后访问：

```text
http://localhost:9090
```

### 方式 B：生成可执行文件后部署

适合在单机环境直接运行。

#### 1. 构建 Go 服务

```powershell
go build -o secflow.exe ./cmd/secflow
```

#### 2. 启动程序

```powershell
.\secflow.exe
```

#### 3. 保持 Python 运行环境可用

SecFlow 的多个功能依赖 Python 脚本，所以部署机上仍需具备：

- Python 解释器
- 已安装的 Python 依赖
- 完整的项目目录结构，尤其是：
  - `scripts/`
  - `packet_analyzer/`
  - `traffic_monitor/`
  - `nic_monitor/`

不建议只拷贝 `secflow.exe` 单文件运行。

Linux 部署说明

当前仓库的主线仍然偏向本机运行，但在 Linux 上同样可以部署。需要注意的是，抓包、网卡统计和部分局域网监测能力通常需要更高权限。

### 1. 安装系统依赖

以 Ubuntu / Debian 为例：

```bash
sudo apt update
sudo apt install -y git golang python3 python3-venv python3-pip
```

如果后续抓包脚本依赖系统抓包能力，建议额外安装：

```bash
sudo apt install -y tcpdump
```

### 2. 获取代码

```bash
git clone <your-repo-url>
cd secflow
```

### 3. 安装 Go 依赖

```bash
go mod download
```

### 4. 创建 Python 虚拟环境

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-nic-monitor.txt
```

如果运行过程中提示缺少其他 Python 包，再按报错补装。

### 5. 启动服务

```bash
source .venv/bin/activate
go run ./cmd/secflow
```

服务启动后访问：

```text
http://localhost:9090
```

### 6. Linux 下构建二进制

```bash
go build -o secflow ./cmd/secflow
```

运行方式：

```bash
source .venv/bin/activate
./secflow
```

### 7. 使用 systemd 部署

如果要长期运行，建议使用 `systemd`。

示例服务文件：

```ini
[Unit]
Description=SecFlow
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/secflow
Environment="PATH=/opt/secflow/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/secflow/secflow
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

说明：

- `WorkingDirectory` 改成你的项目目录
- 如果你不是直接运行二进制，而是用 `go run`，则 `ExecStart` 需要改掉
- 如果涉及抓包，很多情况下需要 `root` 或具备等效网络采集权限

启用方式：

```bash
sudo cp secflow.service /etc/systemd/system/secflow.service
sudo systemctl daemon-reload
sudo systemctl enable secflow
sudo systemctl start secflow
sudo systemctl status secflow
```

### 8. Linux 部署注意事项

- 当前仓库里有一些 Windows 启动脚本，如 `start_monitor.bat`、`start_host_agent.bat`，Linux 下不使用
- `traffic_monitor/` 目录仍保留兼容依赖，不要删除
- 如果要抓包，可能需要 root 权限，或给 Python/抓包工具授予网络采集能力
- 如果服务器启用了防火墙，需要放行 `9090` 端口

部署说明与注意事项

### 1. 数据文件

以下内容属于运行产物，不是源码：

- `data/*.sqlite`
- `data/*.sqlite-shm`
- `data/*.sqlite-wal`
- `data/website_security_state.json`
- `__pycache__/`
- `.gocache/`

首次启动时，如果部分数据文件不存在，程序通常会自动创建。

### 2. 端口

默认监听：

```text
9090
```

如果端口被占用，需要检查服务配置或本地占用情况。

### 3. 权限

涉及抓包、网卡监控、局域网监测时，可能需要更高权限运行终端，否则部分功能可能无法正常采集数据。

### 4. 兼容目录

`traffic_monitor/` 不是当前主产品根目录，但其中仍保留了网卡监控相关兼容依赖。当前阶段不要随意删除。



常用命令

启动主服务：

```powershell
go run ./cmd/secflow
```

兼容启动方式：

```powershell
go run .
```

运行测试：

```powershell
go test ./...
```

Linux 下常用启动：

```bash
source .venv/bin/activate
go run ./cmd/secflow
```

补充说明

- `start_host_agent.bat` 用于启动主机侧辅助脚本
- 当前主线产品以 Go 服务 + 静态前端 + Python 分析模块为核心
