# 运行产物清单

## 为什么要单独列出来

当前仓库的一部分“杂乱感”来自运行产物和本地缓存直接混在代码旁边。它们应该被视为本地状态，而不是项目源码的一部分。

## 已经确认存在的运行产物

### 根目录产物

- `.gocache/`
- `packet_analyzer.exe`

### 数据目录产物

- `data/*.sqlite`
- `data/*.sqlite-shm`
- `data/*.sqlite-wal`
- `data/website_security_state.json`

### `traffic_monitor/` 下的本地产物

- `traffic_monitor/.gocache_traffic/`
- `traffic_monitor/__chrome_profile/`
- `traffic_monitor/__edge_profile/`
- `traffic_monitor/__pycache__/`
- `traffic_monitor/traffic_monitor.exe`
- `traffic_monitor/*.bak`
- `traffic_monitor` 目录下的 `*.dmp`、`*.pma`

### Python 缓存产物

- 任意 `__pycache__/`
- 任意 `*.pyc`

## GitHub 上传原则

不应该上传：

- 本地缓存目录
- 本地浏览器 profile
- 编译产物
- 本地数据库
- 本地状态快照
- crash dump

可以上传：

- 源代码
- 文档
- 部署文件
- 明确属于产品交付内容的静态资源

## 工作规则

如果一个文件是以下方式生成的：

- 运行程序时生成
- 编译程序时生成
- 打开浏览器 profile 时生成
- 保存本机状态时生成

那么默认应该忽略，除非存在非常明确的版本化理由。
