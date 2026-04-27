# UI 乱码审计清单

更新时间：2026-04-27

## 判定规则

- `????` / `??`：文本已丢失，需人工按上下文补写
- `鎬昏` / `璇锋眰` 一类：典型转码乱码，可批量反解后再校对

## 实际确认的前端乱码文件

- `static/script.js`
- `static/report.js`
- `static/lan_monitor.js`
- `static/nic_traffic.js`

## 实际确认的后端界面文案乱码文件

- `internal/app/overview_helpers.go`
- `internal/app/overview_service.go`
- `internal/app/overview_queries.go`
- `internal/app/website_security_checks.go`
- `internal/app/website_security_helpers.go`

## 排除项

- 多个 `static/*.html` 页面在终端中会显示成假乱码，但文件本身是正常 UTF-8，不属于本次真实问题源。

## 已确认的高频乱码类型

- 导航与页面标题
- 按钮文案
- 空状态提示
- 运行状态提示
- 图表图例与统计标签
- 网站安全模块的后端错误/告警提示

## 处理结果

- 已统一修复前端主交互页面中的 `??` / `????`
- 已统一修复总览页与网站安全模块的后端返回乱码
- 当前审计规则下未发现剩余真实乱码
