package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func loadProductOverviewStats(packetDB *sql.DB, websiteState websiteSecurityState, activeNICs, healthyModules, totalModules int) productOverviewStats {
	var totalPackets, threatEvents, behaviorSessions, lanAssets, highRiskAssets int
	err := packetDB.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM packet_events),
			(SELECT COUNT(*) FROM packet_events WHERE is_threat = 1),
			(SELECT COUNT(*) FROM behavior_sessions),
			(SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports),
			(SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports WHERE risk_level IN ('high', 'medium'))
	`).Scan(&totalPackets, &threatEvents, &behaviorSessions, &lanAssets, &highRiskAssets)
	if err != nil {
		totalPackets = queryInt(packetDB, `SELECT COUNT(*) FROM packet_events`)
		threatEvents = queryInt(packetDB, `SELECT COUNT(*) FROM packet_events WHERE is_threat = 1`)
		behaviorSessions = queryInt(packetDB, `SELECT COUNT(*) FROM behavior_sessions`)
		lanAssets = queryInt(packetDB, `SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports`)
		highRiskAssets = queryInt(packetDB, `SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports WHERE risk_level IN ('high', 'medium')`)
	}

	threatRate := 0.0
	if totalPackets > 0 {
		threatRate = float64(threatEvents) / float64(totalPackets) * 100.0
	}

	monitoredWebsites := websiteState.Metrics.TotalWebsites
	websiteThreats := len(websiteState.Threats)
	websiteIssues := websiteState.Metrics.ActiveIssues

	return productOverviewStats{
		TotalPackets:       totalPackets,
		ThreatEvents:       threatEvents,
		ThreatRate:         threatRate,
		BehaviorSessions:   behaviorSessions,
		LANAssets:          lanAssets,
		HighRiskAssets:     highRiskAssets,
		MonitoredWebsites:  monitoredWebsites,
		WebsiteThreats:     websiteThreats,
		WebsiteIssues:      websiteIssues,
		ActiveNICs:         activeNICs,
		HealthyModules:     healthyModules,
		TotalModules:       totalModules,
		MonitoringCoverage: fmt.Sprintf("%d/%d 模块处于实时状态", healthyModules, totalModules),
	}
}

func buildModuleStatuses(packetDB *sql.DB, websiteState websiteSecurityState, activeNICs int, nicUpdatedAt time.Time, nicPeak int64) []productModuleStatus {
	threatUpdatedAt := parseSQLiteTime(queryString(packetDB, `
		SELECT MAX(ts) FROM (
			SELECT MAX(captured_at) AS ts FROM packet_events
			UNION ALL
			SELECT MAX(created_at) AS ts FROM ingest_logs WHERE source = 'threat_detection'
		)
	`))
	threatStatus, threatLabel := moduleStatusFor(threatUpdatedAt, 15*time.Minute, 6*time.Hour)
	threats24h := queryInt(packetDB, `SELECT COUNT(*) FROM packet_events WHERE is_threat = 1 AND captured_at >= datetime('now', '-1 day')`)
	packets24h := queryInt(packetDB, `SELECT COUNT(*) FROM packet_events WHERE captured_at >= datetime('now', '-1 day')`)
	threatMetric := fmt.Sprintf("%d 个威胁事件 / 24h", threats24h)
	threatDetail := fmt.Sprintf("最近 24 小时分析了 %d 条报文，可继续查看威胁详情。", packets24h)

	if fields, ok := taskSupervisor.RuntimeFields(taskKeyThreat); ok && !threatCaptureHub.IsActive() {
		if fields.RuntimeStatus == taskStatusBackoff {
			threatStatus = "warning"
			threatLabel = "恢复中"
			threatDetail = "威胁检测进程异常退出，系统正在自动重启。回到模块页后可继续查看实时输出。"
		}
	}

	if threatCaptureHub.IsActive() {
		threatStatus = "healthy"
		threatLabel = "运行中"
		runtimeInfo := threatCaptureHub.RuntimeInfo()
		if runtimeInfo.LastCommand.Interface != "" {
			threatMetric = fmt.Sprintf("正在监测 %s", runtimeInfo.LastCommand.Interface)
		} else {
			threatMetric = "正在实时监测"
		}
		threatDetail = "抓包任务仍在后台运行，返回页面后会自动接回实时输出。"
	}

	behaviorUpdatedAt := parseSQLiteTime(queryString(packetDB, `SELECT MAX(last_seen) FROM behavior_sessions`))
	behaviorStatus, behaviorLabel := moduleStatusFor(behaviorUpdatedAt, 15*time.Minute, 6*time.Hour)
	behaviorRisk := queryInt(packetDB, `SELECT COUNT(*) FROM behavior_sessions WHERE risk_level IN ('high', 'medium')`)
	behaviorCount := queryInt(packetDB, `SELECT COUNT(*) FROM behavior_sessions`)
	behaviorMetric := fmt.Sprintf("%d 条会话", behaviorCount)
	behaviorDetail := fmt.Sprintf("%d 条会话被标记为中高风险，可继续查看访问意图。", behaviorRisk)

	if fields, ok := taskSupervisor.RuntimeFields(taskKeyBehavior); ok && !behaviorAnalysisHub.IsActive() {
		if fields.RuntimeStatus == taskStatusBackoff {
			behaviorStatus = "warning"
			behaviorLabel = "恢复中"
			behaviorDetail = "行为分析进程正在自动恢复，任务参数和恢复状态都已保留。"
		}
	}

	if behaviorAnalysisHub.IsActive() {
		behaviorStatus = "healthy"
		behaviorLabel = "运行中"
		runtimeInfo := behaviorAnalysisHub.RuntimeInfo()
		if runtimeInfo.LastCommand.Interface != "" {
			behaviorMetric = fmt.Sprintf("正在分析 %s", runtimeInfo.LastCommand.Interface)
		} else {
			behaviorMetric = "正在实时分析"
		}
		behaviorDetail = "行为分析仍在后台运行，返回页面后会自动恢复会话流。"
	}

	lanUpdatedAt := parseSQLiteTime(queryString(packetDB, `SELECT MAX(captured_at) FROM lan_behavior_reports`))
	lanStatus, lanLabel := moduleStatusFor(lanUpdatedAt, 15*time.Minute, 6*time.Hour)
	lanAssets := queryInt(packetDB, `SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports`)
	lanRisk := queryInt(packetDB, `SELECT COUNT(DISTINCT ip_address) FROM lan_behavior_reports WHERE risk_level IN ('high', 'medium')`)
	lanMetric := fmt.Sprintf("%d 台资产", lanAssets)
	lanDetail := fmt.Sprintf("%d 台资产存在中高风险画像，可继续做资产侧审计。", lanRisk)

	if fields, ok := taskSupervisor.RuntimeFields(taskKeyLAN); ok && !lanMonitorHub.IsActive() {
		if fields.RuntimeStatus == taskStatusBackoff {
			lanStatus = "warning"
			lanLabel = "恢复中"
			lanDetail = "局域网监测任务正在自动恢复，上一次监测参数已经保留。"
		}
	}

	if lanMonitorHub.IsActive() {
		lanStatus = "healthy"
		lanLabel = "运行中"
		runtimeInfo := lanMonitorHub.RuntimeInfo()
		if runtimeInfo.LastCommand.Interface != "" {
			lanMetric = fmt.Sprintf("正在监测 %s", runtimeInfo.LastCommand.Interface)
		} else {
			lanMetric = "正在实时监测"
		}
		lanDetail = "局域网监测仍在后台记录，离开页面不会丢失资产画像进度。"
	}

	nicStatus, nicLabel := moduleStatusFor(nicUpdatedAt, 3*time.Minute, 20*time.Minute)
	nicMetric := fmt.Sprintf("%d 张活跃网卡", activeNICs)
	nicDetail := fmt.Sprintf("当前最高吞吐 %s，可继续查看实时流量和历史记录。", formatBpsShort(nicPeak))

	if fields, ok := taskSupervisor.RuntimeFields(taskKeyNIC); ok && !nicMonitorHub.IsActive() {
		if fields.RuntimeStatus == taskStatusBackoff {
			nicStatus = "warning"
			nicLabel = "恢复中"
			nicDetail = "网卡流量采集进程正在自动重启，历史数据和已选网卡都不会丢失。"
		}
	}

	if nicMonitorHub.IsActive() {
		nicStatus = "healthy"
		nicLabel = "运行中"
		runtimeInfo := nicMonitorHub.RuntimeInfo()
		if names := runtimeInfo.LastCommand.NICNames(); len(names) > 0 {
			nicMetric = fmt.Sprintf("正在监测 %s", strings.Join(names, ", "))
		}
		nicDetail = "网卡流量采集仍在后台运行，返回页面后会自动恢复实时和历史查询。"
	}

	websiteUpdatedAt := parseRFC3339(websiteState.UpdatedAt)
	websiteStatus, websiteLabel := moduleStatusFor(websiteUpdatedAt, 30*time.Minute, 6*time.Hour)
	websiteMetric := fmt.Sprintf("%d 个站点监测中", websiteState.Metrics.TotalWebsites)
	websiteDetail := fmt.Sprintf(
		"当前有 %d 个活动问题，其中 %d 个为高风险问题。",
		websiteState.Metrics.ActiveIssues,
		websiteState.Metrics.HighRiskIssues,
	)

	if websiteState.Metrics.TotalWebsites == 0 {
		websiteStatus = "idle"
		websiteLabel = "待配置"
		websiteMetric = "还没有添加监测站点"
		websiteDetail = "添加站点后即可统一查看篡改、恶意脚本、敏感内容、可用性和安全基线。"
	} else if websiteState.Metrics.HighRiskIssues > 0 {
		websiteStatus = "warning"
		websiteLabel = "需处理"
	} else if websiteState.Metrics.ActiveIssues > 0 {
		websiteStatus = "warning"
		websiteLabel = "有告警"
	}

	checkingCount := 0
	for _, site := range websiteState.Websites {
		if site.Checking {
			checkingCount++
		}
	}
	if checkingCount > 0 {
		websiteStatus = "healthy"
		websiteLabel = "检测中"
		websiteMetric = fmt.Sprintf("%d 个站点监测中，%d 个正在检测", websiteState.Metrics.TotalWebsites, checkingCount)
	}

	return []productModuleStatus{
		{
			ID:          "threat-detection",
			Name:        "威胁检测",
			Status:      threatStatus,
			StatusLabel: threatLabel,
			UpdatedAt:   formatModuleTime(threatUpdatedAt),
			URL:         "/analyzer.html",
			Metric:      threatMetric,
			Detail:      threatDetail,
		},
		{
			ID:          "behavior-analysis",
			Name:        "行为分析",
			Status:      behaviorStatus,
			StatusLabel: behaviorLabel,
			UpdatedAt:   formatModuleTime(behaviorUpdatedAt),
			URL:         "/report.html",
			Metric:      behaviorMetric,
			Detail:      behaviorDetail,
		},
		{
			ID:          "lan-monitor",
			Name:        "局域网监测",
			Status:      lanStatus,
			StatusLabel: lanLabel,
			UpdatedAt:   formatModuleTime(lanUpdatedAt),
			URL:         "/lan_monitor.html",
			Metric:      lanMetric,
			Detail:      lanDetail,
		},
		{
			ID:          "nic-traffic",
			Name:        "网卡流量",
			Status:      nicStatus,
			StatusLabel: nicLabel,
			UpdatedAt:   formatModuleTime(nicUpdatedAt),
			URL:         "/nic_traffic.html",
			Metric:      nicMetric,
			Detail:      nicDetail,
		},
		{
			ID:          "website-security",
			Name:        "网站安全",
			Status:      websiteStatus,
			StatusLabel: websiteLabel,
			UpdatedAt:   formatModuleTime(websiteUpdatedAt),
			URL:         "/website_security.html",
			Metric:      websiteMetric,
			Detail:      websiteDetail,
		},
	}
}

func buildProductOverviewResponse(packetDB *sql.DB) productOverviewResponse {
	return buildProductOverviewResponseFromStores(
		newSQLitePacketOverviewStore(packetDB),
		newSQLiteNICOverviewStore(resolveNICDatabasePath()),
		newWebsiteServiceStateStore(websiteSecurityServiceInstance),
	)
}

func buildProductOverviewResponseFromStores(packetStore PacketOverviewStore, nicStore NICOverviewStore, websiteStore WebsiteStateStore) productOverviewResponse {
	nicRanking, activeNICs, nicUpdatedAt, nicPeak := nicStore.LoadNICOverview()
	websiteState := websiteStore.Snapshot()

	modules := packetStore.LoadModuleStatuses(websiteState, activeNICs, nicUpdatedAt, nicPeak)
	healthyModules := 0
	for _, module := range modules {
		if module.Status == "healthy" {
			healthyModules++
		}
	}

	return productOverviewResponse{
		GeneratedAt:  time.Now().Format(time.RFC3339),
		Overview:     packetStore.LoadStats(websiteState, activeNICs, healthyModules, len(modules)),
		Modules:      modules,
		ThreatTypes:  packetStore.LoadThreatTypeDistribution(),
		TopAssets:    packetStore.LoadTopAssets(),
		RecentEvents: packetStore.LoadRecentEvents(websiteState),
		DailyTrends:  packetStore.LoadDailyTrends(),
		NICRanking:   nicRanking,
	}
}

func buildProductOverviewPayload(packetDB *sql.DB) ([]byte, error) {
	return json.Marshal(buildProductOverviewResponse(packetDB))
}
