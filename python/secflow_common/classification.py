from __future__ import annotations

import time
from urllib.parse import parse_qs, unquote, urlsplit

from .domains import is_ip_address, root_domain
from .formatting import format_capture_time
from .protocol_types import SearchEvent, TrafficServiceProfile, ViolationEvent

TRAFFIC_SERVICE_FAMILY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("google_family", ("google", "gstatic", "googleapis", "youtube", "ytimg")),
    ("microsoft_family", ("microsoft", "office", "live.com", "msft", "azure")),
    ("github_family", ("github", "githubusercontent", "githubassets")),
    ("bilibili_family", ("bilibili", "hdslb", "bilivideo")),
    ("social_family", ("twitter", "x.com", "facebook", "instagram", "reddit", "zhihu")),
    ("shopping_family", ("taobao", "tmall", "jd.com", "amazon", "pinduoduo")),
)

TRAFFIC_SERVICE_LABEL_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("YouTube", ("youtube", "ytimg")),
    ("Google", ("google", "gstatic", "googleapis")),
    ("GitHub", ("github", "githubusercontent", "githubassets")),
    ("Bilibili", ("bilibili", "hdslb", "bilivideo")),
    ("Microsoft", ("microsoft", "office", "live.com", "azure")),
    ("Chat / Social", ("twitter", "x.com", "facebook", "instagram", "reddit", "discord")),
    ("Shopping", ("taobao", "tmall", "jd.com", "amazon", "pinduoduo")),
    ("Video / Streaming", ("netflix", "twitch", "iqiyi", "youku")),
)

TRAFFIC_SERVICE_TYPE_RULES: tuple[tuple[str, str, str, tuple[str, ...], str, int], ...] = (
    ("system", "系统服务", "系统", ("windowsupdate", "msftconnecttest", "connectivitycheck", "telemetry", "ocsp", "crl", "alidns", "shence-api", "lenovomm", "legionzonecdn", "wup.browser.qq.com"), "Neutral", 0),
    ("work", "工作协作", "工作", ("github", "gitlab", "stackoverflow", "notion", "jira", "confluence", "slack", "teams", "office", "microsoft", "docs.", "openai", "anthropic"), "Productive", 6),
    ("finance", "财经股票", "财经", ("xueqiu", "eastmoney", "finance", "hexun", "cnstock", "jrj.com", "stock", "fund"), "Entertainment", 34),
    ("video", "视频娱乐", "视频", ("youtube", "ytimg", "bilibili", "hdslb", "bilivideo", "youku", "iqiyi", "netflix", "douyin", "tiktok", "twitch", "qqvideo", "mgtv"), "Entertainment", 28),
    ("game", "游戏娱乐", "游戏", ("steam", "steampowered", "epicgames", "riotgames", "4399", "7k7k", "mihoyo", "hoyoverse", "game"), "Entertainment", 32),
    ("social", "社交通讯", "社交", ("twitter", "x.com", "facebook", "instagram", "reddit", "discord", "weibo", "zhihu", "tieba", "qq.com", "wechat", "telegram", "whatsapp"), "Entertainment", 18),
    ("shopping", "购物消费", "购物", ("taobao", "tmall", "jd.com", "amazon", "pinduoduo", "ebay", "meituan"), "Neutral", 14),
)

TRAFFIC_RISK_RULES: tuple[tuple[str, int], ...] = (
    ("malware", 70),
    ("phishing", 70),
    ("scam", 70),
    ("hack", 45),
    ("adult", 35),
    ("torrent", 30),
    ("steam", 18),
    ("epicgames", 18),
    ("bilibili", 15),
    ("youtube", 15),
    ("netflix", 15),
    ("reddit", 12),
    ("twitter", 12),
    ("facebook", 12),
    ("instagram", 12),
    ("taobao", 10),
    ("jd.com", 10),
    ("amazon", 10),
)

TRAFFIC_ENTERTAINMENT_TYPES = {"video", "game", "social", "finance"}

TRAFFIC_SEARCH_ENGINES: dict[str, tuple[str, ...]] = {
    "baidu": ("baidu.com",),
    "google": ("google.com", "google.com.hk", "googleusercontent.com"),
    "bing": ("bing.com",),
    "sogou": ("sogou.com",),
    "so": ("so.com", "haosou.com"),
}

TRAFFIC_SEARCH_QUERY_KEYS = ("q", "wd", "word", "query", "p")

TRAFFIC_APP_CATEGORY_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("YouTube", "视频", ("youtube", "ytimg")),
    ("Bilibili", "视频", ("bilibili", "hdslb", "bilivideo")),
    ("Netflix", "视频", ("netflix",)),
    ("Douyin", "视频", ("douyin", "tiktok")),
    ("Weibo", "社交", ("weibo",)),
    ("Zhihu", "社交", ("zhihu",)),
    ("Reddit", "社交", ("reddit",)),
    ("X", "社交", ("twitter", "x.com")),
    ("Discord", "IM", ("discord",)),
    ("Telegram", "IM", ("telegram",)),
    ("WhatsApp", "IM", ("whatsapp",)),
    ("QQ", "IM", ("qq.com",)),
    ("WeChat", "IM", ("wechat", "weixin")),
    ("Gmail", "邮箱", ("gmail", "googlemail")),
    ("Outlook", "邮箱", ("outlook", "office365", "hotmail", "live.com")),
    ("QQ Mail", "邮箱", ("mail.qq.com", "foxmail")),
    ("Google Drive", "网盘", ("drive.google", "googleusercontent")),
    ("OneDrive", "网盘", ("onedrive", "sharepoint", "1drv")),
    ("Dropbox", "网盘", ("dropbox",)),
    ("GitHub", "开发工具", ("github", "githubusercontent", "githubassets")),
    ("GitLab", "开发工具", ("gitlab",)),
    ("Stack Overflow", "开发工具", ("stackoverflow",)),
    ("Notion", "开发工具", ("notion",)),
    ("OpenAI", "开发工具", ("openai",)),
)

TRAFFIC_BLACKLIST_DOMAINS = {
    "torrentz2.nz",
    "thepiratebay.org",
    "1337x.to",
}

TRAFFIC_HIGH_RISK_KEYWORDS = {
    "破解",
    "外挂",
    "翻墙",
    "赌博",
    "私彩",
    "暗网",
    "木马",
    "病毒",
    "勒索",
    "代理ip",
}

TRAFFIC_ENTERTAINMENT_APP_CATEGORIES = {"视频", "社交"}
TRAFFIC_EVIDENCE_LEVEL_RANKING = {"low": 1, "medium": 2, "high": 3}

LAN_WEBSITE_CATEGORIES: dict[str, dict[str, object]] = {
    "video": {
        "keywords": ["youtube", "bilibili", "youku", "iqiyi", "tencent", "netflix", "douyin", "tiktok", "twitch"],
        "label": "视频娱乐",
        "risk": "high",
    },
    "stock": {
        "keywords": ["xueqiu", "eastmoney", "finance", "hexun", "cnstock", "jrj.com", "stock"],
        "label": "财经股票",
        "risk": "high",
    },
    "social": {
        "keywords": ["weibo", "twitter", "x.com", "facebook", "instagram", "zhihu", "reddit", "tieba", "discord"],
        "label": "社交媒体",
        "risk": "medium",
    },
    "game": {
        "keywords": ["steam", "epicgames", "game", "4399", "7k7k", "youxi"],
        "label": "游戏娱乐",
        "risk": "high",
    },
    "shopping": {
        "keywords": ["taobao", "jd.com", "tmall", "amazon", "pinduoduo", "ebay"],
        "label": "购物网站",
        "risk": "medium",
    },
    "work": {
        "keywords": ["github", "stackoverflow", "gitlab", "docs.", "office", "microsoft", "notion", "jira"],
        "label": "工作相关",
        "risk": "low",
    },
    "malicious": {
        "keywords": ["malware", "phishing", "scam", "ransom", "botnet"],
        "label": "恶意站点",
        "risk": "critical",
    },
}

LAN_MALICIOUS_KEYWORDS = ("malware", "phishing", "scam", "hack", "botnet", "ransom")


def traffic_evidence_level_from_source(source: str) -> str:
    if source == "http_host":
        return "high"
    if source == "tls_sni":
        return "medium"
    return "low"


def traffic_merge_evidence_level(current: str, candidate: str) -> str:
    current_rank = TRAFFIC_EVIDENCE_LEVEL_RANKING.get(current, 0)
    candidate_rank = TRAFFIC_EVIDENCE_LEVEL_RANKING.get(candidate, 0)
    return current if current_rank >= candidate_rank else candidate


def traffic_classify_app_by_domain(domain: str) -> tuple[str, str]:
    domain_lower = domain.lower()
    for app_name, category, patterns in TRAFFIC_APP_CATEGORY_RULES:
        if any(pattern in domain_lower for pattern in patterns):
            return app_name, category
    return root_domain(domain), "网站"


def traffic_resolve_search_engine(domain: str) -> str | None:
    domain_lower = domain.lower()
    for engine, domains in TRAFFIC_SEARCH_ENGINES.items():
        if any(domain_lower == candidate or domain_lower.endswith("." + candidate) for candidate in domains):
            return engine
    return None


def traffic_extract_http_request_target(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        head = payload[:4096].decode("latin-1", errors="ignore")
    except Exception:  # pragma: no cover - defensive
        return None
    import re

    match = re.search(r"^(GET|POST|HEAD)\s+([^\s]+)\s+HTTP/", head, re.MULTILINE)
    if not match:
        return None
    return match.group(2)


def traffic_extract_search_event(
    domain: str,
    raw_payload: bytes,
    src_ip: str,
    timestamp: float,
    evidence_level: str,
) -> SearchEvent | None:
    engine = traffic_resolve_search_engine(domain)
    if engine is None:
        return None

    request_target = traffic_extract_http_request_target(raw_payload)
    if not request_target:
        return None

    parsed = urlsplit(request_target)
    query_values = parse_qs(parsed.query, keep_blank_values=False)
    keyword = ""
    for key in TRAFFIC_SEARCH_QUERY_KEYS:
        values = query_values.get(key)
        if values:
            keyword = unquote(values[0]).strip()
            if keyword:
                break
    if not keyword:
        return None

    return {
        "captured_at": format_capture_time(timestamp),
        "src_ip": src_ip,
        "domain": root_domain(domain),
        "engine": engine,
        "keyword": keyword[:200],
        "evidence_level": evidence_level,
    }


def traffic_build_violation_events(
    domain: str,
    category: str,
    src_ip: str,
    timestamp: float,
    search_event: SearchEvent | None,
) -> list[ViolationEvent]:
    events: list[ViolationEvent] = []
    normalized_domain = root_domain(domain)
    captured_at = format_capture_time(timestamp)

    if normalized_domain in TRAFFIC_BLACKLIST_DOMAINS:
        events.append(
            {
                "captured_at": captured_at,
                "src_ip": src_ip,
                "domain": normalized_domain,
                "violation_type": "blacklist_domain",
                "severity": "high",
                "reason": f"matched blacklist domain: {normalized_domain}",
            }
        )

    if search_event is not None:
        keyword = str(search_event.get("keyword", ""))
        lowered = keyword.lower()
        for risk_keyword in TRAFFIC_HIGH_RISK_KEYWORDS:
            if risk_keyword.lower() in lowered:
                events.append(
                    {
                        "captured_at": captured_at,
                        "src_ip": src_ip,
                        "domain": normalized_domain,
                        "violation_type": "high_risk_keyword",
                        "severity": "medium",
                        "reason": f"matched keyword: {risk_keyword}",
                    }
                )
                break

    local_time = time.localtime(timestamp)
    if category in TRAFFIC_ENTERTAINMENT_APP_CATEGORIES and (local_time.tm_hour < 8 or local_time.tm_hour >= 20):
        events.append(
            {
                "captured_at": captured_at,
                "src_ip": src_ip,
                "domain": normalized_domain,
                "violation_type": "off_hours_entertainment",
                "severity": "low",
                "reason": f"visited {category} during off-hours",
            }
        )

    return events


def traffic_classify_service(domain: str) -> TrafficServiceProfile:
    if is_ip_address(domain):
        return {
            "service_type": "ip",
            "service_type_label": "IP 地址",
            "service_icon": "IP",
            "productivity_category": "Neutral",
            "base_score": 6,
        }

    domain_lower = domain.lower()
    for service_type, label, icon, patterns, productivity_category, base_score in TRAFFIC_SERVICE_TYPE_RULES:
        if any(pattern in domain_lower for pattern in patterns):
            return {
                "service_type": service_type,
                "service_type_label": label,
                "service_icon": icon,
                "productivity_category": productivity_category,
                "base_score": base_score,
            }

    return {
        "service_type": "website",
        "service_type_label": "普通网站",
        "service_icon": "网站",
        "productivity_category": "Neutral",
        "base_score": 8,
    }


def traffic_risk_level_from_score(score: int) -> str:
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def traffic_higher_risk_level(left: str, right: str) -> str:
    ranking = {"low": 0, "medium": 1, "high": 2}
    left_value = ranking.get((left or "").lower(), 0)
    right_value = ranking.get((right or "").lower(), 0)
    return left if left_value >= right_value else right


class LANWebsiteClassifier:
    CATEGORIES = LAN_WEBSITE_CATEGORIES

    def classify(self, domain: str) -> dict[str, str]:
        domain_lower = domain.lower()
        for category, info in self.CATEGORIES.items():
            keywords = info["keywords"]
            if any(keyword in domain_lower for keyword in keywords):
                return {"category": category, "label": str(info["label"]), "risk": str(info["risk"])}
        return {"category": "unknown", "label": "未分类", "risk": "low"}
