from __future__ import annotations

from .protocol_types import PacketQuickCheckInput, ThreatCheckResult


def quick_threat_check(packet_dict: PacketQuickCheckInput) -> ThreatCheckResult:
    payload = packet_dict.get("payload", "")
    dport = packet_dict.get("dport")
    sport = packet_dict.get("sport")
    flags = str(packet_dict.get("flags", ""))
    src = packet_dict.get("src")
    dst = packet_dict.get("dst")

    if src == "N/A" or dst == "N/A":
        return "safe", None, None
    if payload and isinstance(payload, str):
        payload_upper = payload.upper()
        payload_lower = payload.lower()

        sql_patterns = [
            "UNION SELECT",
            "DROP TABLE",
            "'; DROP",
            "OR 1=1",
            "' OR '1'='1",
            "EXEC(",
            "EXECUTE(",
            "xp_cmdshell",
        ]
        for pattern in sql_patterns:
            if pattern.upper() in payload_upper:
                return "threat", "SQL娉ㄥ叆", f"妫€娴嬪埌 SQL 娉ㄥ叆鐗瑰緛: {pattern}"

        cmd_patterns = [
            "powershell.exe",
            "cmd.exe /c",
            "bash -c",
            "/bin/sh",
            "wget http",
            "curl http",
            "Invoke-WebRequest",
            "system(",
            "exec(",
            "eval(",
            "; rm -rf",
            "& del",
        ]
        for pattern in cmd_patterns:
            if pattern.lower() in payload_lower:
                return "threat", "鍛戒护娉ㄥ叆", f"妫€娴嬪埌鍛戒护娉ㄥ叆鐗瑰緛: {pattern}"

        xss_patterns = [
            "<script>",
            "<script ",
            "javascript:",
            "onerror=",
            "onload=",
            "<iframe",
            "document.cookie",
            "alert(",
        ]
        for pattern in xss_patterns:
            if pattern.lower() in payload_lower:
                return "threat", "XSS鏀诲嚮", f"妫€娴嬪埌 XSS 鐗瑰緛: {pattern}"

        path_patterns = ["../../../", "..\\..\\..\\", "/etc/passwd", "C:\\Windows\\System32"]
        for pattern in path_patterns:
            if pattern in payload:
                return "threat", "璺緞閬嶅巻", f"妫€娴嬪埌璺緞閬嶅巻鐗瑰緛: {pattern}"

    if "S" in flags and "A" not in flags:
        scan_ports = {22, 23, 3306, 3389, 5432, 6379, 27017, 9090}
        if dport in scan_ports:
            return "threat", "绔彛鎵弿", f"妫€娴嬪埌瀵规晱鎰熺鍙?{dport} 鐨?SYN 鎵弿"

    if flags in ["S", "SA", "A", "FA", "F", "R", "RA"] and not payload:
        return "safe", None, None

    normal_ports = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 8443}
    if not payload or len(str(payload)) < 10:
        if dport in normal_ports or sport in normal_ports:
            return "safe", None, None

    if dport == 53 or sport == 53:
        return "safe", None, None

    if dport == 443 or sport == 443:
        return "safe", None, None

    if payload and isinstance(payload, str):
        if payload.startswith(("GET /", "POST /", "HEAD /", "OPTIONS /")):
            return "safe", None, None

    return "unknown", None, None
