"""
Score and filter events by suspiciousness.
Returns top-N high-signal events suitable for LLM analysis.
"""
import re

MAX_EVENTS = 60  # stay within GPT token budget

# --- Scoring rules -------------------------------------------------------

SUSPICIOUS_PATTERNS = [
    # Encoded / obfuscated commands
    (r"-[Ee]ncodedcommand",           30, "PowerShell encoded command"),
    (r"-[Ee]xecutionpolicy\s+bypass", 25, "ExecutionPolicy bypass"),
    (r"iex\s*\(",                     25, "IEX (Invoke-Expression)"),
    (r"downloadstring|webclient",     25, "In-memory download"),
    (r"invoke-expression|invoke-webrequest", 20, "Suspicious invocation"),
    # LOLBIN abuse
    (r"regsvr32.*scrobj",             35, "regsvr32 LOLBin"),
    (r"mshta|wscript|cscript",        20, "Script host abuse"),
    (r"certutil.*-decode",            25, "certutil decode"),
    (r"bitsadmin",                    20, "BITSAdmin transfer"),
    # Credential access
    (r"lsass\.exe",                   40, "lsass access"),
    (r"mimikatz|sekurlsa|logonpasswords", 45, "Mimikatz artifact"),
    (r"pass.the.hash|ntlm",          25, "NTLM / PtH"),
    # Staging / exfil
    (r"xcopy.*\\temp|copy.*\\temp",   20, "Staging to temp"),
    (r"7z\.exe|winrar|compress",      15, "Compression"),
    (r"curl.*-x\s+post|curl.*upload", 30, "curl exfil"),
    (r"\.zip|\.rar|\.7z",            10, "Archive file"),
    # Persistence
    (r"schtasks.*create|at\.exe",     25, "Scheduled task"),
    (r"reg.*add.*run",                20, "Registry run key"),
    (r"sc.*create|sc.*start",         20, "Service install"),
    # Network IOCs (generic)
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 5, "IP address"),
]

HIGH_VALUE_EVENT_IDS = {
    1:    15,   # Process Creation (Sysmon)
    3:    10,   # Network Connection
    8:    35,   # CreateRemoteThread
    10:   40,   # ProcessAccess
    4624: 5,    # Logon
    4648: 15,   # Explicit Logon
    4688: 10,   # Process Creation (Security)
    4698: 20,   # Scheduled Task
    7045: 25,   # Service Installed
}


def _score(event: dict) -> int:
    score = HIGH_VALUE_EVENT_IDS.get(event.get("event_id", 0), 0)
    msg = (event.get("message", "") + str(event.get("raw", ""))).lower()
    for pattern, pts, _ in SUSPICIOUS_PATTERNS:
        if re.search(pattern, msg, re.IGNORECASE):
            score += pts
    return score


def correlate_events(events: list[dict]) -> list[dict]:
    if not events:
        return []

    scored = [{"event": e, "score": _score(e)} for e in events]
    scored.sort(key=lambda x: (-x["score"], x["event"]["id"]))

    top = scored[:MAX_EVENTS]
    top.sort(key=lambda x: x["event"]["id"])  # restore temporal order

    result = []
    for item in top:
        e = dict(item["event"])
        e["suspicion_score"] = item["score"]
        result.append(e)

    return result
