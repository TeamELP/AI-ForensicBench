"""
Parse .evtx (and .json/.log/.txt) into a normalized list of events.
Each event: { id, time, source, event_id, level, message, raw }
"""
import json
import os
from datetime import datetime

# Sysmon + Windows Security EventIDs worth tracking
INTERESTING_IDS = {
    1:    ("Sysmon", "Process Creation"),
    3:    ("Sysmon", "Network Connection"),
    4:    ("Sysmon", "Sysmon Service State Change"),
    5:    ("Sysmon", "Process Terminated"),
    7:    ("Sysmon", "Image Loaded"),
    8:    ("Sysmon", "CreateRemoteThread"),
    10:   ("Sysmon", "ProcessAccess"),
    11:   ("Sysmon", "FileCreate"),
    12:   ("Sysmon", "RegistryEvent"),
    13:   ("Sysmon", "RegistryEvent"),
    15:   ("Sysmon", "FileCreateStreamHash"),
    22:   ("Sysmon", "DNSEvent"),
    4624: ("Security", "Logon Success"),
    4625: ("Security", "Logon Failure"),
    4648: ("Security", "Explicit Logon"),
    4672: ("Security", "Special Logon"),
    4688: ("Security", "Process Creation"),
    4698: ("Security", "Scheduled Task Created"),
    4720: ("Security", "User Account Created"),
    7045: ("System",   "Service Installed"),
}


def _fmt_time(ts) -> str:
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d  %H:%M:%S")
    return str(ts)


def _parse_evtx(path: str) -> list[dict]:
    from evtx import PyEvtxParser

    events = []
    idx = 0
    with PyEvtxParser(path) as parser:
        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                sys_node = data.get("Event", {}).get("System", {})

                event_id = int(sys_node.get("EventID", {}).get("#text", 0)
                               if isinstance(sys_node.get("EventID"), dict)
                               else sys_node.get("EventID", 0))

                if event_id not in INTERESTING_IDS:
                    continue

                ts_raw  = sys_node.get("TimeCreated", {}).get("@SystemTime", "")
                channel = sys_node.get("Channel", INTERESTING_IDS.get(event_id, ("?",))[0])
                level   = int(sys_node.get("Level", 4))
                level_name = {0: "critical", 1: "critical", 2: "critical",
                              3: "warn", 4: "info"}.get(level, "info")

                # Pull EventData fields into a flat message
                ed = data.get("Event", {}).get("EventData", {}) or {}
                if isinstance(ed, dict):
                    pairs = [f"{k}={v}" for k, v in ed.items()
                             if v and not k.startswith("@") and k != "Binary"]
                    message = "  ".join(pairs[:12])
                else:
                    message = str(ed)[:300]

                events.append({
                    "id":       idx,
                    "time":     ts_raw[:19].replace("T", "  "),
                    "source":   channel,
                    "event_id": event_id,
                    "level":    level_name,
                    "message":  f"EventID={event_id} ({INTERESTING_IDS[event_id][1]})  {message}",
                    "raw":      data,
                })
                idx += 1

            except Exception:
                continue

    return events


def _parse_json(path: str) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    records = data if isinstance(data, list) else data.get("events", [data])
    events = []
    for i, rec in enumerate(records[:2000]):
        events.append({
            "id":       i,
            "time":     rec.get("time", rec.get("timestamp", "")),
            "source":   rec.get("source", rec.get("channel", "Unknown")),
            "event_id": rec.get("event_id", rec.get("EventID", 0)),
            "level":    rec.get("level", "info"),
            "message":  rec.get("message", rec.get("msg", json.dumps(rec)[:200])),
            "raw":      rec,
        })
    return events


def _parse_text(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            events.append({
                "id":       i,
                "time":     "",
                "source":   "LogFile",
                "event_id": 0,
                "level":    "info",
                "message":  line[:300],
                "raw":      {},
            })
            if i >= 2000:
                break
    return events


def parse_file(path: str, filename: str) -> list[dict]:
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext == ".evtx":
            return _parse_evtx(path)
        elif ext == ".json":
            return _parse_json(path)
        else:
            return _parse_text(path)
    except Exception as e:
        raise ValueError(f"Failed to parse {filename}: {e}")
