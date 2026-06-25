import json
import os
from collections import defaultdict
from datetime import datetime, timedelta

# =========================================================
# INPUT / OUTPUT
# =========================================================

INPUT_FILE = "normalized_events.json"
OUTPUT_FILE = "event_graph.json"

# =========================================================
# SETTINGS
# =========================================================

# lineage 시간 제한
MAX_PROCESS_DIFF_MINUTES = 30

# same_pid 시간 제한
MAX_SAME_PID_DIFF_SECONDS = 15

# 너무 많이 등장하는 artifact 제외
MAX_ARTIFACT_OCCURRENCE = 15

# =========================================================
# source priority
# =========================================================

SOURCE_PRIORITY = {
    "sysmon": 0,
    "security": 1,
    "system": 2
}

# noisy directory 제외
EXCLUDED_DIRECTORIES = [
    "\\downloads",
    "\\desktop",
    "\\temp",
    "\\appdata"
]

# correlation 허용 extension
HIGH_VALUE_EXTENSIONS = {
    ".vhd",
    ".zip",
    ".7z",
    ".rar",
    ".pst",
    ".ps1",
    ".txt",
    ".pdf",
    ".docx",
    ".xlsx"
}

# weak lineage 활성화
ENABLE_WEAK_LINEAGE = True

# =========================================================
# same_pid 연결 허용 이벤트
# =========================================================

FORENSIC_EVENT_TYPES = {
    # process
    "process_create",
    "process_access",

    # network
    "network_connection",
    "dns_query",

    # file
    "file_create",
    "file_delete",
    "file_stream_create",

    # registry
    "registry_value_set",

    # shell
    "powershell_execution",
    "shell_execution",

    # =========================
    # system events 추가
    # =========================

    "service_state_change",
    "service_config_change",
    "driver_load",
    "device_connect",
    "device_disconnect"
}

# =========================================================
# TIME PARSER
# =========================================================

def parse_timestamp(ts):
    return datetime.fromisoformat(ts)

# =========================================================
# EVENT ORDER KEY
# =========================================================

def event_order_key(event):

    return (
        event["_dt"],
        SOURCE_PRIORITY.get(event.get("source"), 999),
        event.get("source_index", 0)
    )

# =========================================================
# LOAD EVENTS
# =========================================================

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    events = json.load(f)

print(f"[+] Loaded events: {len(events)}")

# =========================================================
# DATETIME OBJECT 추가
# =========================================================

for event in events:
    event["_dt"] = parse_timestamp(event["timestamp"])

events.sort(key=event_order_key)

# =========================================================
# EDGE 저장
# =========================================================

edges = []
edge_set = set()

# =========================================================
# EDGE ADD FUNCTION
# =========================================================

def add_edge(src, dst, relation, extra=None):

    if src == dst:
        return

    key = tuple(sorted([src, dst])) + (relation,)

    if key in edge_set:
        return

    edge_set.add(key)

    edge = {
        "src": src,
        "dst": dst,
        "relation": relation
    }

    if extra:
        edge.update(extra)

    edges.append(edge)

# =========================================================
# 1. PROCESS LINEAGE CORRELATION
# =========================================================

print("[*] Building process lineage correlation...")

MAX_PROCESS_DIFF = timedelta(minutes=MAX_PROCESS_DIFF_MINUTES)

pid_index = defaultdict(list)

# process_create index
for event in events:

    if event.get("event_type") != "process_create":
        continue

    pid = event.get("pid")

    if pid is None:
        continue

    pid = str(pid)

    event["_normalized_pid"] = pid

    parent_pid = event.get("parent_pid")

    if parent_pid is not None:
        event["_normalized_parent_pid"] = str(parent_pid)

    pid_index[pid].append(event)

# stable ordering
for pid in pid_index:
    pid_index[pid].sort(key=event_order_key)

strict_lineage_count = 0
weak_lineage_count = 0

# build lineage
for child in events:

    if child.get("event_type") != "process_create":
        continue

    parent_pid = child.get("_normalized_parent_pid")

    if parent_pid is None:
        continue

    parent_candidates = pid_index.get(parent_pid, [])

    best_parent = None
    best_diff = None

    for parent in parent_candidates:

        if event_order_key(parent) > event_order_key(child):
            continue

        diff = child["_dt"] - parent["_dt"]

        if diff > MAX_PROCESS_DIFF:
            continue

        if best_diff is None or diff < best_diff:
            best_parent = parent
            best_diff = diff

    # strict lineage
    if best_parent:

        strict_lineage_count += 1

        add_edge(
            best_parent["event_id"],
            child["event_id"],
            "process_lineage",
            {
                "parent_pid": best_parent.get("pid"),
                "child_pid": child.get("pid"),

                "parent_process": best_parent.get("process_name"),
                "child_process": child.get("process_name"),

                "time_diff_seconds": int(best_diff.total_seconds())
            }
        )

    # weak lineage
    elif ENABLE_WEAK_LINEAGE:

        weak_lineage_count += 1

        child["parent_missing"] = True
        child["missing_parent_pid"] = parent_pid

print(f"[+] Strict process lineage edges: {strict_lineage_count}")
print(f"[+] Weak process lineage edges: {weak_lineage_count}")

# =========================================================
# 2. SHARED ARTIFACT CORRELATION
# =========================================================

print("[*] Building shared artifact correlation...")

artifact_index = defaultdict(list)

for event in events:

    artifacts = event.get("artifacts", [])

    for artifact in artifacts:

        artifact_type = artifact.get("type")
        artifact_value = artifact.get("value")

        if not artifact_type or not artifact_value:
            continue

        artifact_value_lower = str(artifact_value).lower()

        # =================================================
        # FILE FILTERING
        # =================================================

        if artifact_type == "file":

            # noisy path 제외
            excluded = False

            for ex in EXCLUDED_DIRECTORIES:

                if ex in artifact_value_lower:
                    excluded = True
                    break

            if excluded:
                continue

            # extension filtering
            ext = os.path.splitext(artifact_value_lower)[1]

            if ext and ext not in HIGH_VALUE_EXTENSIONS:
                continue

        artifact_index[(artifact_type, artifact_value)].append(event)

# =========================================================
# BUILD SHARED ARTIFACT EDGES
# =========================================================

shared_artifact_count = 0

for (artifact_type, artifact_value), related_events in artifact_index.items():

    if len(related_events) > MAX_ARTIFACT_OCCURRENCE:
        continue

    related_events.sort(key=event_order_key)

    for i in range(len(related_events)):

        for j in range(i + 1, len(related_events)):

            e1 = related_events[i]
            e2 = related_events[j]

            add_edge(
                e1["event_id"],
                e2["event_id"],
                f"shared_{artifact_type}",
                {
                    "artifact": artifact_value
                }
            )

            shared_artifact_count += 1

print(f"[+] Shared artifact edges: {shared_artifact_count}")

# =========================================================
# 3. SAME PID CORRELATION
# =========================================================

print("[*] Building same PID correlation...")

pid_event_index = defaultdict(list)

for event in events:

    pid = event.get("pid")

    if pid is None:
        continue

    if event.get("event_type") not in FORENSIC_EVENT_TYPES:
        continue

    pid_event_index[str(pid)].append(event)

same_pid_count = 0

for pid, pid_events in pid_event_index.items():

    if len(pid_events) < 2:
        continue

    pid_events_sorted = sorted(pid_events, key=event_order_key)

    # chain graph
    for i in range(len(pid_events_sorted) - 1):

        e1 = pid_events_sorted[i]
        e2 = pid_events_sorted[i + 1]

        diff = abs(
            (e2["_dt"] - e1["_dt"]).total_seconds()
        )

        if diff > MAX_SAME_PID_DIFF_SECONDS:
            continue

        add_edge(
            e1["event_id"],
            e2["event_id"],
            "same_pid",
            {
                "pid": pid,
                "process": e1.get("process_name"),
                "time_diff_seconds": int(diff)
            }
        )

        same_pid_count += 1

print(f"[+] Same PID edges: {same_pid_count}")

# =========================================================
# CLEANUP
# =========================================================

for event in events:

    if "_dt" in event:
        del event["_dt"]

    if "_normalized_pid" in event:
        del event["_normalized_pid"]

    if "_normalized_parent_pid" in event:
        del event["_normalized_parent_pid"]

# =========================================================
# SAVE
# =========================================================

graph = {
    "nodes": events,
    "edges": edges
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(graph, f, indent=2, ensure_ascii=False)

print(f"[+] Total edges: {len(edges)}")
print(f"[+] Final saved to: {OUTPUT_FILE}")