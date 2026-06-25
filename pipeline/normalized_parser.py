import json
import os
from datetime import datetime

# =========================
# INPUT FILES
# =========================

INPUT_FILES = {
    "sysmon": "normalized_sysmon.json",
    "security": "normalized_security.json",
    "system": "normalized_system.json"
}

OUTPUT_FILE = "normalized_events.json"

# =========================
# source priority
# =========================

SOURCE_PRIORITY = {
    "sysmon": 0,
    "security": 1,
    "system": 2
}

# =========================
# timestamp parser
# =========================

def parse_timestamp(ts):
    return datetime.fromisoformat(ts)

# =========================
# load existing files only
# =========================

events = []

for source_name, file_path in INPUT_FILES.items():

    # 파일이 없으면 skip
    if not os.path.exists(file_path):
        print(f"[!] Skip ({source_name}) : file not found")
        continue

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # source / source_index 추가
    for idx, event in enumerate(data):

        event["source"] = source_name

        # 각 로그 내부 원래 순서 보존
        event["source_index"] = idx

        events.append(event)

    print(f"[+] Loaded {len(data)} events from {file_path}")

# =========================
# stable sort
# =========================

events.sort(
    key=lambda x: (
        parse_timestamp(x["timestamp"]),
        SOURCE_PRIORITY.get(x["source"], 999),
        x["source_index"]
    )
)

# =========================
# assign event_id
# =========================

for idx, event in enumerate(events):
    event["event_id"] = idx + 1

# =========================
# save
# =========================

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

# =========================
# result
# =========================

print()
print(f"[+] Total merged events: {len(events)}")
print(f"[+] Saved to: {OUTPUT_FILE}")