import pandas as pd
import json
import uuid
import os

from datetime import datetime, timezone, timedelta

# =========================
# 설정
# =========================

INPUT_FILE = os.environ.get("INPUT_FILE", "sysmon_events.csv")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "normalized_sysmon.json")

KST = timezone(timedelta(hours=9))

# =========================
# 안전한 int 변환
# =========================

def safe_int(value):

    try:
        return int(value)
    except:
        return None

# =========================
# CSV TimeCreated 정규화
# 🔥 한국어 오전/오후 처리
# =========================

def normalize_csv_timestamp(ts):

    """
    CSV TimeCreated 예시:
    2026-05-20 오후 3:58:35
    """

    if not ts:
        return None

    try:

        ts = str(ts)

        # 🔥 한국어 오전/오후 처리
        ts = ts.replace("오전", "AM")
        ts = ts.replace("오후", "PM")

        dt = datetime.strptime(
            ts,
            "%Y-%m-%d %p %I:%M:%S"
        )

        # 🔥 KST timezone 부여
        dt = dt.replace(
            tzinfo=KST
        )

        return dt.isoformat()

    except Exception as e:

        print(f"[TIME ERROR] {ts} -> {e}")

        return None

# =========================
# Hash Parsing
# =========================

def parse_hashes(hash_string):

    if not hash_string:
        return {}

    result = {}

    parts = hash_string.split(",")

    for part in parts:

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        result[key.strip().lower()] = value.strip()

    return result

# =========================
# Artifact 생성
# =========================

def make_artifact(artifact_type, value):

    return {
        "type": artifact_type,
        "value": value
    }

# =========================
# Message → dict
# =========================

def parse_message(message):

    fields = {}

    if pd.isna(message):
        return fields

    for line in str(message).splitlines():

        line = line.strip()

        # 빈 줄 제거
        if not line:
            continue

        # ':' 없는 줄 제거
        if ":" not in line:
            continue

        try:

            key, value = line.split(":", 1)

            key = key.strip()
            value = value.strip()

            # 빈 key 제거
            if not key:
                continue

            fields[key] = value

        except:
            continue

    return fields

# =========================
# 공통 Event 구조
# =========================

def base_event(row, fields):

    return {

        "evidence_id": str(uuid.uuid4()),

        # 🔥 CSV TimeCreated 기준
        "timestamp": normalize_csv_timestamp(
            row["TimeCreated"]
        ),

        "source": "sysmon",

        "raw_event_id": int(row["Id"]),

        "event_type": None,

        "process_name": None,
        "process_path": None,

        "pid": None,
        "parent_pid": None,

        "command_line": None,

        "user": None,

        "file_path": None,

        "destination_ip": None,
        "destination_port": None,

        "artifacts": [],

        "additional_fields": {}
    }

# =========================
# Event 1
# Process Create
# =========================

def parse_event_1(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "process_create"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["parent_pid"] = safe_int(
        fields.get("ParentProcessId")
    )

    event["command_line"] = fields.get(
        "CommandLine"
    )

    event["user"] = fields.get("User")

    if process_path:
        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    if fields.get("ParentImage"):
        event["artifacts"].append(
            make_artifact(
                "parent_process",
                fields.get("ParentImage")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "parent_process_guid":
            fields.get("ParentProcessGuid"),

        "parent_image":
            fields.get("ParentImage"),

        "parent_command_line":
            fields.get("ParentCommandLine"),

        "hashes":
            parse_hashes(
                fields.get("Hashes")
            ),

        "integrity_level":
            fields.get("IntegrityLevel"),

        "current_directory":
            fields.get("CurrentDirectory")
    }

    return event

# =========================
# Event 3
# Network Connection
# =========================

def parse_event_3(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "network_connection"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    event["destination_ip"] = fields.get(
        "DestinationIp"
    )

    event["destination_port"] = safe_int(
        fields.get("DestinationPort")
    )

    if fields.get("DestinationIp"):
        event["artifacts"].append(
            make_artifact(
                "ip",
                fields.get("DestinationIp")
            )
        )

    event["additional_fields"] = {

        "source_ip":
            fields.get("SourceIp"),

        "source_port":
            safe_int(
                fields.get("SourcePort")
            ),

        "protocol":
            fields.get("Protocol"),

        "source_hostname":
            fields.get("SourceHostname"),

        "destination_hostname":
            fields.get("DestinationHostname"),

        "initiated":
            fields.get("Initiated"),

        "process_guid":
            fields.get("ProcessGuid")
    }

    return event

# =========================
# Event 5
# Process Terminate
# =========================

def parse_event_5(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "process_terminate"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    if process_path:
        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid")
    }

    return event

# =========================
# Event 8
# Create Remote Thread
# =========================

def parse_event_8(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "create_remote_thread"

    process_path = fields.get("SourceImage")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        )

    event["pid"] = safe_int(
        fields.get("SourceProcessId")
    )

    event["user"] = fields.get("SourceUser")

    if process_path:
        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    if fields.get("TargetImage"):
        event["artifacts"].append(
            make_artifact(
                "target_process",
                fields.get("TargetImage")
            )
        )

    event["additional_fields"] = {

        "source_process_guid":
            fields.get("SourceProcessGuid"),

        "target_process_guid":
            fields.get("TargetProcessGuid"),

        "target_process_id":
            safe_int(
                fields.get("TargetProcessId")
            ),

        "target_image":
            fields.get("TargetImage"),

        "new_thread_id":
            safe_int(
                fields.get("NewThreadId")
            ),

        "start_address":
            fields.get("StartAddress"),

        "start_module":
            fields.get("StartModule"),

        "start_function":
            fields.get("StartFunction"),

        "target_user":
            fields.get("TargetUser")
    }

    return event

# =========================
# Event 10
# Process Access
# =========================

def parse_event_10(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "process_access"

    process_path = fields.get("SourceImage")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("SourceProcessId")
    )

    event["user"] = fields.get("SourceUser")

    if process_path:
        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    if fields.get("TargetImage"):
        event["artifacts"].append(
            make_artifact(
                "target_process",
                fields.get("TargetImage")
            )
        )

    event["additional_fields"] = {

        "source_process_guid":
            fields.get("SourceProcessGUID"),

        "target_process_guid":
            fields.get("TargetProcessGUID"),

        "target_process_id":
            safe_int(
                fields.get("TargetProcessId")
            ),

        "target_image":
            fields.get("TargetImage"),

        "granted_access":
            fields.get("GrantedAccess"),

        "call_trace":
            fields.get("CallTrace"),

        "target_user":
            fields.get("TargetUser")
    }

    return event

# =========================
# Event 11
# File Create
# =========================

def parse_event_11(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "file_create"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    event["file_path"] = fields.get(
        "TargetFilename"
    )

    if fields.get("TargetFilename"):
        event["artifacts"].append(
            make_artifact(
                "file",
                fields.get("TargetFilename")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "creation_utc_time":
            fields.get("CreationUtcTime")
    }

    return event

# =========================
# Event 12
# Registry Object Add/Delete
# =========================

def parse_event_12(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "registry_object_change"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    if fields.get("TargetObject"):
        event["artifacts"].append(
            make_artifact(
                "registry",
                fields.get("TargetObject")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "event_type_detail":
            fields.get("EventType"),

        "target_object":
            fields.get("TargetObject"),

        "rule_name":
            fields.get("RuleName")
    }

    return event

# =========================
# Event 13
# Registry Value Set
# =========================

def parse_event_13(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "registry_value_set"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    if fields.get("TargetObject"):
        event["artifacts"].append(
            make_artifact(
                "registry",
                fields.get("TargetObject")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "event_type_detail":
            fields.get("EventType"),

        "target_object":
            fields.get("TargetObject"),

        "details":
            fields.get("Details"),

        "rule_name":
            fields.get("RuleName")
    }

    return event

# =========================
# Event 15
# File Stream Create
# =========================

def parse_event_15(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "file_stream_create"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    event["file_path"] = fields.get(
        "TargetFilename"
    )

    if fields.get("TargetFilename"):
        event["artifacts"].append(
            make_artifact(
                "file",
                fields.get("TargetFilename")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "creation_utc_time":
            fields.get("CreationUtcTime"),

        "hashes":
            parse_hashes(
                fields.get("Hash")
            ),

        "contents":
            fields.get("Contents")
    }

    return event

# =========================
# Event 22
# DNS Query
# =========================

def parse_event_22(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "dns_query"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    if fields.get("QueryName"):
        event["artifacts"].append(
            make_artifact(
                "domain",
                fields.get("QueryName")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "query_name":
            fields.get("QueryName"),

        "query_status":
            fields.get("QueryStatus"),

        "query_results":
            fields.get("QueryResults")
    }

    return event

# =========================
# Event 26
# File Delete
# =========================

def parse_event_26(row, fields):

    event = base_event(row, fields)

    event["event_type"] = "file_delete"

    process_path = fields.get("Image")

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(process_path)

    event["pid"] = safe_int(
        fields.get("ProcessId")
    )

    event["user"] = fields.get("User")

    event["file_path"] = fields.get(
        "TargetFilename"
    )

    if fields.get("TargetFilename"):
        event["artifacts"].append(
            make_artifact(
                "file",
                fields.get("TargetFilename")
            )
        )

    event["additional_fields"] = {

        "process_guid":
            fields.get("ProcessGuid"),

        "hashes":
            parse_hashes(
                fields.get("Hashes")
            ),

        "is_executable":
            fields.get("IsExecutable")
    }

    return event

# =========================
# Event Routing
# =========================

EVENT_PARSERS = {

    1: parse_event_1,

    3: parse_event_3,

    5: parse_event_5,

    8: parse_event_8,

    10: parse_event_10,

    11: parse_event_11,

    12: parse_event_12,

    13: parse_event_13,

    15: parse_event_15,

    22: parse_event_22,

    26: parse_event_26
}

# =========================
# 메인
# =========================

def main():

    # 🔥 engine="python" 권장
    df = pd.read_csv(
        INPUT_FILE,
        engine="python"
    )

    # 🔥 CSV 자체가 시간 역순이므로 reverse
    df = df.iloc[::-1].reset_index(drop=True)

    normalized_events = []

    for _, row in df.iterrows():

        try:

            event_id = int(row["Id"])

            if event_id not in EVENT_PARSERS:
                continue

            fields = parse_message(
                row["Message"]
            )

            parser = EVENT_PARSERS[event_id]

            normalized = parser(
                row,
                fields
            )

            normalized_events.append(
                normalized
            )

        except Exception as e:

            print(f"[ERROR] {e}")

    # 🔥 추가 sort 절대 하지 않음
    # CSV reverse 순서를 그대로 유지

    # 저장
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            normalized_events,
            f,
            ensure_ascii=False,
            indent=2
        )

    print(f"[+] Saved: {OUTPUT_FILE}")
    print(f"[+] Parsed events: {len(normalized_events)}")

# =========================
# 실행
# =========================

if __name__ == "__main__":

    main()