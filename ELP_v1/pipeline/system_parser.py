import pandas as pd
import json
import uuid
import re
import os

from datetime import datetime, timezone, timedelta

# =========================
# 설정
# =========================

INPUT_FILE = os.environ.get("INPUT_FILE", "system_events.csv")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "normalized_system.json")

KST = timezone(timedelta(hours=9))

# =========================
# 시간 파싱
# =========================

def normalize_csv_timestamp(ts):

    if not ts:
        return None

    try:

        ts = str(ts)

        ts = ts.replace("오전", "AM")
        ts = ts.replace("오후", "PM")

        dt = datetime.strptime(
            ts,
            "%Y-%m-%d %p %I:%M:%S"
        )

        dt = dt.replace(
            tzinfo=KST
        )

        return dt.isoformat()

    except Exception as e:

        print(f"[TIME ERROR] {ts} -> {e}")

        return None

# =========================
# Artifact
# =========================

def make_artifact(artifact_type, value):

    return {
        "type": artifact_type,
        "value": value
    }

# =========================
# Base Event
# =========================

def base_event(row):

    return {

        "evidence_id":
            str(uuid.uuid4()),

        "timestamp":
            normalize_csv_timestamp(
                row["TimeCreated"]
            ),

        "source":
            "system",

        "raw_event_id":
            int(row["Id"]),

        "event_type":
            None,

        "service_name":
            None,

        "service_state":
            None,

        "user":
            None,

        "artifacts":
            [],

        "additional_fields":
            {}
    }

# =========================
# Event 7036
# Service State Change
# =========================

def parse_event_7036(row):

    event = base_event(row)

    event["event_type"] = "service_state_change"

    msg = str(row["Message"])

    patterns = [

        r"The (.+?) service entered the (.+?) state"
    ]

    for pattern in patterns:

        m = re.search(pattern, msg)

        if m:

            event["service_name"] = m.group(1).strip()

            event["service_state"] = m.group(2).strip()

            break

    if event["service_name"]:

        event["artifacts"].append(

            make_artifact(
                "service",
                event["service_name"]
            )
        )

    return event

# =========================
# Event 7040
# Service Config Change
# =========================

def parse_event_7040(row):

    event = base_event(row)

    event["event_type"] = "service_config_change"

    msg = str(row["Message"])

    patterns = [

        r"The start type of the (.+?) service was changed from (.+?) to (.+?)\."
    ]

    for pattern in patterns:

        m = re.search(pattern, msg)

        if m:

            event["service_name"] = m.group(1).strip()

            event["additional_fields"]["old_start_type"] = (
                m.group(2).strip()
            )

            event["additional_fields"]["new_start_type"] = (
                m.group(3).strip()
            )

            break

    if event["service_name"]:

        event["artifacts"].append(

            make_artifact(
                "service",
                event["service_name"]
            )
        )

    return event

# =========================
# Event 7045
# Service Install
# =========================

def parse_event_7045(row):

    event = base_event(row)

    event["event_type"] = "service_install"

    msg = str(row["Message"])

    # 필요시 regex 추가 가능

    return event

# =========================
# Event 1014
# DNS Timeout
# =========================

def parse_event_1014(row):

    event = base_event(row)

    event["event_type"] = "dns_timeout"

    msg = str(row["Message"])

    pattern = (
        r"Name resolution for the name (.+?) "
        r"timed out"
    )

    m = re.search(pattern, msg)

    if m:

        domain = m.group(1).strip()

        event["artifacts"].append(

            make_artifact(
                "domain",
                domain
            )
        )

        event["additional_fields"] = {

            "query_domain":
                domain
        }

    return event

# =========================
# Event Routing
# =========================

EVENT_PARSERS = {

    7036: parse_event_7036,

    7040: parse_event_7040,

    7045: parse_event_7045,

    1014: parse_event_1014
}

# =========================
# Main
# =========================

def main():

    df = pd.read_csv(
        INPUT_FILE,
        engine="python"
    )

    # CSV가 최신순이면 reverse
    df = df.iloc[::-1].reset_index(drop=True)

    normalized_events = []

    for _, row in df.iterrows():

        try:

            event_id = int(row["Id"])

            if event_id not in EVENT_PARSERS:
                continue

            parser = EVENT_PARSERS[event_id]

            normalized = parser(row)

            normalized_events.append(
                normalized
            )

        except Exception as e:

            print(f"[ERROR] {e}")

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