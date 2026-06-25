"""
make_llm.py
AI-ForensicBench / ELP Team

semantic_activities.json → GPT-4o-mini → llm_output.json

사용법:
    python make_llm.py --input ../scenarios/scenario1/outputs/semantic_activities.json
                       --output ../scenarios/scenario1/outputs/llm_output.json
"""

import json
import argparse
import os
from openai import OpenAI
from llm_prompt_v2 import SYSTEM_PROMPT, build_user_prompt, PRIMITIVE_VOCABULARY

# =========================================================
# CONFIG
# =========================================================

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")  # 환경 변수로 설정하세요

MODEL = "gpt-4o-mini"

MIN_EVENT_COUNT = 2

FORENSIC_SIGNAL_TYPES = {
    "process_create",
    "network_connection",
    "file_create",
    "file_delete",
    "dns_query",
    "process_access",
    "powershell_execution",
    "shell_execution",
    "registry_value_set",
    "driver_load",
    "service_state_change",
    "service_config_change",
}

# =========================================================
# 구조 정규화
# 시나리오 1: activity_id, event_count, event_types 등 상세 필드
# 시나리오 2~10: group_id, events만 존재
# =========================================================

def normalize_activity(a: dict, idx: int) -> dict:
    """두 가지 schema를 통일된 형태로 변환"""
    if "activity_id" in a:
        # 시나리오 1 형식 — 그대로 사용
        return a
    else:
        # 시나리오 2~10 형식 — 최소 필드로 채움
        events = a.get("events", [])
        return {
            "activity_id":  a.get("group_id", idx + 1),
            "events":       events,
            "event_count":  len(events),
            "event_types":  [],
            "processes":    [],
            "files":        [],
            "ips":          [],
            "users":        [],
            "start_time":   "",
            "end_time":     "",
        }


# =========================================================
# CLUSTER SCORING
# =========================================================

def score_cluster(activity: dict) -> int:
    s = 0
    types = set(activity.get("event_types", []))

    if "network_connection" in types: s += 2
    if "file_create" in types:        s += 2
    if "process_create" in types:     s += 2
    if "dns_query" in types:          s += 1
    if "process_access" in types:     s += 1
    if activity.get("event_count", 0) >= 3: s += 1
    if len(activity.get("processes", [])) >= 2: s += 2

    return s


def select_clusters(activities: list, top_n: int = 10) -> list:
    scored = []
    for a in activities:
        if a.get("event_count", 0) < MIN_EVENT_COUNT:
            continue
        types = set(a.get("event_types", []))
        has_signal = bool(types & FORENSIC_SIGNAL_TYPES) or a.get("event_count", 0) >= MIN_EVENT_COUNT
        if not has_signal:
            continue
        s = score_cluster(a)
        scored.append((s, a))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [a for _, a in scored[:top_n]]


# =========================================================
# SEMANTIC ACTIVITIES → CORRELATED EVIDENCE 변환
# =========================================================

def activities_to_correlated_evidence(activities: list) -> list:
    result = []
    for idx, activity in enumerate(activities):
        group = {
            "group_id":      activity.get("activity_id", idx + 1),
            "score":         score_cluster(activity),
            "related_events": []
        }
        for event_id in activity.get("events", []):
            group["related_events"].append({
                "event_id":   str(event_id),
                "event_type": ", ".join(activity.get("event_types", [])),
                "process":    ", ".join(activity.get("processes", [])),
                "timestamp":  activity.get("start_time", ""),
                "artifact":   ", ".join(activity.get("files", [])[:2]),
            })
        result.append(group)
    return result


# =========================================================
# GPT API 호출
# =========================================================

def call_gpt(correlated_evidence: list) -> dict:
    client = OpenAI(api_key=OPENAI_API_KEY)
    user_prompt = build_user_prompt(correlated_evidence)

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt}
        ],
        temperature=0.0,
        response_format={"type": "json_object"}
    )

    raw = response.choices[0].message.content
    return json.loads(raw)


# =========================================================
# VALIDATION
# =========================================================

def validate_output(llm_output: dict) -> list:
    warnings = []
    for item in llm_output.get("timeline", []):
        stage = item.get("stage", "")
        if stage not in PRIMITIVE_VOCABULARY:
            warnings.append(f"[WARNING] 알 수 없는 primitive: {stage}")
        if not item.get("evidence_ids"):
            warnings.append(f"[WARNING] evidence_ids 없음: stage={stage}")
    return warnings


# =========================================================
# MAIN
# =========================================================

def main(input_path: str, output_path: str):
    print(f"[+] Loading: {input_path}")
    with open(input_path, encoding="utf-8") as f:
        raw_activities = json.load(f)

    print(f"[+] Total activities: {len(raw_activities)}")

    # 구조 정규화
    activities = [normalize_activity(a, i) for i, a in enumerate(raw_activities)]

    # cluster 선별
    selected = select_clusters(activities, top_n=10)
    print(f"[+] Selected clusters: {len(selected)}")

    if not selected:
        print("[ERROR] forensic signal 있는 cluster 없음")
        return

    correlated_evidence = activities_to_correlated_evidence(selected)

    print(f"[+] Calling {MODEL}...")
    llm_output = call_gpt(correlated_evidence)

    warnings = validate_output(llm_output)
    for w in warnings:
        print(w)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(llm_output, f, indent=2, ensure_ascii=False)

    print(f"[+] Saved: {output_path}")
    print()
    print("=== LLM OUTPUT ===")
    print(json.dumps(llm_output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    main(args.input, args.output)