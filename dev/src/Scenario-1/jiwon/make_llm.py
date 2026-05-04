import json
import re
import random
import os
from datetime import datetime, timedelta, timezone

# =========================
# 설정
# =========================

INPUT_FILE = "merged_logs.json"
OUTPUT_FILE = "final_ai_input.json"

KST = timezone(timedelta(hours=9))

DELETE_WINDOWS = [
    ("2026-05-01T04:53:09+09:00", "2026-05-01T04:53:19+09:00"),
    ("2026-05-01T04:59:01+09:00", "2026-05-01T04:59:21+09:00")
]

# =========================
# 1. 시간 파싱 (KST aware로 통일)
# =========================

def parse_time(ts):
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=KST)
    else:
        dt = dt.astimezone(KST)
    return dt

# =========================
# 2. 시간대 삭제
# =========================

def filter_by_time(logs):
    result = []
    for log in logs:
        t = parse_time(log["TimeCreated"])
        keep = True
        for start, end in DELETE_WINDOWS:
            if parse_time(start) <= t <= parse_time(end):
                keep = False
                break
        if keep:
            result.append(log)
    return result

# =========================
# 3. 경로 치환 (관계 유지 + 확장자 유지)
# =========================

path_map = {}

def anonymize_path(path):
    if path not in path_map:
        base = os.path.basename(path)
        name, ext = os.path.splitext(base)
        new_name = f"file_{len(path_map)}{ext}"
        path_map[path] = f"C:\\fake\\{new_name}"
    return path_map[path]

path_pattern = re.compile(r"[A-Za-z]:\\[^\"'\n]+")

def replace_paths(text):
    def repl(match):
        return anonymize_path(match.group(0))
    return path_pattern.sub(repl, text)

def apply_anonymization(logs):
    for log in logs:
        if "Message" in log:
            log["Message"] = replace_paths(log["Message"])
    return logs

# =========================
# 5. 셔플
# =========================

def shuffle_logs(logs):
    random.shuffle(logs)
    return logs

# =========================
# 6. 반복 패턴 완화
# =========================

def reduce_pattern_bias(logs, drop_rate=0.4):
    result = []
    for log in logs:
        msg = log.get("Message", "")
        if "http.server" in msg:
            if random.random() < drop_rate:
                continue
        result.append(log)
    return result

# =========================
# 7. LLM 입력 변환
# =========================

def convert_to_ai_input(logs):
    ai_logs = []
    for log in logs:
        ai_logs.append({
            "timestamp": log["TimeCreated"],
            "source": log.get("source"),
            "event_id": log.get("Id"),
            "log": log.get("Message")
        })
    return ai_logs

# =========================
# 실행 파이프라인
# =========================

with open(INPUT_FILE, encoding="utf-8") as f:
    logs = json.load(f)

print(f"[INFO] 원본 로그 수: {len(logs)}")

logs = filter_by_time(logs)
print(f"[INFO] 시간 필터링 후: {len(logs)}")

logs = apply_anonymization(logs)
print("[INFO] 경로 치환 완료")

logs = reduce_pattern_bias(logs)
print("[INFO] 패턴 완화 완료")

logs = shuffle_logs(logs)
print("[INFO] 셔플 완료")

ai_input = convert_to_ai_input(logs)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(ai_input, f, indent=2, ensure_ascii=False)

print("[INFO] 완료 → final_ai_input.json 생성")
