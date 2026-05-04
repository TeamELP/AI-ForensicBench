import os
import json
import re
import random
from datetime import datetime, timezone, timedelta
from groq import Groq

# ======================
# 설정
# ======================
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "api 입력하세요")

GT_PATH = "sua/ground_truth.json"
MERGED_LOG_PATH = "jiwon/merged_logs.json"
NUM_RUNS = 3

LEVELS = [
    {"name": "level0_baseline",      "shuffle": False},
    {"name": "level1_shuffle",       "shuffle": True},
    {"name": "level3_shuffle_noise", "shuffle": True},
]

client = Groq(api_key=GROQ_API_KEY)

with open(GT_PATH, "r", encoding="utf-8-sig") as f:
    gt = json.load(f)

attack_records = [r for r in gt["records"] if r.get("attack", False)]
num_attack_stages = len(attack_records)

def get_start(r): return r.get("stage_start_time") or r.get("start", "")
def get_end(r):   return r.get("stage_end_time")   or r.get("end", "")

gt_start = min(get_start(r) for r in attack_records if get_start(r))
gt_end   = max(get_end(r)   for r in attack_records if get_end(r))

KST = timezone(timedelta(hours=9))

def parse_ts(ts):
    if not ts: return None
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None: dt = dt.replace(tzinfo=KST)
    return dt.astimezone(KST)

gt_start_dt = parse_ts(gt_start)
gt_end_dt   = parse_ts(gt_end)
non_attack_dts = [
    (parse_ts(get_start(r)), parse_ts(get_end(r)))
    for r in gt["records"] if not r.get("attack", True)
]

with open(MERGED_LOG_PATH, "r", encoding="utf-8") as f:
    raw_logs = json.load(f)

print("[INFO] 원본 로그 수: " + str(len(raw_logs)))
print("[INFO] GT attack stage 수: " + str(num_attack_stages))
print("[INFO] GT 시간 범위: " + gt_start + " ~ " + gt_end)

NOISE_KEYWORDS = ["VS Code", "Code.exe", "vmtoolsd", "VMware", "vscode", "unparsed"]

def remove_noise(logs):
    return [l for l in logs if not any(kw in json.dumps(l, ensure_ascii=False) for kw in NOISE_KEYWORDS)]

def in_non_attack(dt):
    return any(s and e and s <= dt <= e for s, e in non_attack_dts)

def filter_by_gt_time(logs):
    result = []
    for log in logs:
        try:
            dt = parse_ts(log.get("TimeCreated", ""))
            if dt and not in_non_attack(dt) and gt_start_dt <= dt <= gt_end_dt:
                result.append(log)
        except: pass
    return result

def remove_non_attack_only(logs):
    result = []
    for log in logs:
        try:
            dt = parse_ts(log.get("TimeCreated", ""))
            if not dt or not in_non_attack(dt): result.append(log)
        except: result.append(log)
    return result

def extract_key_fields(msg):
    fields = {}
    patterns = {
        "Image":           r"Image:\s*([^\r\n]+)",
        "CommandLine":     r"CommandLine:\s*([^\r\n]+)",
        "TargetFilename":  r"TargetFilename:\s*([^\r\n]+)",
        "DestinationIp":   r"DestinationIp:\s*([^\r\n]+)",
        "DestinationPort": r"DestinationPort:\s*([^\r\n]+)",
        "RuleName":        r"RuleName:\s*([^\r\n\-][^\r\n]+)",
        "ProcessName":     r"새 프로세스 이름:\s*([^\r\n]+)",
        "Account":         r"계정 이름:\s*\t\t([^\r\n]+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, msg)
        if m:
            val = m.group(1).strip()
            if key in ("Image", "TargetFilename", "ProcessName"): val = val.split("\\")[-1]
            if key == "CommandLine": val = val[:80]
            fields[key] = val
    if not fields: fields["raw"] = msg[:60].replace("\r\n", " ").strip()
    return fields

def log_to_text(log):
    ts  = log.get("TimeCreated", "")
    eid = log.get("Id", "")
    src = log.get("source", "")
    msg = log.get("Message", "")
    return "[" + ts + "] " + str(src) + " EID:" + str(eid) + " " + str(extract_key_fields(msg))

def prepare_logs(level):
    logs = list(raw_logs)
    logs = remove_noise(logs)
    if not level["shuffle"]:
        logs = filter_by_gt_time(logs)
    else:
        logs = remove_non_attack_only(logs)
        random.shuffle(logs)
    return logs

def build_prompt(logs_text, num_stages):
    return """You are a digital forensics analyst.

Analyze the following system event logs and reconstruct the likely attack workflow.
The logs may be incomplete, and some direct evidence for certain stages may be missing.
Note: Some logs are normal system activity (noise) — focus only on attack-related events.

[LOGS]
""" + logs_text + """

Task:
1. Reconstruct exactly """ + str(num_stages) + """ attack stages in chronological order.
2. Use concise, generic stage names (e.g. "system reconnaissance", "data exfiltration").
3. Do NOT include normal login/logoff stages.
4. Output ONLY valid JSON with NO additional text before or after.

Output format:
{
  "stages": [
    {"stage_id": 1, "stage_name": "..."},
    ...
    {"stage_id": """ + str(num_stages) + """, "stage_name": "..."}
  ]
}"""

def map_stage(name):
    n = name.lower().strip().replace("_", " ")
    if any(k in n for k in ["browser", "url access", "initial compromise", "initial access", "file download", "download", "script download", "ingress"]):
        return "initial_access"
    elif any(k in n for k in ["script execution", "powershell", "execution", "payload", "code exec", "tool exec"]):
        return "execution"
    elif any(k in n for k in ["reconnaissance", "system recon", "network recon", "network config", "network discovery", "network exploration", "directory discovery", "file and directory", "enumeration", "exploration", "ipconfig", "recon", "scanning"]):
        return "discovery"
    elif any(k in n for k in ["file staging", "staging", "collection", "gather", "archive", "compress", "zip", "email", "eml", "draft", "packet", "pcap", "sniff"]):
        return "collection"
    elif any(k in n for k in ["c2", "beacon", "c2 fallback", "command and control", "connection establish", "port bind", "network connection"]):
        return "c2"
    elif any(k in n for k in ["masquerad", "rename", "defense evasion", "evasion", "covering tracks", "cleanup", "deletion", "remove", "tool removal", "log tamper", "evidence", "file delet", "partial cleanup", "temporary cleanup"]):
        return "defense_evasion"
    elif any(k in n for k in ["exfil", "upload", "transfer", "removable", "usb", "vhd", "bulk copy", "copy bulk", "data exfil", "external upload"]):
        return "exfiltration"
    elif any(k in n for k in ["account creation", "local account", "backdoor", "persistence", "runkey"]):
        return "persistence"
    elif any(k in n for k in ["credential", "password", "credential access"]):
        return "credential_access"
    elif any(k in n for k in ["lateral", "remote login", "rdp"]):
        return "lateral_movement"
    else:
        return "unknown"

def lcs_length(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(1, m+1):
        for j in range(1, n+1):
            if a[i-1] == b[j-1]: dp[i][j] = dp[i-1][j-1] + 1
            else: dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    return dp[m][n]

gt_seq = [map_stage(r.get("action_type", "")) for r in attack_records]

def score_result(llm_stages):
    pred_raw = [s["stage_name"].lower().strip() for s in llm_stages]
    pred_seq = [map_stage(x) for x in pred_raw]
    correct = sum(g == p for g, p in zip(gt_seq, pred_seq))
    stage_acc = correct / len(gt_seq)
    lcs = lcs_length(gt_seq, pred_seq)
    seq_sim = (2 * lcs) / (len(gt_seq) + len(pred_seq))
    gt_set = set(gt_seq)
    pred_set = set(pred_seq)
    scenario_acc = len(gt_set & pred_set) / len(gt_set | pred_set)
    return stage_acc, seq_sim, scenario_acc, pred_raw, pred_seq

def run_level(level, run_num):
    name = level["name"]
    logs = prepare_logs(level)
    logs_text = "\n".join(log_to_text(l) for l in logs)
    prompt = build_prompt(logs_text, num_attack_stages)

    llm_output = ""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        llm_output = response.choices[0].message.content

        clean = llm_output.strip()
        if "```" in clean:
            parts = clean.split("```")
            for part in parts:
                if part.strip().startswith("{") or part.strip().startswith("json"):
                    clean = part.strip()
                    if clean.startswith("json"): clean = clean[4:]
                    break
        clean = clean.strip()

        start = clean.find("{")
        end = clean.rfind("}") + 1
        if start != -1 and end > start:
            clean = clean[start:end]

        result = json.loads(clean)

        if "stages" not in result or len(result["stages"]) != num_attack_stages:
            raise ValueError("stages 개수 오류: " + str(len(result.get("stages", []))))

        stage_acc, seq_sim, scenario_acc, pred_raw, pred_seq = score_result(result["stages"])
        return {"success": True, "stage_accuracy": stage_acc, "sequence_similarity": seq_sim,
                "scenario_accuracy": scenario_acc, "pred_raw": pred_raw, "pred_seq": pred_seq}

    except Exception as e:
        print("  ❌ 오류: " + str(e))
        return {"success": False}

# ======================
# 실행: NUM_RUNS회 반복 후 평균
# ======================
if __name__ == "__main__":
    all_results = {l["name"]: {"stage_accuracy": [], "sequence_similarity": [], "scenario_accuracy": []} for l in LEVELS}

    for run in range(1, NUM_RUNS + 1):
        print("\n" + "=" * 60)
        print("▶▶ RUN " + str(run) + " / " + str(NUM_RUNS))
        print("=" * 60)

        for level in LEVELS:
            name = level["name"]
            print("\n  [" + name + "]")
            result = run_level(level, run)
            if result["success"]:
                all_results[name]["stage_accuracy"].append(result["stage_accuracy"])
                all_results[name]["sequence_similarity"].append(result["sequence_similarity"])
                all_results[name]["scenario_accuracy"].append(result["scenario_accuracy"])
                print("  Stage Acc=" + str(round(result["stage_accuracy"], 4)) +
                      " Seq Sim=" + str(round(result["sequence_similarity"], 4)) +
                      " Scenario Acc=" + str(round(result["scenario_accuracy"], 4)))

    print("\n\n" + "=" * 60)
    print("▶ " + str(NUM_RUNS) + "회 평균 결과")
    print("=" * 60)
    print("{:<25} {:>10} {:>10} {:>14}".format("Level", "Stage Acc", "Seq Sim", "Scenario Acc"))
    print("-" * 60)

    summary = []
    for level in LEVELS:
        name = level["name"]
        vals = all_results[name]
        if not vals["stage_accuracy"]:
            print(name + ": 결과 없음")
            continue

        n = len(vals["stage_accuracy"])
        avg_s = sum(vals["stage_accuracy"]) / n
        avg_q = sum(vals["sequence_similarity"]) / n
        avg_c = sum(vals["scenario_accuracy"]) / n
        std_s = (sum((x-avg_s)**2 for x in vals["stage_accuracy"]) / n) ** 0.5
        std_q = (sum((x-avg_q)**2 for x in vals["sequence_similarity"]) / n) ** 0.5
        std_c = (sum((x-avg_c)**2 for x in vals["scenario_accuracy"]) / n) ** 0.5

        print("{:<25} {:>10.4f} {:>10.4f} {:>14.4f}".format(name, avg_s, avg_q, avg_c))
        print("{:<25} {:>10} {:>10} {:>14}".format(
            "  (std)", "+-" + str(round(std_s, 4)), "+-" + str(round(std_q, 4)), "+-" + str(round(std_c, 4))))

        summary.append({"level": name, "avg_stage_accuracy": avg_s, "avg_sequence_similarity": avg_q,
                         "avg_scenario_accuracy": avg_c, "std_stage_accuracy": std_s,
                         "std_sequence_similarity": std_q, "std_scenario_accuracy": std_c,
                         "raw": vals})

    with open("evaluation_average.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n✅ evaluation_average.json 저장 완료")