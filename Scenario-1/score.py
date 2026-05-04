import json

GT_PATH = "sua/ground_truth.json"
LEVELS = ["level0_baseline", "level1_shuffle", "level2_noise", "level3_shuffle_noise"]

with open(GT_PATH, "r", encoding="utf-8-sig") as f:
    gt = json.load(f)

attack_records = [r for r in gt["records"] if r.get("attack", False)]

def map_stage(name):
    n = name.lower().strip().replace("_", " ")

    # initial access / browser / download
    if any(k in n for k in ["browser", "url access", "phishing", "initial compromise",
                              "initial access", "drive by", "ingress"]):
        return "initial_access"

    elif any(k in n for k in ["file download", "download", "script download"]):
        return "initial_access"

    # execution
    elif any(k in n for k in ["script execution", "powershell", "execution", "payload",
                                "code exec", "tool exec", "sniffing tool"]):
        return "execution"

    # discovery / recon
    elif any(k in n for k in ["reconnaissance", "system recon", "network recon",
                                "network config", "network discovery", "network exploration",
                                "directory discovery", "file and directory", "enumeration",
                                "privilege check", "exploration", "system info", "ipconfig",
                                "recon", "scanning", "scan"]):
        return "discovery"

    # collection / staging
    elif any(k in n for k in ["file staging", "staging", "collection", "gather",
                                "file collect", "data collect"]):
        return "collection"

    # c2 / beacon
    elif any(k in n for k in ["c2", "beacon", "c2 beacon", "c2 fallback", "fallback beacon",
                                "command and control", "callback", "connection establish",
                                "port bind", "network connection"]):
        return "c2"

    # archive / compress
    elif any(k in n for k in ["archive", "compress", "zip", "packaging",
                                "archive creation", "archive fail", "archive success",
                                "archive retry"]):
        return "collection"

    # masquerading / defense evasion
    elif any(k in n for k in ["masquerad", "file masquerad", "rename", "obfuscat",
                                "defense evasion", "evasion", "covering tracks"]):
        return "defense_evasion"

    # email / communication artifact
    elif any(k in n for k in ["email", "eml", "draft", "email draft", "email artifact"]):
        return "collection"

    # exfiltration / upload / removable media / vhd / usb
    elif any(k in n for k in ["exfil", "upload", "transfer", "removable media",
                                "removable", "usb", "vhd", "bulk copy", "copy bulk",
                                "data exfil", "final exfil", "external upload"]):
        return "exfiltration"

    # persistence / account
    elif any(k in n for k in ["account creation", "local account", "backdoor",
                                "persistence", "runkey", "scheduler"]):
        return "persistence"

    # privilege escalation
    elif any(k in n for k in ["privilege", "priv check", "permission", "escalation"]):
        return "discovery"

    # packet capture / sniffing
    elif any(k in n for k in ["sniff", "capture", "pcap", "packet", "tshark"]):
        return "collection"

    # credential
    elif any(k in n for k in ["credential", "password", "extraction", "auth extract"]):
        return "credential_access"

    # lateral movement / rdp
    elif any(k in n for k in ["rdp", "lateral", "remote login", "login success",
                                "login attempt", "login fail", "brute"]):
        return "lateral_movement"

    # cleanup / deletion
    elif any(k in n for k in ["cleanup", "deletion", "remove", "tool removal",
                                "log tamper", "evidence", "file delet", "partial cleanup",
                                "temporary cleanup", "tool cleanup"]):
        return "defense_evasion"

    else:
        return "unknown"

# GT도 map_stage로 추상화
gt_seq = [map_stage(r.get("action_type", "")) for r in attack_records]

def lcs_length(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(1, m+1):
        for j in range(1, n+1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    return dp[m][n]

summary = []
SEP = "=" * 50

for level in LEVELS:
    input_path = "llm_result_" + level + ".json"
    output_path = "evaluation_result_" + level + ".json"

    print("\n" + SEP)
    print("▶ " + level)
    print(SEP)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            llm = json.load(f)
    except FileNotFoundError:
        print("❌ " + input_path + " 없음 - 스킵")
        continue

    pred_raw = [s["stage_name"].lower().strip() for s in llm["stages"]]
    pred_seq = [map_stage(x) for x in pred_raw]

    correct = sum(g == p for g, p in zip(gt_seq, pred_seq))
    stage_acc = correct / len(gt_seq)
    lcs = lcs_length(gt_seq, pred_seq)
    seq_sim = (2 * lcs) / (len(gt_seq) + len(pred_seq))
    gt_set = set(gt_seq)
    pred_set = set(pred_seq)
    scenario_acc = len(gt_set & pred_set) / len(gt_set | pred_set)

    print("=== Stage별 비교 ===")
    for i, (g, p_raw, p) in enumerate(zip(gt_seq, pred_raw, pred_seq), start=1):
        mark = "✅" if g == p else "❌"
        print("  Stage " + str(i) + ": " + mark + " | GT=" + g + " | LLM=" + p_raw + " → " + p)

    print("\n  Stage-level Accuracy   : " + str(round(stage_acc, 4)))
    print("  Sequence Similarity    : " + str(round(seq_sim, 4)))
    print("  Scenario-level Accuracy: " + str(round(scenario_acc, 4)))

    result = {
        "level": level,
        "stage_accuracy": stage_acc,
        "sequence_similarity": seq_sim,
        "scenario_accuracy": scenario_acc,
        "gt_sequence": gt_seq,
        "llm_sequence": pred_seq,
        "llm_raw_sequence": pred_raw,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("\n  ✅ " + output_path + " 저장 완료")
    summary.append(result)

print("\n\n" + SEP)
print("▶ 전체 요약")
print(SEP)
print("{:<25} {:>10} {:>10} {:>14}".format("Level", "Stage Acc", "Seq Sim", "Scenario Acc"))
print("-" * 60)
for r in summary:
    print("{:<25} {:>10.4f} {:>10.4f} {:>14.4f}".format(
        r["level"], r["stage_accuracy"], r["sequence_similarity"], r["scenario_accuracy"]))

with open("evaluation_summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print("\n✅ evaluation_summary.json 저장 완료")