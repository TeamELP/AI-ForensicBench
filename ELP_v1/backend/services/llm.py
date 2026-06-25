"""
Send correlated events to OpenAI and parse the structured forensic analysis.
"""
import json
import os
import sys
from difflib import SequenceMatcher
from openai import AsyncOpenAI

# evaluation 폴더 import 경로 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "evaluation"))
from gt_verification import load_gt_primitives, compute_metrics

client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# 시나리오별 GT 파일 경로 매핑
_SCENARIOS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "scenarios")
GT_PATH_MAP = {
    "scenario1":  "scenario1/ground_truth_scenario1.json",
    "scenario2":  "scenario2/ground_truth_2.json",
    "scenario3":  "scenario3/ground_truth_scenario3.json",
    "scenario4":  "scenario4/ground_truth_scenario4.json",
    "scenario5":  "scenario5/ground_truth_scenario5.json",
    "scenario6":  "scenario6/ground_truth_scenario6.json",
    "scenario7":  "scenario7/ground_truth_scenario7.json",
    "scenario8":  "scenario8/ground_truth_scenario8.json",
    "scenario9":  "scenario9/ground_truth_scenario9.json",
    "scenario10": "scenario10/ground_truth_scenario10.json",
}


def _resolve_gt_path(filename: str) -> str | None:
    """
    업로드된 파일명에서 시나리오 번호 추출 후 GT 경로 반환.
    예: "security_events.csv", "sysmon_events(4).csv" → scenario4
    매칭 실패 시 None 반환.
    """
    import re
    # 파일명에서 숫자 추출 시도
    m = re.search(r'(\d+)', filename)
    if m:
        key = f"scenario{m.group(1)}"
        rel = GT_PATH_MAP.get(key)
        if rel:
            return os.path.join(_SCENARIOS_DIR, rel)
    return None


SYSTEM_PROMPT = """You are an expert Windows forensic analyst specializing in attack chain reconstruction and MITRE ATT&CK mapping.

Given a list of correlated Windows event log entries, reconstruct the attack chain and produce a structured forensic report.

Attack stage primitives (use ONLY these exact strings):
  payload_delivery, execution, discovery, collection,
  command_and_control, exfiltration, persistence,
  credential_access, defense_evasion, impact

Rules:
- Only include stages that have clear evidence in the logs.
- Order stages chronologically.
- evidence_indices must reference the "id" field of the input events.
- severity: "low" | "medium" | "high" | "critical"
- risk for IOCs: "low" | "medium" | "high" | "critical"

Return ONLY valid JSON — no markdown, no explanation — matching this schema exactly:
{
  "attack_timeline": [
    {
      "stage": string,
      "tactic": string,
      "tacticName": string,
      "timestamp": string,
      "description": string,
      "severity": string,
      "evidence_indices": number[]
    }
  ],
  "summary": string,
  "kill_chain": string[],
  "iocs": [{"type": string, "value": string, "risk": string}],
  "recommendations": string[]
}"""


def _format_events(events: list[dict]) -> str:
    lines = []
    for e in events:
        lines.append(
            f"[{e['id']}] {e['time']}  src={e['source']}  "
            f"EventID={e['event_id']}  level={e['level']}\n  {e['message']}"
        )
    return "\n".join(lines)


def _seq_similarity(a: list, b: list) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _build_response(raw: dict, events: list[dict], mode: str, filename: str) -> dict:
    timeline = raw.get("attack_timeline", [])

    # Map evidence_indices → actual log entries grouped by stage
    evidence_logs: dict[int, list] = {}
    for i, stage in enumerate(timeline, start=1):
        idx_list = stage.pop("evidence_indices", [])
        id_set   = set(idx_list)
        stage_logs = [
            {
                "time":   e["time"],
                "source": e["source"],
                "level":  e["level"],
                "msg":    e["message"],
            }
            for e in events if e["id"] in id_set
        ]
        evidence_logs[i] = stage_logs
        stage["id"]    = i
        stage["color"] = "red" if stage.get("severity") in ("critical",) else "orange"

    analyst_report = {
        "caseId":          "CASE-AUTO-001",
        "date":            (timeline[0]["timestamp"][:10] if timeline else ""),
        "analyst":         "ForensicAI v1.0",
        "severity":        "CRITICAL" if any(
            s.get("severity") == "critical" for s in timeline
        ) else "HIGH",
        "summary":         raw.get("summary", ""),
        "killChain":       raw.get("kill_chain", []),
        "iocs":            raw.get("iocs", []),
        "recommendations": raw.get("recommendations", []),
    }

    base = {
        "attack_timeline": timeline,
        "evidence_logs":   evidence_logs,
        "analyst_report":  analyst_report,
    }

    if mode == "dev":
        llm_predicted = [s["stage"] for s in timeline]

        # GT 로드 — 파일명으로 시나리오 매칭
        gt_path = _resolve_gt_path(filename)
        if gt_path and os.path.exists(gt_path):
            gt_sequence = load_gt_primitives(gt_path)
        else:
            # GT 매칭 실패 시 빈 리스트 (메트릭은 0으로 표시)
            gt_sequence = []

        # gt_verification.compute_metrics() 사용
        m = compute_metrics(gt_sequence, llm_predicted)

        base.update({
            "ground_truth":  gt_sequence,
            "llm_predicted": llm_predicted,
            "metrics": {
                "stageAccuracy":      round(m["stage_accuracy"] * 100),
                "sequenceSimilarity": round(m["sequence_similarity"], 2),
                "missing":            len(m["missing"]),
                "unsupported":        len(m["unsupported"]),
                "missing_stages":     m["missing"],
                "unsupported_stages": m["unsupported"],
            },
            "grounding_rows": [
                {
                    "stage":      s["stage"],
                    "status":     "correct" if s["stage"] in m["matched"] else "wrong",
                    "evidence":   [e["msg"][:80] for e in evidence_logs.get(s["id"], [])[:2]],
                    "confidence": 0.92,
                }
                for s in timeline
            ],
        })

    return base


async def analyze_with_llm(events: list[dict], filename: str, mode: str) -> dict:
    if not events:
        raise ValueError("No events to analyze after correlation.")

    user_msg = (
        f"Analyze these {len(events)} Windows event log entries from '{filename}':\n\n"
        + _format_events(events)
    )

    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )

    raw_json = json.loads(response.choices[0].message.content)
    return _build_response(raw_json, events, mode, filename)
