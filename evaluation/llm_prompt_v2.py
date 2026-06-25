"""
LLM Forensic Reasoning - Prompt v2
AI-ForensicBench / ELP Team
"""

PRIMITIVE_VOCABULARY = [
    "payload_delivery",
    "execution",
    "discovery",
    "collection",
    "command_and_control",
    "exfiltration",
    "persistence",
    "credential_access",
    "defense_evasion",
    "impact",
]

SYSTEM_PROMPT = """You are a digital forensics analyst specializing in Windows incident response.

Your task is to analyze correlated forensic evidence groups and reconstruct the attack flow.

## Stage Vocabulary
Only use the following exact stage names. Do not paraphrase or create synonymous stage labels.
- payload_delivery
- execution
- discovery
- collection
- command_and_control
- exfiltration
- persistence
- credential_access
- defense_evasion
- impact

## Rules
1. Only use the exact primitive names listed above. Do NOT invent new stage names.
2. Every stage MUST reference at least one valid evidence_id from the input evidence groups.
3. Do not generate a stage without evidence support.
4. If you are uncertain about a stage, include it in the "uncertain" list with a reason.
5. Output MUST be valid JSON only. No additional text, no markdown, no explanation outside JSON.

## Group Boundary Semantics
Each evidence group represents a cluster of forensic events that are strongly related by
process lineage, shared artifacts, or temporal proximity.
Do NOT split a single group into multiple stages unless the events within it clearly map to
distinct attack phases with separate evidence support.

## Output Format
{
  "timeline": [
    {
      "stage": "<primitive>",
      "evidence_ids": ["<id1>", "<id2>"],
      "reason": "<one sentence explanation based on evidence>"
    }
  ],
  "uncertain": [
    {
      "stage": "<primitive>",
      "reason": "<why this stage is uncertain>"
    }
  ],
  "analyst_summary": "<2-3 sentence overall attack flow summary>"
}
"""


def build_user_prompt(correlated_evidence: list) -> str:
    lines = []
    lines.append("The following is a sequence of correlated forensic evidence groups observed during a Windows security incident.")
    lines.append("")
    lines.append("Each group represents a set of strongly related forensic events connected by process lineage, shared artifacts, or temporal proximity.")
    lines.append("Events within the same group are considered strongly related forensic evidence and should be analyzed together during attack reconstruction.")
    lines.append("")
    lines.append("Analyze the evidence groups and reconstruct the attack flow using only the allowed stage vocabulary.")
    lines.append("")
    lines.append("=== FORENSIC EVIDENCE GROUPS ===")
    lines.append("")

    for group in correlated_evidence:
        group_id = group.get("group_id")
        score    = group.get("score", "N/A")
        events   = group.get("related_events", [])

        lines.append(f"[Group {group_id}] (correlation_score: {score})")
        for event in events:
            event_id   = event.get("event_id", "")
            event_type = event.get("event_type", "")
            process    = event.get("process", "")
            timestamp  = event.get("timestamp", "")
            artifact   = event.get("artifact", "")

            line = f"  - [{event_id}] {timestamp} | {event_type} | process: {process}"
            if artifact:
                line += f" | artifact: {artifact}"
            lines.append(line)
        lines.append("")

    lines.append("=== END OF EVIDENCE GROUPS ===")
    lines.append("")
    lines.append("Reconstruct the attack timeline. Reference evidence_ids from the groups above.")

    return "\n".join(lines)


OUTPUT_SCHEMA = {
    "timeline": [
        {
            "stage": "one of PRIMITIVE_VOCABULARY",
            "evidence_ids": ["event_ids from input"],
            "reason": "one sentence, evidence-based",
        }
    ],
    "uncertain": [
        {
            "stage": "one of PRIMITIVE_VOCABULARY",
            "reason": "why uncertain",
        }
    ],
    "analyst_summary": "2-3 sentences overall summary",
}