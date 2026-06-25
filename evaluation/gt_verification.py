"""
GT Verification
AI-ForensicBench / ELP Team

LLM reconstruction 결과와 GT primitive sequence를 비교하여
4개 metric을 계산한다.

Metrics:
- Stage Accuracy
- Sequence Similarity (LCS)
- Missing Stage
- Unsupported Stage Generation
"""

import json

# ============================================================
# GT action_type → Primitive Mapping Table
# 실제 GT 파일 10개 전수 조사 기반 완성본
#
# Primitive vocabulary (10개):
#   payload_delivery, execution, persistence, discovery,
#   collection, exfiltration, command_and_control,
#   defense_evasion, credential_access, impact
#
# None = attack:false stage → 채점 제외
# ============================================================
ACTION_TYPE_MAP = {

    # ────────────────────────────────────────────
    # attack:false — 채점 제외
    # ────────────────────────────────────────────
    "user_logon":                                   None,
    "logon":                                        None,
    "logon_session":                                None,
    "process_exit":                                 None,
    "session_logoff":                               None,
    "session_termination":                          None,
    "logoff":                                       None,
    "residual_artifact":                            None,
    "residual_artifact_state":                      None,
    "wal_artifact_remaining":                       None,

    # ────────────────────────────────────────────
    # payload_delivery
    # ────────────────────────────────────────────
    "browser_url_access":                           "payload_delivery",
    "file_download":                                "payload_delivery",
    "rdp_bruteforce_initial_access":                "payload_delivery",
    "privileged_session_established":               "payload_delivery",
    "payload_transfer":                             "payload_delivery",
    "remote_login_attempt":                         "payload_delivery",
    "remote_login_success":                         "payload_delivery",
    "tool_download":                                "payload_delivery",

    # ────────────────────────────────────────────
    # execution
    # ────────────────────────────────────────────
    "script_execution":                             "execution",
    "fileless_execution":                           "execution",
    "payload_execution_fail":                       "execution",
    "payload_execution_success":                    "execution",
    "process_start":                                "execution",
    "process_execution":                            "execution",
    "command_execution":                            "execution",
    "process_access":                               "execution",
    "tool_execution":                               "execution",
    "powershell_execution":                         "execution",
    "lolbin_execution":                             "execution",
    "proxy_execution":                              "execution",
    "mounted_media_execution":                      "execution",
    "tool_unpacking":                               "execution",
    "browser_launch":                               "execution",
    "script_deployment":                            "execution",
    "driver_staging":                               "execution",
    "driver_load":                                  "execution",
    "memory_tool_execution":                        "execution",
    "process_injection_simulation":                 "execution",
    "privilege_escalation_adjustment":              "execution",

    # ────────────────────────────────────────────
    # persistence
    # ────────────────────────────────────────────
    "registry_modification":                        "persistence",
    "task_creation":                                "persistence",
    "account_creation":                             "persistence",
    "wallet_monitoring_persistence":                "persistence",
    "kernel_service_creation":                      "persistence",
    "scheduled_task_creation":                      "persistence",

    # ────────────────────────────────────────────
    # discovery
    # ────────────────────────────────────────────
    "system_reconnaissance":                        "discovery",
    "system_recon":                                 "discovery",
    "system_discovery":                             "discovery",
    "file_and_directory_discovery":                 "discovery",
    "privilege_enumeration":                        "discovery",
    "network_recon":                                "discovery",
    "privileged_account_discovery":                 "discovery",
    "network_configuration_discovery":              "discovery",
    "remote_system_discovery":                      "discovery",
    "network_share_discovery":                      "discovery",
    "domain_trust_discovery":                       "discovery",
    "security_software_discovery":                  "discovery",
    "wallet_application_discovery":                 "discovery",
    "privilege_validation":                         "discovery",
    "driver_validation":                            "discovery",
    "process_discovery":                            "discovery",
    "domain_reconnaissance":                        "discovery",
    "account_discovery":                            "discovery",
    "policy_discovery":                             "discovery",
    "service_discovery":                            "discovery",
    "service_status_check":                         "discovery",
    "privilege_token_inspection":                   "discovery",
    "network_topology_discovery":                   "discovery",
    "domain_controller_and_trust_discovery":        "discovery",
    "security_process_enumeration":                 "discovery",

    # ────────────────────────────────────────────
    # collection
    # ────────────────────────────────────────────
    "file_staging":                                 "collection",
    "archive_creation_fail":                        "collection",
    "archive_creation_success":                     "collection",
    "file_masquerading":                            "collection",
    "packet_capture":                               "collection",
    "analysis":                                     "collection",
    "local_data_staging":                           "collection",
    "sensitive_portal_access":                      "collection",
    "sensitive_document_download":                  "collection",
    "sqlite_history_recon":                         "collection",
    "history_export_recon":                         "collection",
    "sqlite_reconnaissance":                        "collection",
    "history_export":                               "collection",
    "clipboard_monitoring":                         "collection",
    "transaction_interception":                     "collection",
    "wallet_staging_directory_preparation":         "collection",
    "data_staging":                                 "collection",
    "reconnaissance_result_staging":                "collection",
    "file_create":                                  "collection",
    "file_access":                                  "collection",

    # ────────────────────────────────────────────
    # exfiltration
    # ────────────────────────────────────────────
    "email_draft_preparation":                      "exfiltration",
    "data_exfiltration":                            "exfiltration",
    "removable_media_simulation":                   "exfiltration",
    "copy_bulk_data_to_removable_media":            "exfiltration",
    "dns_exfiltration_simulation":                  "exfiltration",

    # ────────────────────────────────────────────
    # command_and_control
    # ────────────────────────────────────────────
    "c2_beacon_attempt":                            "command_and_control",
    "c2_fallback_beacon":                           "command_and_control",
    "network_connection":                           "command_and_control",
    "background_transfer":                          "command_and_control",

    # ────────────────────────────────────────────
    # defense_evasion
    # ────────────────────────────────────────────
    "partial_artifact_deletion":                    "defense_evasion",
    "cleanup":                                      "defense_evasion",
    "file_deletion":                                "defense_evasion",
    "file_delete":                                  "defense_evasion",
    "tool_cleanup":                                 "defense_evasion",
    "artifact_cleanup":                             "defense_evasion",
    "artifact_concealment":                         "defense_evasion",
    "initial_cleanup_attempt":                      "defense_evasion",
    "final_cleanup_partial":                        "defense_evasion",
    "temporary_artifact_cleanup":                   "defense_evasion",
    "temporary_wallet_cleanup":                     "defense_evasion",
    "defender_disable_attempt_fail":                "defense_evasion",
    "defender_disable_retry":                       "defense_evasion",
    "service_config_modification_attempt_fail":     "defense_evasion",
    "service_config_modification_retry_success":    "defense_evasion",
    "hosts_file_tampering":                         "defense_evasion",
    "log_deletion_attempt_fail":                    "defense_evasion",
    "log_deletion_retry_partial_success":           "defense_evasion",
    "eventlog_tampering_attempt":                   "defense_evasion",
    "eventlog_cleanup_attempt":                     "defense_evasion",
    "payload_decode":                               "defense_evasion",
    "process_masquerading":                         "defense_evasion",
    "browser_artifact_cleanup":                     "defense_evasion",
    "browser_history_tampering":                    "defense_evasion",
    "download_record_tampering":                    "defense_evasion",
    "download_record_manipulation":                 "defense_evasion",
    "prefetch_cleanup":                             "defense_evasion",
    "prefetch_artifact_cleanup":                    "defense_evasion",
    "process_termination":                          "defense_evasion",
    "clipboard_manipulation_attempt":               "defense_evasion",
    "transaction_deception":                        "defense_evasion",
    "rootkit_behavior":                             "defense_evasion",
    "driver_unload_attempt":                        "defense_evasion",
    "driver_load_execution":                        "defense_evasion",
    "registry_cleanup_attempt":                     "defense_evasion",
    "hidden_directory_creation":                    "defense_evasion",
    "hidden_recon_directory_creation":              "defense_evasion",
    "hidden_process_simulation":                    "defense_evasion",
    "suspicious_memory_activity":                   "defense_evasion",
    "recon_script_deployment_and_execution":        "defense_evasion",
    "file_modification":                            "defense_evasion",
    "service_modification":                         "defense_evasion",
    "service_policy_modification":                  "defense_evasion",
    "session_token":                                "defense_evasion",

    # ────────────────────────────────────────────
    # credential_access
    # ────────────────────────────────────────────
    "credential_search":                            "credential_access",
    "metamask_leveldb_access":                      "credential_access",
    "wallet_file_collection":                       "credential_access",
    "seed_phrase_keyword_search":                   "credential_access",
    "clipboard_seed_monitoring":                    "credential_access",
    "lsass_handle_access":                          "credential_access",
    "lsass_memory_access":                          "credential_access",
    "credential_collection":                        "credential_access",

    # ────────────────────────────────────────────
    # impact
    # ────────────────────────────────────────────
    "file_encryption_partial":                      "impact",
    "mbr_modification_attempt_fail":                "impact",
    "ransom_note_creation":                         "impact",
    "service_disruption":                           "impact",
    "service_stop_attempt_fail":                    "impact",
    "service_stop_retry_success":                   "impact",
    "service_restart_loop_attempt":                 "impact",
    "service_restart_loop_retry":                   "impact",
    "service_disruption_observed":                  "impact",
    "service_stop":                                 "impact",
    "service_restart":                              "impact",
    "service_state_manipulation":                   "impact",
    "financial_transaction_manipulation":           "impact",
}


# ============================================================
# GT 로드 및 Primitive Sequence 변환
# ============================================================
def load_gt_primitives(gt_path: str) -> list:
    with open(gt_path, "r", encoding="utf-8-sig") as f:
        gt = json.load(f)

    records = gt.get("records", [])
    primitives = []

    for record in records:
        if not record.get("attack", False):
            continue

        action_type = record.get("action_type", "")
        primitive = ACTION_TYPE_MAP.get(action_type)

        if action_type not in ACTION_TYPE_MAP:
            print(f"[WARNING] 매핑 없음: {action_type} (stage_id: {record.get('stage_id')})")
            continue

        if primitive is None:
            continue  # attack:false 계열 명시 등록 — 조용히 스킵

        primitives.append(primitive)

    return primitives


# ============================================================
# LLM 출력에서 Primitive Sequence 추출
# ============================================================
def load_llm_primitives(llm_output: dict) -> list:
    timeline = llm_output.get("timeline", [])
    return [item.get("stage", "") for item in timeline]


# ============================================================
# LCS
# ============================================================
def lcs_length(a: list, b: list) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    return dp[m][n]


# ============================================================
# 4개 Metric 계산
# ============================================================
def compute_metrics(gt_primitives: list, llm_primitives: list) -> dict:
    gt_set = set(gt_primitives)
    llm_set = set(llm_primitives)

    matched = gt_set & llm_set
    stage_accuracy = len(matched) / len(gt_set) if gt_set else 0.0

    lcs = lcs_length(gt_primitives, llm_primitives)
    total = len(gt_primitives) + len(llm_primitives)
    sequence_similarity = (2 * lcs) / total if total > 0 else 0.0

    missing = list(gt_set - llm_set)
    unsupported = list(llm_set - gt_set)

    return {
        "stage_accuracy": round(stage_accuracy, 4),
        "sequence_similarity": round(sequence_similarity, 4),
        "missing": missing,
        "unsupported": unsupported,
        "gt_sequence": gt_primitives,
        "llm_sequence": llm_primitives,
        "matched": list(matched),
    }


# ============================================================
# 리포트 출력
# ============================================================
def print_verification_report(metrics: dict):
    print("\n" + "="*60)
    print("GT VERIFICATION REPORT")
    print("="*60)

    print("\n[GT Sequence]")
    print(" → ".join(metrics["gt_sequence"]))

    print("\n[LLM Sequence]")
    print(" → ".join(metrics["llm_sequence"]))

    print("\n[Metrics]")
    print(f"  Stage Accuracy      : {metrics['stage_accuracy']}")
    print(f"  Sequence Similarity : {metrics['sequence_similarity']}")
    print(f"  Missing             : {metrics['missing']}")
    print(f"  Unsupported         : {metrics['unsupported']}")
    print(f"  Matched             : {metrics['matched']}")
    print("="*60)


# ============================================================
# 전체 시나리오 WARNING 검증
# ============================================================
def verify_all_scenarios(base_dir: str):
    import os
    import glob

    gt_files = sorted(glob.glob(os.path.join(base_dir, "scenario*/ground_truth*.json")))
    total_warnings = 0

    for gt_path in gt_files:
        sc_name = os.path.basename(os.path.dirname(gt_path))
        with open(gt_path, encoding="utf-8-sig") as f:
            gt = json.load(f)
        warnings = 0
        for r in gt.get("records", []):
            if r.get("attack"):
                at = r.get("action_type", "")
                if at not in ACTION_TYPE_MAP:
                    print(f"  [WARNING] {sc_name} stage {r['stage_id']}: {at}")
                    warnings += 1
        if warnings == 0:
            print(f"  [OK] {sc_name}")
        total_warnings += warnings

    print(f"\n총 WARNING: {total_warnings}개")


if __name__ == "__main__":
    import os
    base = os.path.join(os.path.dirname(__file__), "..", "scenarios")
    verify_all_scenarios(base)
