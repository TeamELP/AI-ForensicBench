"""
run_eval.py
AI-ForensicBench / ELP Team

터미널에서 GT 검증 + 메트릭 출력.

사용법:
    python run_eval.py --scenario 1
    python run_eval.py --scenario 1 2 3
    python run_eval.py --all
"""

import json
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gt_verification import load_gt_primitives, compute_metrics, print_verification_report

BASE = os.path.join(os.path.dirname(__file__), "..", "scenarios")

GT_FILES = {
    1:  "scenario1/ground_truth_scenario1.json",
    2:  "scenario2/ground_truth_2.json",
    3:  "scenario3/ground_truth_scenario3.json",
    4:  "scenario4/ground_truth_scenario4.json",
    5:  "scenario5/ground_truth_scenario5.json",
    6:  "scenario6/ground_truth_scenario6.json",
    7:  "scenario7/ground_truth_scenario7.json",
    8:  "scenario8/ground_truth_scenario8.json",
    9:  "scenario9/ground_truth_scenario9.json",
    10: "scenario10/ground_truth_scenario10.json",
}


def run_single(sc_num: int):
    gt_path  = os.path.join(BASE, GT_FILES[sc_num])
    llm_path = os.path.join(BASE, f"scenario{sc_num}", "outputs", "llm_output.json")

    print(f"\n{'='*60}")
    print(f"SCENARIO {sc_num}")
    print(f"{'='*60}")

    if not os.path.exists(gt_path):
        print(f"[ERROR] GT 파일 없음: {gt_path}")
        return

    if not os.path.exists(llm_path):
        print(f"[ERROR] llm_output.json 없음: {llm_path}")
        print(f"        먼저 make_llm.py 돌려야 해:")
        print(f"        python make_llm.py --input ../scenarios/scenario{sc_num}/outputs/semantic_activities.json --output ../scenarios/scenario{sc_num}/outputs/llm_output.json")
        return

    gt_primitives = load_gt_primitives(gt_path)

    with open(llm_path, encoding="utf-8") as f:
        llm_out = json.load(f)

    llm_primitives = [s["stage"] for s in llm_out.get("timeline", [])]

    if not llm_primitives:
        print("[ERROR] llm_output.json에 timeline이 비어있음")
        return

    metrics = compute_metrics(gt_primitives, llm_primitives)
    print_verification_report(metrics)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", type=int, nargs="+", help="시나리오 번호 (예: --scenario 1 2 3)")
    group.add_argument("--all", action="store_true", help="전체 시나리오 실행")
    args = parser.parse_args()

    if args.all:
        targets = list(GT_FILES.keys())
    else:
        targets = args.scenario

    for sc in targets:
        if sc not in GT_FILES:
            print(f"[ERROR] 시나리오 {sc}번 없음 (1~10만 가능)")
            continue
        run_single(sc)

    print("\n완료.")


if __name__ == "__main__":
    main()
