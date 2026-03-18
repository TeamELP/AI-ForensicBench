# 🧠 AI-ForensicBench

> **AI Forensic Reasoning Benchmark with Ground-Truth-Guaranteed Data**

---

## 🚀 Overview

AI-ForensicBench는 **포렌식 사건 시나리오를 자동 실행**하고,
실행과 동시에 **Ground Truth와 시스템 아티팩트를 병렬 기록**하여
AI 모델의 포렌식 추론 능력을 평가하는 벤치마크 프레임워크입니다.

---

## ⚡ Why AI-ForensicBench?

기존 디지털 포렌식 AI 연구의 가장 큰 문제는:

> ❗ **정확한 Ground Truth 데이터 부족**

이로 인해 AI 모델의 성능을 **객관적으로 평가하기 어려움**

---

## 💡 Key Features

### 🧾 Ground Truth 자동 생성

* 시나리오 실행과 동시에 정답 데이터 생성
* **라벨 노이즈 없는 데이터셋**

### 🧠 AI Forensic Reasoning Benchmark

* 사건 유형 분류 (Classification)
* 타임라인 재구성 (Timeline Reconstruction)

### 🔀 Dual Recording Architecture

* 실제 행동 (Ground Truth)
* 시스템 흔적 (Artifacts)
  👉 **두 데이터를 분리 저장**

---

## 🏗 System Architecture

```text
Scenario Execution
   ↓
Ground Truth Recording   +   Artifact Collection
   ↓                          ↓
      → Dataset Builder ←
               ↓
        Prompt Builder
               ↓
           AI Analyzer
               ↓
      Benchmark Evaluator
               ↓
        Result Dashboard
```

---

## 📁 Project Structure

```bash
AI-ForensicBench/
 ├── label_schema.json
 ├── run_pipeline.py
 │
 ├── src/
 │    ├── scenario_executor.py
 │    ├── ground_truth_recorder.py
 │    ├── artifact_collector.py
 │    ├── dataset_builder.py
 │    ├── prompt_builder.py
 │    ├── ai_analyzer.py
 │    └── benchmark_evaluator.py
 │
 └── dataset/
      └── case_001/
           ├── scenario.json
           ├── metadata.json
           ├── ground_truth.json
           ├── raw_artifacts.json
           ├── ai_input.json
           ├── ai_result.json
           └── evaluation.json
```

---

## 🎯 MVP Scope

| Category | Details                                 |
| -------- | --------------------------------------- |
| Scenario | malware_execution, data_exfiltration    |
| Artifact | file, process, event logs               |
| AI Task  | Classification, Timeline Reconstruction |
| Metric   | Accuracy, Timeline LCS Score            |
| Input    | Template-based natural language         |

---

## 👥 Team

| Name | Role                        | Output                            |
| ---- | --------------------------- | --------------------------------- |
| 정민   | AI / Evaluation / Pipeline  | ai_result.json, evaluation.json   |
| 수아   | Scenario / Ground Truth     | scenario.json, ground_truth.json  |
| 지원   | Artifact / Dataset / Prompt | raw_artifacts.json, ai_input.json |

---

## 🔑 Keywords

`Digital Forensics` · `AI` · `Security` · `Ground Truth` · `Benchmark`

---

## 📌 Vision

> **“AI가 포렌식을 얼마나 ‘정확하게 이해하는가’를 측정한다”**

AI-ForensicBench는
단순 자동화 도구가 아니라,
**AI 포렌식 추론 능력을 검증하는 표준 벤치마크**를 목표로 합니다.
