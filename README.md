# AI-ForensicBench

> 포렌식 사건 시나리오를 자동 실행하고, Ground Truth와 시스템 아티팩트를 병렬 기록하여 AI 모델의 포렌식 추론 능력을 평가하는 벤치마크 프레임워크

---

## 프로젝트 개요

기존 디지털 포렌식 AI 연구는 **정확한 Ground Truth 데이터 부족** 문제로 인해 AI 모델의 성능을 객관적으로 평가하기 어려웠습니다.

AI-ForensicBench는 가상 환경에서 포렌식 사건 시나리오를 직접 실행하고, 실행과 동시에 Ground Truth를 자동 기록함으로써 **라벨 노이즈 없는 포렌식 AI 벤치마크 데이터셋**을 생성합니다.

### 핵심 차별점

- **Ground Truth 자동 기록** — 시나리오 실행과 동시에 정답 데이터 생성, 라벨 노이즈 없음
- **AI Forensic Reasoning Benchmark** — 사건 유형 분류 + 타임라인 재구성 태스크 평가
- **듀얼 기록 구조** — 실제 행동(Ground Truth)과 시스템 흔적(Artifact)을 분리 저장

---

## 시스템 아키텍처

```
[Scenario Executor]
    ├──────────────────────────────┐
    ▼                              ▼
[Ground Truth Recorder]    [Artifact Collector]
    ↓                              ↓
ground_truth.json          raw_artifacts.json
    └──────────────┬───────────────┘
                   ▼
          [Dataset Builder]
                   ↓
             case_xxx/
                   ↓
          [Prompt Builder]
                   ↓
            ai_input.json
                   ↓
           [AI Analyzer]
                   ↓
            ai_result.json
                   ↓
       [Benchmark Evaluator]
                   ↓
           evaluation.json
                   ↓
        [Result Dashboard]
```

---

## 파일 구조

```
AI-ForensicBench/
 ├── label_schema.json         # 공통 라벨 체계
 ├── run_pipeline.py           # 전체 파이프라인 실행
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
           ├── scenario.json        # 무엇을 실행했는가
           ├── metadata.json        # 어떤 환경/설정으로 실행했는가
           ├── ground_truth.json    # 실제로 어떤 행동이 일어났는가
           ├── raw_artifacts.json   # 시스템에 어떤 흔적이 남았는가
           ├── ai_input.json        # AI에게 무엇을 입력했는가
           ├── ai_result.json       # AI가 무엇이라고 판단했는가
           └── evaluation.json      # AI가 얼마나 맞았는가
```

---

## MVP 범위

| 항목 | 내용 |
|------|------|
| 시나리오 | `malware_execution`, `data_exfiltration` |
| Artifact | file events, process events, event logs |
| AI Task | 사건 유형 분류, 타임라인 재구성 |
| 평가 지표 | Classification Accuracy, Timeline LCS Score |
| AI 입력 방식 | 템플릿 기반 자연어 요약 |

---

## 팀원 및 역할

| 이름 | 담당 모듈 | 산출물 |
|------|-----------|--------|
| 정민 | AI Analyzer, Benchmark Evaluator, 파이프라인 총괄 | `ai_result.json`, `evaluation.json`, `run_pipeline.py`, `label_schema.json` |
| 수아 | Scenario Executor, Ground Truth Recorder | `scenario.json`, `ground_truth.json` |
| 지원 | Artifact Collector, Dataset Builder, Prompt Builder | `raw_artifacts.json`, `ai_input.json`, `metadata.json` |

---

## 키워드

`Digital Forensics` `AI` `Security` `Ground Truth` `Benchmark`
