import json
import os
import re
import shutil
import tempfile
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

load_dotenv()

from services.correlator import correlate_events
from services.llm import analyze_with_llm
from services.parser import parse_file

app = FastAPI(title="ForensicAI Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 결과 저장 루트 경로
_BASE_DIR      = os.path.dirname(__file__)
_SCENARIOS_DIR = os.path.join(_BASE_DIR, "..", "scenarios")
_OUTPUTS_DIR   = os.path.join(_BASE_DIR, "..", "outputs")   # 시나리오 특정 안 될 때 fallback


def _resolve_output_dir(filename: str) -> str:
    """
    파일명에서 시나리오 번호 추출 → scenarios/scenarioN/outputs/ 반환.
    매칭 실패 시 outputs/ (프로젝트 루트 하위) 반환.
    """
    m = re.search(r'(\d+)', filename)
    if m:
        sc_dir = os.path.join(_SCENARIOS_DIR, f"scenario{m.group(1)}", "outputs")
        if os.path.isdir(sc_dir):
            return sc_dir
    os.makedirs(_OUTPUTS_DIR, exist_ok=True)
    return _OUTPUTS_DIR


def _save_result(result: dict, filename: str, mode: str):
    """
    분석 결과를 JSON + 텍스트 보고서로 저장.
    저장 경로: scenarios/scenarioN/outputs/
    """
    out_dir   = _resolve_output_dir(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"llm_output_{mode}_{timestamp}"

    # 1) JSON 전체 저장
    json_path = os.path.join(out_dir, f"{base_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # 2) 텍스트 보고서 저장
    report_path = os.path.join(out_dir, f"{base_name}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        ar = result.get("analyst_report", {})
        tl = result.get("attack_timeline", [])

        f.write("=" * 60 + "\n")
        f.write("AI-ForensicBench  ANALYST REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Case ID  : {ar.get('caseId', '')}\n")
        f.write(f"Date     : {ar.get('date', '')}\n")
        f.write(f"Analyst  : {ar.get('analyst', '')}\n")
        f.write(f"Severity : {ar.get('severity', '')}\n")
        f.write(f"Mode     : {mode}\n\n")

        f.write("[ Summary ]\n")
        f.write(ar.get("summary", "") + "\n\n")

        f.write("[ Kill Chain ]\n")
        f.write(" → ".join(ar.get("killChain", [])) + "\n\n")

        f.write("[ Attack Timeline ]\n")
        for s in tl:
            f.write(f"  {s.get('id', '')}. [{s.get('stage', '')}] "
                    f"{s.get('timestamp', '')}  severity={s.get('severity', '')}\n")
            f.write(f"     {s.get('description', '')}\n")
        f.write("\n")

        f.write("[ IOCs ]\n")
        for ioc in ar.get("iocs", []):
            f.write(f"  {ioc.get('type', '')} : {ioc.get('value', '')}  "
                    f"risk={ioc.get('risk', '')}\n")
        f.write("\n")

        f.write("[ Recommendations ]\n")
        for r in ar.get("recommendations", []):
            f.write(f"  - {r}\n")
        f.write("\n")

        # dev 모드일 때만 메트릭 추가
        if mode == "dev" and "metrics" in result:
            mt = result["metrics"]
            f.write("[ Evaluation Metrics ]\n")
            f.write(f"  Stage Accuracy      : {mt.get('stageAccuracy')}%\n")
            f.write(f"  Sequence Similarity : {mt.get('sequenceSimilarity')}\n")
            f.write(f"  Missing stages      : {mt.get('missing_stages', [])}\n")
            f.write(f"  Unsupported stages  : {mt.get('unsupported_stages', [])}\n")
            f.write("\n")
            f.write("[ GT Sequence ]\n")
            f.write(" → ".join(result.get("ground_truth", [])) + "\n\n")
            f.write("[ LLM Sequence ]\n")
            f.write(" → ".join(result.get("llm_predicted", [])) + "\n")

    return json_path, report_path


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    mode: str = Form("real"),
):
    suffix = os.path.splitext(file.filename or "upload")[1] or ".log"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        events      = parse_file(tmp_path, file.filename or "upload")
        high_signal = correlate_events(events)

        if not high_signal:
            raise HTTPException(
                status_code=422,
                detail="No suspicious events found in the uploaded file.",
            )

        result = await analyze_with_llm(high_signal, file.filename or "upload", mode)

        # 결과 저장
        json_path, report_path = _save_result(result, file.filename or "upload", mode)
        result["saved_json"]   = json_path
        result["saved_report"] = report_path

        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        os.unlink(tmp_path)


@app.get("/report")
def download_report(path: str):
    """
    저장된 보고서 파일 다운로드.
    사용: GET /report?path=<saved_report 경로>
    """
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(path, media_type="text/plain", filename=os.path.basename(path))
