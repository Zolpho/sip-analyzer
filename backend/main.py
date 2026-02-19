from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from typing import Optional
import json
from models import AnalyzeRequest, AnalyzeResponse
from analyzer import analyze
from exporter import to_csv, to_pdf

app = FastAPI(title="SIP Analyzer API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_route(req: AnalyzeRequest):
    try: return analyze(req)
    except Exception as e: raise HTTPException(500, detail=str(e))

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...),
    caller: Optional[str] = Form(None), callee: Optional[str] = Form(None),
    caller_imsi: Optional[str] = Form(None), callee_imsi: Optional[str] = Form(None),
    flags: Optional[str] = Form("[]")):
    try:
        log_text = (await file.read()).decode("utf-8", errors="replace")
        req = AnalyzeRequest(caller=caller, callee=callee, caller_imsi=caller_imsi,
                             callee_imsi=callee_imsi, log=log_text, flags=json.loads(flags))
        return analyze(req)
    except Exception as e: raise HTTPException(500, detail=str(e))

@app.post("/export/csv")
async def export_csv(req: AnalyzeRequest):
    try:
        return Response(content=to_csv(analyze(req)), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=sip_analysis.csv"})
    except Exception as e: raise HTTPException(500, detail=str(e))

@app.post("/export/pdf")
async def export_pdf(req: AnalyzeRequest):
    try:
        return Response(content=to_pdf(analyze(req)), media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=sip_analysis.pdf"})
    except Exception as e: raise HTTPException(500, detail=str(e))

