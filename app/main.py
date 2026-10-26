import csv
import io
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Literal, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, Request
from fastapi.responses import FileResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.auth import clerk_domain, current_user, publishable_key
from app.database import Analysis, get_db, initialize_database, serialize
from app.engine import ENGINE_VERSION, RULES, classify
from app.schemas import AnalysisResult, EmailInput
from app.ml import load_model, model_metadata

STATIC = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app):
    load_model()
    initialize_database()
    yield


app = FastAPI(title="SpamSentry-ML · Email Intelligence", version="2.0.0", lifespan=lifespan,
              description="Supervised TF-IDF and logistic regression email classification with supplemental security checks.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "landing.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    # The static shell contains no user data. Its initialization requires Clerk;
    # every data endpoint independently verifies a signed session token.
    return FileResponse(STATIC / "index.html")


@app.get("/auth/login", include_in_schema=False)
@app.get("/auth/register", include_in_schema=False)
@app.get("/auth/login/{path:path}", include_in_schema=False)
@app.get("/auth/register/{path:path}", include_in_schema=False)
def authentication_page():
    return FileResponse(STATIC / "auth.html")


@app.get("/sign-in", include_in_schema=False)
def sign_in_alias():
    return RedirectResponse("/auth/login")


@app.get("/sign-up", include_in_schema=False)
def sign_up_alias():
    return RedirectResponse("/auth/register")


@app.middleware("http")
async def privacy_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/") or request.url.path in ("/dashboard", "/auth/login", "/auth/register"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/auth/config")
def auth_config():
    try:
        domain = clerk_domain()
    except (ValueError, UnicodeError):
        return {"configured": False, "publishable_key": "", "domain": ""}
    return {"configured": True, "publishable_key": publishable_key(), "domain": domain}


@app.get("/api/me")
def me(user_id: str = Depends(current_user)):
    return {"user_id": user_id}


@app.get("/api/health")
def health():
    load_model()
    return {"status": "ok", "engine": ENGINE_VERSION, "method": "TF-IDF + logistic regression + security policy"}


@app.post("/api/analyze", response_model=AnalysisResult, status_code=201)
def analyze(email: EmailInput, db: Session = Depends(get_db), user_id: str = Depends(current_user)):
    started = time.perf_counter()
    result = classify(email)
    row = Analysis(id=str(uuid4()), user_id=user_id, **email.model_dump(), **result,
                   elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                   created_at=datetime.now(timezone.utc))
    db.add(row)
    db.commit()
    db.refresh(row)
    return serialize(row)


@app.post("/api/import", response_model=EmailInput)
async def import_email(file: UploadFile = File(...), user_id: str = Depends(current_user)):
    if not (file.filename or "").lower().endswith((".eml", ".txt")):
        raise HTTPException(400, "Choose an .eml or .txt file.")
    content = await file.read(100001)
    await file.close()
    if len(content) > 100000:
        raise HTTPException(413, "Files must be smaller than 100 KB.")
    if (file.filename or "").lower().endswith(".txt"):
        values = {"sender": "", "subject": "", "body": content.decode("utf-8", errors="replace")}
    else:
        try:
            message = BytesParser(policy=policy.default).parsebytes(content)
            part = message.get_body(preferencelist=("plain",))
            body = part.get_content() if part else ""
            if not isinstance(body, str) or not body.strip():
                raise HTTPException(400, "This email has no plain-text body. Paste its readable content instead.")
            values = {"sender": str(message.get("From", "")), "subject": str(message.get("Subject", "")), "body": body}
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "Could not read this email file. Paste its content instead.")
    try:
        return EmailInput(**values)
    except ValueError:
        raise HTTPException(400, "The email is empty or exceeds the field limits (50,000 characters for the body).")


@app.get("/api/analyses")
def history(q: str = Query(default="", max_length=200), verdict: Optional[Literal["safe", "suspicious", "spam"]] = None,
            limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db),
            user_id: str = Depends(current_user)):
    conditions = [Analysis.user_id == user_id]
    if q:
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conditions.append(or_(Analysis.subject.ilike(term, escape="\\"), Analysis.sender.ilike(term, escape="\\")))
    if verdict:
        conditions.append(Analysis.verdict == verdict)
    total = db.scalar(select(func.count()).select_from(Analysis).where(*conditions))
    rows = db.scalars(select(Analysis).where(*conditions).order_by(Analysis.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [serialize(row) for row in rows], "total": total}


@app.get("/api/analyses/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: str, db: Session = Depends(get_db), user_id: str = Depends(current_user)):
    row = db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == user_id))
    if not row:
        raise HTTPException(404, "Analysis not found.")
    return serialize(row)


@app.get("/api/stats")
def stats(db: Session = Depends(get_db), user_id: str = Depends(current_user)):
    counts = dict(db.execute(select(Analysis.verdict, func.count()).where(Analysis.user_id == user_id).group_by(Analysis.verdict)).all())
    average = db.scalar(select(func.avg(Analysis.elapsed_ms)).where(Analysis.user_id == user_id))
    return {"total": sum(counts.values()), "safe": counts.get("safe", 0), "suspicious": counts.get("suspicious", 0),
            "spam": counts.get("spam", 0), "average_ms": round(average, 2) if average is not None else None,
            "rule_count": len(RULES)}


@app.get("/api/rules")
def rules(user_id: str = Depends(current_user)):
    return {"version": ENGINE_VERSION, "method": "Trained TF-IDF + logistic regression with supplemental security checks", "rules": [{key: value for key, value in rule.items() if key != "patterns"} for rule in RULES],
            "thresholds": {"safe": "0–19", "suspicious": "20–49", "spam": "50–100"},
            "aggregation": "max(round(100 * model probability), capped sum of security points)",
            "limitations": "Final risk scores include security policy points and are not calibrated probabilities. This engine does not authenticate senders, visit URLs, scan attachments, or verify factual claims."}


@app.get("/api/model")
def model_info(user_id: str = Depends(current_user)):
    # Do not send thousands of split hashes to the UI; they remain in the report.
    return {key: value for key, value in model_metadata().items() if key != "split_body_hashes"}


@app.get("/api/export")
def export(db: Session = Depends(get_db), user_id: str = Depends(current_user)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Sender", "Subject", "Verdict", "Risk score", "Created at"])
    for row in db.scalars(select(Analysis).where(Analysis.user_id == user_id).order_by(Analysis.created_at.desc())).yield_per(200):
        # Neutralize spreadsheet formula injection in user-supplied text.
        safe = lambda value: "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        writer.writerow([row.id, safe(row.sender), safe(row.subject), row.verdict, row.score, serialize(row)["created_at"]])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="postmark-history.csv"'})
