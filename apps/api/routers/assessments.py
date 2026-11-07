"""Assessment lifecycle, SSE telemetry, cancellation, checkpoints, and report endpoints (Spec 06)."""

import asyncio
import hashlib
import json
import logging
import re
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from apps.api.database import TERMINAL_STATUSES
from apps.api.models import (
    AssessmentCreate,
    AssessmentDetail,
    AssessmentSummary,
    AssessmentTarget,
    StatusResponse,
)
from core.evidence.evidence_vault import EvidenceVault
from core.executor.process_runner import terminate_active_processes
from core.reporting.report_generator import ReportGenerator
from core.scope.validator import ScopeValidator
from engine.graph import create_initial_state
from integrations.langfuse import LangfuseTracer
from packages.contracts.findings import Finding
from packages.contracts.scope import compute_scope_hash, normalize_scope


def verify_api_key(request: Request) -> str:
    """Authenticates API requests against configured ARGUS_API_KEY (SEC-05)."""
    settings = getattr(request.app.state, "settings", None)
    configured_key = (getattr(settings, "API_KEY", "") or "").strip()
    if not configured_key:
        return "default_operator"

    auth_header = request.headers.get("authorization", "")
    token = ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    elif "x-api-key" in request.headers:
        token = request.headers["x-api-key"].strip()

    if not token or token != configured_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API authorization token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "operator"


_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")
HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


router = APIRouter(
    prefix="/api/v1/assessments",
    tags=["assessments"],
    dependencies=[Depends(verify_api_key)],
)


def _summary(record: dict[str, Any], request: Request) -> AssessmentDetail:
    state = record.get("state") or {}
    assessment_id = record["id"]
    report_md = record.get("report_path_md")
    report_pdf = record.get("report_path_pdf")
    base = str(request.base_url).rstrip("/")

    target_data = record.get("target") or {}
    if isinstance(target_data, str):
        target = AssessmentTarget(
            type="web" if target_data.startswith(("http://", "https://")) else "network",
            value=target_data,
        )
    elif isinstance(target_data, dict):
        target = AssessmentTarget(
            type=target_data.get("type", "web"),
            value=target_data.get("value") or str(target_data),
        )
    else:
        target = AssessmentTarget(type="web", value=str(target_data))

    objective_data = record.get("objective") or "discover_services"

    findings = state.get("findings", [])
    if not findings:
        db = getattr(request.app.state, "db", None)
        if db:
            findings = db.get_findings(assessment_id) or []
    total_findings = len(findings)

    return AssessmentDetail(
        id=assessment_id,
        name=record.get("name") or f"Assessment-{target.value}",
        status=record["status"],
        outcome=record.get("outcome"),
        target=target,
        objective=objective_data,
        simulation=record["simulation"],
        summary=record.get("summary"),
        error=record.get("error"),
        created_at=record["created_at"],
        updated_at=record.get("updated_at"),
        completed_at=record.get("completed_at"),
        report_url=(
            f"{base}/api/v1/assessments/{assessment_id}/report?format=md" if report_md else None
        ),
        report_pdf_url=(
            f"{base}/api/v1/assessments/{assessment_id}/report/pdf" if report_pdf else None
        ),
        discovered_assets=state.get("discovered_assets", []),
        discovered_services=state.get("discovered_services", []),
        total_findings=total_findings,
        findings=findings,
        evidence_refs=state.get("evidence_refs", []),
        blocked_actions=state.get("blocked_actions", []),
        telemetry=state.get("telemetry", []),
        budget=state.get("budget", {}),
        is_terminal=record["status"] in TERMINAL_STATUSES,
        assessment_id=assessment_id,
        langfuse_trace_id=record.get("langfuse_trace_id"),
        langfuse_session_id=record.get("langfuse_session_id"),
        langfuse_configured=LangfuseTracer().is_enabled,
    )


def _parse_scope(payload: AssessmentCreate) -> tuple[Any, str]:
    scope_input = (
        payload.scope_yaml
        if payload.scope_yaml is not None
        else (payload.scope if payload.scope is not None else payload.scope_document)
    )
    if scope_input is None:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Scope document is required.",
        )

    try:
        if isinstance(scope_input, str):
            scope_raw = scope_input
            scope = ScopeValidator.parse_yaml_string(scope_raw)
        else:
            scope = normalize_scope(scope_input)
            scope_raw = yaml.safe_dump(scope.model_dump(mode="json"), sort_keys=True)
    except (ValueError, TypeError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=HTTP_422,
            detail=f"Invalid scope document: {exc}",
        ) from exc

    valid, reason = ScopeValidator.validate_scope_document(scope)
    if not valid:
        # Check if expired or schema violation
        is_expired = "expired" in str(reason).lower()
        status_code = status.HTTP_400_BAD_REQUEST if is_expired else HTTP_422
        raise HTTPException(
            status_code=status_code,
            detail=f"Scope rejected: {reason}",
        )

    calculated_hash = compute_scope_hash(scope)
    if payload.imported_scope_hash and payload.imported_scope_hash != calculated_hash:
        raise HTTPException(
            status_code=HTTP_422,
            detail=(
                f"Scope hash mismatch: imported_scope_hash '{payload.imported_scope_hash}' "
                f"does not match calculated '{calculated_hash}'."
            ),
        )

    return scope, scope_raw


@router.post("", status_code=status.HTTP_201_CREATED, response_model=AssessmentDetail)
def create_assessment(payload: AssessmentCreate, request: Request) -> AssessmentDetail:
    """Create assessment & validate scope (Spec 06 / Spec 12). Stages as READY or auto-launches."""
    app = request.app
    settings = app.state.settings
    simulation = (
        payload.simulation if payload.simulation is not None else app.state.simulation_default
    )
    if not simulation and not settings.BIFROST_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Live assessments require ARGUS_BIFROST_API_KEY. "
                "Set simulation=true for a clearly-labelled offline demo."
            ),
        )

    scope, scope_raw = _parse_scope(payload)
    assessment_id = f"asm-{uuid4().hex[:12]}"
    scope_hash = compute_scope_hash(scope)

    if isinstance(payload.target, AssessmentTarget):
        target = payload.target.model_dump(mode="json")
    else:
        target = {"type": "web", "value": str(payload.target)}

    database = app.state.db
    initial_status = "QUEUED" if payload.auto_start else "READY"
    obj_data = (
        payload.objective
        if isinstance(payload.objective, (str, dict))
        else {"type": "discover_services"}
    )

    tracer = LangfuseTracer()
    lf_trace_id = None
    lf_session_id = None
    if tracer.is_enabled:
        lf_session_id = assessment_id
        try:
            lf_trace_id = tracer.client.create_trace_id()
        except Exception:
            lf_trace_id = None

    database.create(
        assessment_id,
        name=payload.name or f"Assessment-{target.get('value')}",
        status=initial_status,
        target=target,
        objective=obj_data,
        scope=scope.model_dump(mode="json"),
        scope_raw=scope_raw,
        simulation=simulation,
        max_iterations=payload.max_iterations,
        langfuse_trace_id=lf_trace_id,
        langfuse_session_id=lf_session_id,
    )
    database.append_event(
        assessment_id,
        "assessment_created",
        data={
            "target": target,
            "objective": obj_data,
            "simulation": simulation,
            "max_iterations": payload.max_iterations,
            "status": initial_status,
            "scope_hash": scope_hash,
        },
    )

    # Spec 12 Pre-Flight Invariant: commit scope_confirmed audit event on auto_confirm or auto_start
    if payload.auto_confirm or payload.auto_start:
        confirmed_by = (
            "cli_flag_auto_confirm" if payload.auto_confirm else "auto_start_implicit"
        )
        database.append_event(
            assessment_id,
            "scope_confirmed",
            data={
                "confirmed_at": datetime.now(UTC).isoformat(),
                "confirmed_by": confirmed_by,
                "scope_hash": scope_hash,
                "auto_confirm": payload.auto_confirm,
            },
        )

    if payload.auto_start:
        app.state.runner.launch(
            assessment_id,
            scope=scope,
            scope_raw=scope_raw,
            target=target,
            objective=obj_data if isinstance(obj_data, dict) else {"type": str(obj_data)},
            simulation=simulation,
            max_iterations=payload.max_iterations,
        )

    record = database.get(assessment_id)
    assert record is not None
    return _summary(record, request)


@router.get("", response_model=list[AssessmentSummary])
def list_assessments(request: Request, limit: int = 20) -> list[AssessmentSummary]:
    """Return the most recent assessments for the dashboard."""
    records = request.app.state.db.list_recent(limit=max(1, min(limit, 100)))
    return [_summary(record, request) for record in records]


@router.get("/{assessment_id}", response_model=AssessmentDetail)
def get_assessment(assessment_id: str, request: Request) -> AssessmentDetail:
    """Fetch current assessment state and summary."""
    record = request.app.state.db.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return _summary(record, request)


@router.delete("/{assessment_id}", response_model=StatusResponse)
def delete_assessment(assessment_id: str, request: Request) -> StatusResponse:
    """Permanently delete an assessment, its evidence artifacts, and all related records."""
    if not _SAFE_ID_RE.match(assessment_id):
        raise HTTPException(status_code=400, detail="Invalid assessment_id")

    app = request.app
    database = app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Stop active work first so the worker cannot write after the hard delete.
    if record["status"] not in TERMINAL_STATUSES:
        database.request_cancel(assessment_id)
        terminate_active_processes(assessment_id)
        runner = getattr(app.state, "runner", None)
        if runner is not None:
            deadline = time.monotonic() + 5.0
            while runner.is_active(assessment_id) and time.monotonic() < deadline:
                time.sleep(0.05)
            if runner.is_active(assessment_id):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Assessment cancellation is still in progress. "
                        "Please retry deletion in a moment."
                    ),
                )

    artifacts_dir = Path(app.state.artifacts_dir).resolve()
    assessment_dir = (artifacts_dir / assessment_id).resolve()
    if not assessment_dir.is_relative_to(artifacts_dir):
        raise HTTPException(status_code=400, detail="Invalid assessment artifact path")

    if not database.delete_assessment(assessment_id):
        raise HTTPException(status_code=404, detail="Assessment not found")

    if assessment_dir.is_dir():
        shutil.rmtree(assessment_dir)

    return StatusResponse(status="DELETED")


@router.post("/{assessment_id}/confirm", response_model=StatusResponse)
def confirm_scope(
    assessment_id: str, request: Request, payload: dict[str, Any] | None = None
) -> StatusResponse:
    """Pre-flight operator authorization confirming the parsed scope (Spec 12)."""
    app = request.app
    database = app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    scope = normalize_scope(record["scope"])
    is_valid, reason = ScopeValidator.validate_scope_document(scope)
    if not valid:
        raise HTTPException(status_code=422, detail=f"Cannot confirm invalid scope: {reason}")

    scope_hash = compute_scope_hash(scope)
    operator = (payload or {}).get("confirmed_by") or "operator"
    database.append_event(
        assessment_id,
        "scope_confirmed",
        data={
            "confirmed_at": datetime.now(UTC).isoformat(),
            "confirmed_by": operator,
            "scope_hash": scope_hash,
        },
    )
    database.update_assessment(assessment_id, status="READY")
    return StatusResponse(status="READY")


@router.post("/{assessment_id}/start", response_model=StatusResponse)
def start_assessment(assessment_id: str, request: Request) -> StatusResponse:
    """Launch LangGraph agent runner from READY or QUEUED state (Spec 06)."""
    app = request.app
    database = app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    status_val = record["status"]
    if status_val == "RUNNING":
        return StatusResponse(status="RUNNING")
    if status_val in TERMINAL_STATUSES:
        raise HTTPException(status_code=400, detail="Cannot start a completed assessment")

    scope = normalize_scope(record["scope"])
    is_valid, reason = ScopeValidator.validate_scope_document(scope)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot start assessment: {reason}",
        )

    scope_hash = compute_scope_hash(scope)
    database.append_event(
        assessment_id,
        "scope_confirmed",
        data={
            "confirmed_at": datetime.now(UTC).isoformat(),
            "confirmed_by": "operator",
            "scope_hash": scope_hash,
        },
    )

    target = record["target"]
    objective = record["objective"]
    obj_dict = objective if isinstance(objective, dict) else {"type": str(objective)}

    database.update_assessment(assessment_id, status="RUNNING")
    app.state.runner.launch(
        assessment_id,
        scope=scope,
        scope_raw=record["scope_raw"],
        target=target,
        objective=obj_dict,
        simulation=record["simulation"],
        max_iterations=record["max_iterations"],
    )
    return StatusResponse(status="RUNNING")


@router.post("/{assessment_id}/pause", response_model=StatusResponse)
def pause_assessment(assessment_id: str, request: Request) -> StatusResponse:
    """Pause active execution cleanly at the next safe node boundary (Spec 06)."""
    database = request.app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if record["status"] == "PAUSED":
        return StatusResponse(status="PAUSED")
    if record["status"] in TERMINAL_STATUSES:
        raise HTTPException(status_code=400, detail="Cannot pause a finished assessment")

    database.request_pause(assessment_id)

    # Ensure a checkpoint is immediately available
    checkpoint = database.get_latest_checkpoint(assessment_id)
    if checkpoint is None:
        state = record.get("state")
        if not state:
            scope = normalize_scope(record["scope"])
            target = record["target"]
            objective = record["objective"]
            state = dict(
                create_initial_state(
                    assessment_id=assessment_id,
                    target=target,
                    objective=objective
                    if isinstance(objective, dict)
                    else {"type": str(objective)},
                    scope=scope,
                    scope_yaml_raw=record["scope_raw"],
                    max_iterations=record["max_iterations"],
                )
            )
        checkpoint_id = f"chk-{uuid4().hex[:12]}"
        checkpoint_blob = json.dumps(state, default=str).encode("utf-8")
        database.save_checkpoint(
            checkpoint_id=checkpoint_id,
            assessment_id=assessment_id,
            thread_id=f"thread-{assessment_id}",
            checkpoint_blob=checkpoint_blob,
        )
        database.update_assessment(
            assessment_id,
            status="PAUSED",
            state_json=json.dumps(state, default=str),
        )
        database.append_event(
            assessment_id,
            "assessment_paused",
            data={"checkpoint_id": checkpoint_id},
        )
    else:
        database.update_assessment(assessment_id, status="PAUSED")

    return StatusResponse(status="PAUSED")


@router.post("/{assessment_id}/resume", response_model=StatusResponse)
def resume_assessment(assessment_id: str, request: Request) -> StatusResponse:
    """Resume execution from latest saved checkpoint (Spec 06)."""
    app = request.app
    database = app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if record["status"] == "RUNNING":
        return StatusResponse(status="RUNNING")
    if record["status"] in TERMINAL_STATUSES:
        raise HTTPException(status_code=400, detail="Cannot resume a finished assessment")
    if record["status"] != "PAUSED":
        raise HTTPException(status_code=400, detail="Only paused assessments can be resumed")

    database.clear_pause(assessment_id)
    database.update_assessment(assessment_id, status="RUNNING")

    checkpoint = database.get_latest_checkpoint(assessment_id)
    checkpoint_state = None
    if checkpoint:
        try:
            checkpoint_state = json.loads(checkpoint["checkpoint_blob"].decode("utf-8"))
        except Exception:  # noqa: BLE001
            checkpoint_state = record.get("state")
    else:
        checkpoint_state = record.get("state")

    scope = normalize_scope(record["scope"])
    is_valid, reason = ScopeValidator.validate_scope_document(scope)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume assessment: {reason}",
        )

    # Verify scope hash consistency between checkpoint and current scope
    current_scope_raw = record.get("scope_raw", "")
    current_scope_hash = hashlib.sha256(current_scope_raw.encode("utf-8")).hexdigest()
    if isinstance(checkpoint_state, dict):
        saved_scope_hash = checkpoint_state.get("scope_snapshot_hash") or checkpoint_state.get("scope_hash")
        if saved_scope_hash and saved_scope_hash != current_scope_hash:
            raise HTTPException(
                status_code=400,
                detail="Scope hash mismatch: authorized scope was modified while assessment was paused.",
            )

    target = record["target"]
    objective = record["objective"]
    obj_dict = objective if isinstance(objective, dict) else {"type": str(objective)}

    database.append_event(
        assessment_id,
        "assessment_resumed",
        data={"checkpoint_id": checkpoint["id"] if checkpoint else None},
    )

    app.state.runner.launch(
        assessment_id,
        scope=scope,
        scope_raw=record["scope_raw"],
        target=target,
        objective=obj_dict,
        simulation=record["simulation"],
        max_iterations=record["max_iterations"],
        initial_state=checkpoint_state,
    )
    return StatusResponse(status="RUNNING")


@router.post("/{assessment_id}/cancel", response_model=StatusResponse)
def cancel_assessment(assessment_id: str, request: Request) -> StatusResponse:
    """Gracefully request cancellation at the next safe boundary."""
    database = request.app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if record["status"] in TERMINAL_STATUSES:
        return StatusResponse(status="CANCELLED")

    database.request_cancel(assessment_id)
    terminate_active_processes(assessment_id)
    database.append_event(
        assessment_id,
        "cancel_requested",
        data={"message": "Cancellation requested by user. Active tool processes terminated."},
    )
    return StatusResponse(status="CANCELLED")


@router.get("/{assessment_id}/events")
@router.get("/{assessment_id}/stream")
async def stream_assessment_events(assessment_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events stream of node transitions, findings, and telemetry."""
    database = request.app.state.db
    record = await run_in_threadpool(database.get, assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    try:
        last_event_id = int(request.headers.get("last-event-id", "0") or "0")
    except ValueError:
        last_event_id = 0
    # Browsers resend Last-Event-ID automatically, but an explicit query
    # parameter lets a fresh client (or a REST replay) resume from a cursor.
    query_cursor = request.query_params.get("last_event_id")
    if query_cursor:
        try:
            last_event_id = max(last_event_id, int(query_cursor))
        except ValueError:
            pass

    async def event_generator() -> Any:
        cursor = last_event_id
        idle_ticks = 0
        while True:
            events = await run_in_threadpool(database.events_after, assessment_id, cursor)
            for event in events:
                cursor = event["id"]
                event_data = event.get("data")
                payload_obj: dict[str, Any] = (
                    dict(event_data) if isinstance(event_data, dict) else {"value": event_data}
                )
                # Enrich every event with routing/telemetry metadata so the
                # dashboard can show the exact pipeline step and event time.
                payload_obj.setdefault("node", event["node"])
                payload_obj.setdefault("timestamp", event["created_at"])
                payload_obj.setdefault("event_id", event["id"])
                payload = json.dumps(payload_obj, default=str)
                yield f"id: {cursor}\nevent: {event['event_type']}\ndata: {payload}\n\n"
            current = await run_in_threadpool(database.get, assessment_id)
            if current is None:
                break
            if current["status"] in TERMINAL_STATUSES and not events:
                yield f"event: stream_closed\ndata: {json.dumps({'status': current['status'], 'is_terminal': True})}\n\n"
                break
            if await request.is_disconnected():
                break
            idle_ticks += 1
            if idle_ticks >= 10:
                idle_ticks = 0
                yield ": heartbeat\n\n"
            await asyncio.sleep(0.5)

    from typing import cast
    return StreamingResponse(
        cast(Any, event_generator()),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{assessment_id}/findings", response_model=list[Finding])
def get_assessment_findings(assessment_id: str, request: Request) -> list[Finding]:
    """List findings & evidence links (Spec 06)."""
    database = request.app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    raw_findings = database.get_findings(assessment_id)
    if not raw_findings:
        state = record.get("state") or {}
        raw_findings = state.get("findings", [])

    results: list[Finding] = []
    for f in raw_findings:
        try:
            results.append(Finding.model_validate(f))
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to validate finding model: %s", exc)
            continue
    return results


@router.get("/{assessment_id}/evidence/{evidence_id}")
def download_evidence(assessment_id: str, evidence_id: str, request: Request) -> PlainTextResponse:
    """Download raw artifact file securely (Spec 06)."""
    if not _SAFE_ID_RE.match(assessment_id) or not _SAFE_ID_RE.match(evidence_id):
        raise HTTPException(status_code=400, detail="Invalid assessment_id or evidence_id")

    database = request.app.state.db
    record = database.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    artifacts_dir = Path(request.app.state.artifacts_dir).resolve()
    vault = EvidenceVault(base_dir=artifacts_dir)
    try:
        content = vault.read_artifact_content(assessment_id, evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if content is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence artifact '{evidence_id}' not found for assessment '{assessment_id}'",
        )

    return PlainTextResponse(content, media_type="text/plain")


@router.get("/{assessment_id}/report")
def download_report(
    assessment_id: str,
    request: Request,
    format: str | None = Query(default=None),
) -> Any:
    """Retrieve Markdown report as JSON, file, HTML, or PDF (Spec 06)."""
    record = request.app.state.db.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    artifacts_dir = Path(request.app.state.artifacts_dir).resolve()

    def _safe(path_value: str | None) -> Path | None:
        if not path_value:
            return None
        candidate = Path(path_value).resolve()
        if not candidate.is_relative_to(artifacts_dir) or not candidate.exists():
            return None
        return candidate

    accept_header = request.headers.get("accept", "")
    report_format = (format or ("json" if "application/json" in accept_header else "md")).lower()

    if report_format == "json":
        md_text = record.get("report_markdown")
        if not md_text:
            path = _safe(record.get("report_path_md"))
            if path and path.exists():
                md_text = path.read_text(encoding="utf-8")
        if not md_text:
            raise HTTPException(status_code=404, detail="Markdown report not ready")
        return {"markdown": md_text}

    if report_format == "md":
        path = _safe(record.get("report_path_md"))
        if path is None:
            raise HTTPException(status_code=404, detail="Markdown report not ready")
        return FileResponse(path, media_type="text/markdown", filename=f"{assessment_id}-report.md")

    if report_format == "pdf":
        path = _safe(record.get("report_path_pdf"))
        if path is None:
            raise HTTPException(status_code=404, detail="PDF report not ready")
        return FileResponse(
            path, media_type="application/pdf", filename=f"{assessment_id}-report.pdf"
        )

    if report_format == "html":
        state = record.get("state") or {}
        if not state:
            raise HTTPException(status_code=404, detail="Assessment state not ready")
        html = ReportGenerator().generate_html_report(
            state,
            scope=normalize_scope(record["scope"]),
            evidence_vault=None,
            simulation_mode=record["simulation"],
        )
        return HTMLResponse(html)

    raise HTTPException(
        status_code=400, detail="Unsupported report format. Use json, md, pdf, or html."
    )


@router.get("/{assessment_id}/report/pdf")
def download_report_pdf(assessment_id: str, request: Request) -> FileResponse:
    """Download client-ready PDF directly (Spec 06)."""
    record = request.app.state.db.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    artifacts_dir = Path(request.app.state.artifacts_dir).resolve()
    path_value = record.get("report_path_pdf")
    if not path_value:
        raise HTTPException(status_code=404, detail="PDF report not ready")

    candidate = Path(path_value).resolve()
    if not candidate.is_relative_to(artifacts_dir) or not candidate.exists():
        raise HTTPException(status_code=404, detail="PDF report not ready on disk")

    return FileResponse(
        candidate, media_type="application/pdf", filename=f"{assessment_id}-report.pdf"
    )


@router.get("/{assessment_id}/proof")
def download_proof_capsule(
    assessment_id: str,
    request: Request,
    finding_id: str = "",
) -> FileResponse:
    """Generates and downloads a self-contained .argusproof Proof Capsule (Spec 11)."""
    record = request.app.state.db.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    artifacts_dir = Path(request.app.state.artifacts_dir).resolve()
    assessment_artifacts_dir = artifacts_dir / assessment_id

    # Find the finding
    findings = record.get("findings", [])
    target_finding = None
    if finding_id:
        for f in findings:
            if f.get("finding_id") == finding_id:
                target_finding = f
                break
        if target_finding is None:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    elif findings:
        target_finding = findings[0]
    else:
        raise HTTPException(status_code=404, detail="No findings available to generate proof for")

    # Load ledger
    from core.evidence.ledger import AssessmentLedger
    from core.evidence.proof_capsule import ProofCapsuleBuilder

    ledger_path = assessment_artifacts_dir / "ledger.jsonl"
    if not ledger_path.exists():
        raise HTTPException(status_code=404, detail="Ledger not found for this assessment")

    ledger = AssessmentLedger(ledger_path, assessment_id=assessment_id)
    head = ledger.head()
    records = ledger.records()

    # Collect proofs and artifacts for this finding
    proofs = []
    artifacts = []
    for ev_id in target_finding.get("evidence_ids", []):
        proof_obj = ledger.get_proof_for_evidence_id(ev_id)
        if proof_obj:
            proofs.append(
                {
                    "evidence_id": ev_id,
                    "leaf_index": proof_obj["leaf_index"],
                    "tree_size": proof_obj["tree_size"],
                    "audit_path": proof_obj["audit_path"],
                }
            )
        art_path = assessment_artifacts_dir / f"{ev_id}.raw"
        if art_path.exists():
            content = art_path.read_text(encoding="utf-8")
            sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            artifacts.append(
                {
                    "evidence_id": ev_id,
                    "content": content,
                    "sha256": f"sha256:{sha256}",
                }
            )

    fid = target_finding.get("finding_id", "F-001")
    capsule_filename = f"{assessment_id}-{fid}.argusproof"
    capsule_path = assessment_artifacts_dir / capsule_filename

    builder = ProofCapsuleBuilder(
        assessment_id=assessment_id,
        finding=target_finding,
        ledger_head=head,
        proofs=proofs,
        artifacts=artifacts,
        ledger_records=records,
        bifrost_telemetry=record.get("bifrost_telemetry"),
        research_citations=record.get("research_sources"),
        simulation=record.get("simulation_mode", False),
    )
    builder.write_capsule_zip(capsule_path)

    return FileResponse(
        capsule_path,
        media_type="application/zip",
        filename=capsule_filename,
    )
