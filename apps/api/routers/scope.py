"""Scope parsing and pre-flight validation endpoint (Spec 12)."""

import json
from email.parser import BytesParser
from email.policy import default
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from apps.api.models import ScopeParseRequest, ScopeParseResponse
from apps.api.routers.assessments import verify_api_key
from core.scope.validator import MAX_SCOPE_BYTES, ScopeValidator

router = APIRouter(
    prefix="/api/v1/scope",
    tags=["scope"],
    dependencies=[Depends(verify_api_key)],
)


@router.post("/parse", response_model=ScopeParseResponse)
async def parse_scope_endpoint(request: Request) -> JSONResponse:
    """Parses arbitrary scope content (YAML, JSON, Markdown, prose) without launching an assessment.

    Returns:
    - 200 OK: Valid scope with canonical SHA-256 hash and read-back summary.
    - 413 Payload Too Large: Content exceeds 1MB limit.
    - 422 Unprocessable Content: Semantically invalid, ambiguous, or unparseable scope.
    """
    body = await request.body()
    if len(body) > MAX_SCOPE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Scope payload size ({len(body)} bytes) exceeds 1MB limit.",
        )

    content_type = request.headers.get("content-type", "").lower()
    raw_content: str | bytes = ""
    target_filename: str | None = None

    if "application/json" in content_type:
        try:
            data = json.loads(body.decode("utf-8"))
            req = ScopeParseRequest.model_validate(data)
            raw_content = req.file_content or ""
            target_filename = req.filename
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Malformed JSON request body: {exc}",
            ) from exc
    elif "multipart/form-data" in content_type:
        try:
            msg = BytesParser(policy=default).parsebytes(
                b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body
            )
            for part in msg.iter_parts():
                cd = str(part.get("Content-Disposition", ""))
                if "filename=" in cd:
                    target_filename = part.get_filename()
                    raw_content = part.get_payload(decode=True) or b""
                    break
                elif 'name="file_content"' in cd or 'name="content"' in cd:
                    raw_content = part.get_payload(decode=True) or b""
                    break
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to parse multipart upload: {exc}",
            ) from exc
    else:
        raw_content = body.decode("utf-8", errors="replace")

    result = ScopeValidator.parse_input(raw_content, filename=target_filename)
    payload = result.model_dump(mode="json")

    if not result.is_valid:
        return JSONResponse(content=payload, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    return JSONResponse(content=payload, status_code=status.HTTP_200_OK)
