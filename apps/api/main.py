"""FastAPI application entrypoint for ARGUS.

Serves the assessment API, the SSE telemetry stream, generated reports, and a
dependency-free judge dashboard from the same origin.
"""

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from apps.api.database import Database
from apps.api.routers.assessments import router as assessments_router
from apps.api.routers.scope import router as scope_router
from apps.api.runner import AssessmentRunner
from core.config import get_settings

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    *,
    database_path: Path | str | None = None,
    artifacts_dir: Path | str | None = None,
    simulation_default: bool | None = None,
    model_gateway: Any = None,
    tool_executor: Any = None,
) -> FastAPI:
    """Builds the API with optional test injection for the gateway and executor."""
    settings = get_settings()
    db = Database(database_path or settings.DB_PATH)
    simulation = simulation_default if simulation_default is not None else settings.SIMULATION_MODE
    artifacts = Path(artifacts_dir or settings.ARTIFACTS_DIR)

    app = FastAPI(
        title="ARGUS Autonomous Security Testing API",
        version="0.1.0",
        description=(
            "Authorized, evidence-backed autonomous penetration testing. "
            "Every confirmed finding carries cryptographic proof."
        ),
    )
    app.state.db = db
    app.state.settings = settings
    app.state.artifacts_dir = artifacts
    app.state.simulation_default = simulation
    app.state.runner = AssessmentRunner(
        db,
        artifacts,
        simulation_default=simulation,
        model_gateway=model_gateway,
        tool_executor=tool_executor,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.CORS_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Last-Event-ID", "Authorization", "X-API-Key"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'",
        )
        return response

    app.include_router(assessments_router)
    app.include_router(scope_router)

    @app.get("/healthz", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "argus-api"}

    @app.post("/api/v1/proof/verify", tags=["proof"])
    async def verify_proof_upload(request: Request) -> JSONResponse:
        """Verifies an uploaded .argusproof Proof Capsule archive (Spec 11)."""
        import tempfile
        from core.evidence.proof_capsule import verify_capsule_archive

        body = await request.body()
        if not body:
            return JSONResponse({"verdict": "FAILED", "reasons": ["Empty request body"]}, status_code=400)

        with tempfile.NamedTemporaryFile(suffix=".argusproof", delete=False) as tmp:
            tmp.write(body)
            tmp_path = Path(tmp.name)

        try:
            result = verify_capsule_archive(tmp_path)
            return JSONResponse(result)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    @app.get("/", include_in_schema=False)
    def dashboard() -> Any:
        index = STATIC_DIR / "index.html"
        if not index.exists():
            return JSONResponse(
                {"service": "argus-api", "dashboard": "not installed"}, status_code=200
            )
        return FileResponse(index, media_type="text/html")

    return app


app = create_app()
