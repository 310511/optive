"""FastAPI application factory — includes web UI at /."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from tprm.api.routes import router
from tprm.common.config import get_settings
from tprm.common.errors import (
    GateViolation,
    PayloadViolation,
    SignatureError,
    TPRMError,
    UnsupportedFormat,
)
from tprm.common.logging import configure_logging, get_logger

log = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent / "ui" / "templates"
_STATIC_DIR    = Path(__file__).parent.parent / "ui" / "static"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)

    app = FastAPI(
        title="TPRM Privacy-Preserving Pipeline",
        description="Vendor risk assessment with Security Gate privacy guarantees.",
        version="0.1.0",
    )

    # ── Serve static files (CSS/JS assets if any) ─────────────────────────
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Serve the UI at root ───────────────────────────────────────────────
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def ui_root() -> HTMLResponse:
        html = (_TEMPLATES_DIR / "index.html").read_text()
        return HTMLResponse(html)

    # ── API routes ─────────────────────────────────────────────────────────
    app.include_router(router, prefix="/api/v1")

    # ── Exception handlers ─────────────────────────────────────────────────
    @app.exception_handler(UnsupportedFormat)
    async def unsupported_format_handler(req: Request, exc: UnsupportedFormat) -> JSONResponse:
        return JSONResponse(status_code=415, content={"error": str(exc)})

    @app.exception_handler(GateViolation)
    async def gate_violation_handler(req: Request, exc: GateViolation) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "Gate violation — document quarantined"})

    @app.exception_handler(SignatureError)
    async def signature_error_handler(req: Request, exc: SignatureError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"error": "Signature verification failed"})

    @app.exception_handler(PayloadViolation)
    async def payload_violation_handler(req: Request, exc: PayloadViolation) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "Payload validation failed"})

    @app.exception_handler(TPRMError)
    async def tprm_error_handler(req: Request, exc: TPRMError) -> JSONResponse:
        log.error("tprm_error", error_type=type(exc).__name__)
        return JSONResponse(status_code=500, content={"error": "Internal pipeline error"})

    return app


app = create_app()
