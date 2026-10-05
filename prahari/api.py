"""Local single-user workspace with persistent analysis history."""

from contextlib import asynccontextmanager
import secrets
from fastapi import Header
from pathlib import Path
from typing import Literal
from fastapi import Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .storage import Store
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from .detectors.models import Models
from .engine import Engine
from .schemas import ScanInput, ScanResult, EnforcementEvent
from .config import Settings
from starlette.middleware.trustedhost import TrustedHostMiddleware


class BodyLimit:
    def __init__(self, app, limit=65536):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > self.limit:
                return await JSONResponse(
                    {"detail": "Request body exceeds 64 KiB."}, status_code=413
                )(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            return (
                chunks.pop(0)
                if chunks
                else {"type": "http.request", "body": b"", "more_body": False}
            )

        await self.app(scope, replay, send)


def create_app(models=None, db_path=None, settings=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings.from_env()
        config = app.state.settings
        app.state.engine = Engine(
            models or Models(config.model_directory),
            demo_strict=config.policy == "demo-strict",
            review_threshold=config.review_threshold,
        )
        app.state.store = Store(db_path or config.db_path)
        yield

    app = FastAPI(
        title="Prahari",
        version="0.3.0",
        description="Unified experimental web threat analysis. Local development API; decisions are advisory.",
        lifespan=lifespan,
    )
    app.add_middleware(BodyLimit)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default error body may echo input containing secrets.
        return JSONResponse(
            status_code=422,
            content={
                "detail": [
                    {"location": list(e["loc"]), "message": e["msg"], "type": e["type"]}
                    for e in exc.errors()
                ]
            },
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.3.0", "mode": "local-advisory"}

    @app.get("/api/v1/config")
    def config():
        value = app.state.settings
        return {
            "policy": value.policy,
            "review_threshold": value.review_threshold,
            "max_content_characters": 10000,
            "max_body_bytes": 65536,
            "stores_original_input": False,
            "model_scores_calibrated": False,
        }

    @app.get("/ready")
    def ready():
        errors = app.state.engine.models.errors
        return JSONResponse(
            status_code=503 if errors else 200,
            content={
                "ready": not bool(errors),
                "detectors": errors or {"request": "loaded", "phishing": "loaded"},
            },
        )

    @app.post("/api/v1/scans", response_model=ScanResult)
    def scan(data: ScanInput):
        try:
            result = app.state.engine.scan(data)
            app.state.store.save(result, data.input_type)
            return result
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.post("/api/v1/enforcement-events")
    def event(data: EnforcementEvent, x_prahari_key: str = Header(default="")):
        key = app.state.settings.integration_key
        if not key or not secrets.compare_digest(key, x_prahari_key):
            raise HTTPException(401, "Integration authentication required")
        scan = app.state.store.get(data.scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        expected = (
            "allowed"
            if data.mode == "monitor"
            else {"Allow": "allowed", "Review": "held", "Block": "blocked"}[
                scan["decision"]
            ]
        )
        if data.action != expected:
            raise HTTPException(422, "Action does not match decision and mode")
        try:
            app.state.store.event(data)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        return {"recorded": True}

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(static / "index.html")

    @app.get("/api/v1/scans")
    def history(
        decision: Literal["Allow", "Review", "Block"] | None = None,
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        return app.state.store.list(decision, limit, offset)

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanResult)
    def detail(scan_id: str):
        result = app.state.store.get(scan_id)
        if result is None:
            raise HTTPException(404, "Scan not found")
        return result

    @app.get("/api/v1/dashboard/summary")
    def summary():
        return app.state.store.summary()

    return app


app = create_app()
