"""Local single-user workspace with persistent analysis history."""
from contextlib import asynccontextmanager
import os
import secrets
from fastapi import Header
from pathlib import Path
from typing import Literal
from fastapi import Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .storage import Store
from .telemetry.service import Telemetry, TelemetryError
from .telemetry.schemas import TelemetryEvent, IncidentReview
from .security import Security
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from .detectors.models import Models
from .engine import Engine
from .schemas import ScanInput, ScanResult, EnforcementEvent, ReviewInput, PolicyInput

class BodyLimit:
    def __init__(self, app, limit=65536):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect': return
            total += len(message.get('body',b''))
            if total > self.limit:
                return await JSONResponse({'detail':'Request body exceeds 64 KiB.'}, status_code=413)(scope, receive, send)
            chunks.append(message)
            if not message.get('more_body',False): break
        async def replay():
            return chunks.pop(0) if chunks else {'type':'http.request','body':b'','more_body':False}
        await self.app(scope, replay, send)


def create_app(models=None, db_path=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.engine = Engine(models or Models(), demo_strict=os.getenv('PRAHARI_POLICY') == 'demo-strict')
        app.state.store = Store(db_path or os.getenv("PRAHARI_DB", str(Path(__file__).resolve().parents[1] / "data" / "prahari.db")))
        app.state.telemetry = Telemetry(app.state.store)
        selected=app.state.store.setting('policy')
        if selected:app.state.engine.demo_strict=selected=='protect'
        yield

    app = FastAPI(title='Prahari', version='2.0.0', description='Unified web threat analysis, session and network telemetry, and explainable incidents. Behaviour alerts are advisory.', lifespan=lifespan)
    app.add_middleware(BodyLimit)
    app.add_middleware(Security)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('PRAHARI_ALLOWED_HOSTS','127.0.0.1,localhost,testserver').split(','))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default error body may echo input containing secrets.
        return JSONResponse(status_code=422, content={'detail':[{'location':list(e['loc']), 'message':e['msg'], 'type':e['type']} for e in exc.errors()]})

    @app.get('/health')
    def health(): return {'status':'ok','version':'2.0.0','mode':'local-advisory'}

    @app.get('/ready')
    def ready():
        errors = app.state.engine.models.errors
        return JSONResponse(status_code=503 if errors else 200, content={'ready':not bool(errors),'detectors':errors or {'request':'loaded','phishing':'loaded'}})

    @app.post('/api/v1/scans', response_model=ScanResult)
    def scan(data: ScanInput):
        try:
            result = app.state.engine.scan(data)
            app.state.store.save(result, data.input_type)
            return result
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.post('/api/v1/enforcement-events')
    def event(data: EnforcementEvent, x_prahari_key: str = Header(default='')):
        key = os.getenv('PRAHARI_INTEGRATION_KEY', '')
        if not key or not secrets.compare_digest(key, x_prahari_key):
            raise HTTPException(401, 'Integration authentication required')
        scan = app.state.store.get(data.scan_id)
        if scan is None: raise HTTPException(404, 'Scan not found')
        expected = 'allowed' if data.mode == 'monitor' else {'Allow':'allowed','Review':'held','Block':'blocked'}[scan['decision']]
        if data.action != expected: raise HTTPException(422, 'Action does not match decision and mode')
        try: app.state.store.event(data)
        except ValueError as error: raise HTTPException(409, str(error)) from error
        return {'recorded':True}

    static = Path(__file__).parent / 'static' 
    app.mount('/static', StaticFiles(directory=static), name='static')

    @app.get('/', include_in_schema=False)
    def home(): return FileResponse(static / 'index.html')

    @app.get('/api/v1/scans')
    def history(decision: Literal['Allow','Review','Block'] | None = None, limit: int = Query(20,ge=1,le=100), offset: int = Query(0,ge=0), q: str = Query('',max_length=64)):
        return app.state.store.list(decision,limit,offset,q)

    @app.get('/api/v1/scans/{scan_id}', response_model=ScanResult)
    def detail(scan_id: str):
        result = app.state.store.get(scan_id)
        if result is None: raise HTTPException(404,'Scan not found')
        return result

    @app.get('/api/v1/dashboard/summary')
    def summary(): return app.state.store.summary()

    @app.get('/api/v1/policy')
    def policy(): return {'mode':'protect' if app.state.engine.demo_strict else 'review-first','ml_blocking':False}

    @app.put('/api/v1/policy')
    def update_policy(data: PolicyInput):
        app.state.store.set_setting('policy',data.mode)
        app.state.engine.demo_strict=data.mode=='protect'
        return policy()

    @app.post('/api/v1/scans/{scan_id}/review')
    def review(scan_id: str,data: ReviewInput):
        if app.state.store.get(scan_id) is None:raise HTTPException(404,'Scan not found')
        app.state.store.review(scan_id,data.verdict)
        return {'recorded':True,'note':'Analyst label recorded; no automatic retraining or replay.'}

    @app.exception_handler(TelemetryError)
    async def telemetry_error(request, exc):
        return JSONResponse(status_code=exc.status, content={'detail':exc.message})

    @app.post('/api/v1/telemetry')
    def telemetry(data: TelemetryEvent, x_prahari_key: str = Header(default='')):
        key=os.getenv('PRAHARI_INTEGRATION_KEY','')
        if not key or not secrets.compare_digest(key,x_prahari_key):
            raise HTTPException(401,'Integration authentication required')
        return app.state.telemetry.ingest(data)

    @app.get('/api/v1/telemetry/summary')
    def telemetry_summary():return app.state.telemetry.summary()

    @app.get('/api/v1/incidents')
    def incidents(status: Literal['open','investigating','resolved','false_positive'] | None = None,
                  mode: Literal['live','replay'] | None = None,
                  limit: int = Query(20,ge=1,le=100),offset: int = Query(0,ge=0)):
        return app.state.telemetry.incidents(status,mode,limit,offset)

    @app.get('/api/v1/incidents/{incident_id}')
    def incident(incident_id: str):return app.state.telemetry.detail(incident_id)

    @app.patch('/api/v1/incidents/{incident_id}')
    def incident_review(incident_id: str,data: IncidentReview):
        return app.state.telemetry.review(incident_id,data.status)

    return app

app = create_app()
