"""Optional bearer authentication, local origin checks and bounded rate limits."""
import os,secrets,time
from collections import defaultdict,deque
from urllib.parse import urlsplit
from starlette.responses import JSONResponse

class Security:
    def __init__(self,app):self.app=app;self.windows=defaultdict(deque)
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        headers=dict(scope.get('headers',[]));path=scope['path'];method=scope['method']
        async def reject(code,message):await JSONResponse({'detail':message},status_code=code)(scope,receive,send)
        if method in ('POST','PUT','PATCH','DELETE'):
            origin=headers.get(b'origin',b'').decode()
            if origin and urlsplit(origin).netloc != headers.get(b'host',b'').decode():return await reject(403,'Cross-origin write rejected')
            if headers.get(b'sec-fetch-site')==b'cross-site':return await reject(403,'Cross-site write rejected')
        key=os.getenv('PRAHARI_API_KEY','')
        if key and path.startswith('/api/'):
            supplied=headers.get(b'authorization',b'').decode()
            integration=headers.get(b'x-prahari-key',b'').decode()
            ikey=os.getenv('PRAHARI_INTEGRATION_KEY','')
            if not secrets.compare_digest(supplied,'Bearer '+key) and not (ikey and secrets.compare_digest(integration,ikey)):
                return await reject(401,'Enter your workspace API key')
        if path in ('/api/v1/scans','/api/v1/telemetry') and method=='POST':
            client=((scope.get('client') or ('local',0))[0],path);now=time.monotonic();window=self.windows[client]
            while window and window[0]<now-60:window.popleft()
            if len(window)>=(600 if path.endswith('/telemetry') else 120):return await reject(429,'Ingestion limit reached; retry in one minute')
            window.append(now)
            if len(self.windows)>1000:
                self.windows={k:v for k,v in self.windows.items() if v and v[-1]>now-60}
                self.windows=defaultdict(deque,self.windows)
        async def secured(message):
            if message['type']=='http.response.start':
                message['headers']=list(message.get('headers',[]))+[(b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),(b'referrer-policy',b'no-referrer'),(b'cache-control',b'no-store')]
            await send(message)
        await self.app(scope,receive,secured)
