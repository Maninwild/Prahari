import os,sys,tempfile,subprocess,time,json,urllib.request,urllib.error
from pathlib import Path
os.chdir(Path(__file__).resolve().parents[1])

def request(url,data=None,key=None):
 headers={'Content-Type':'application/json'}
 if key:headers['X-Prahari-Key']=key
 req=urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,headers=headers)
 try:r=urllib.request.urlopen(req,timeout=20)
 except urllib.error.HTTPError as e:r=e
 return r.status,json.load(r)
with tempfile.TemporaryDirectory() as d:
 env={**os.environ,'PRAHARI_DB':d+'/test.db','PRAHARI_POLICY':'demo-strict','PRAHARI_INTEGRATION_KEY':'integration-test-key','PRAHARI_URL':'http://127.0.0.1:8129','DEMO_PORT':'3139','PRAHARI_DEMO_DATA':d+'/demo'}
 processes=[]
 try:
  processes.append(subprocess.Popen([sys.executable,'-m','uvicorn','prahari.api:app','--port','8129'],cwd='.',env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
  processes.append(subprocess.Popen(['node','demo-app/server.mjs'],cwd='.',env=env,stdout=subprocess.DEVNULL))
  for _ in range(100):
   try:request('http://127.0.0.1:8129/ready');request('http://127.0.0.1:3139/stats');break
   except OSError:time.sleep(.1)
  for kind,text,expected in [('payload','GET /products?page=2 HTTP/1.1',200),('payload','<script>alert(1)</script>',403),('url','http://secure-paypal-verify.example/login',409)]:
   code,result=request('http://127.0.0.1:3139/submit',{'input_type':kind,'content':text});print(code,result);assert code==expected;assert result['handler_reached']==1;assert result['acknowledgement_recorded']
  summary=request('http://127.0.0.1:8129/api/v1/dashboard/summary')[1];assert summary['enforced_blocks']==1
  # Independent scan proves idempotent ack and authentication.
  scan=request('http://127.0.0.1:8129/api/v1/scans',{'input_type':'payload','content':'<script>'})[1]
  event={'event_id':'test-event','scan_id':scan['scan_id'],'mode':'enforce','action':'blocked'}
  assert request('http://127.0.0.1:8129/api/v1/enforcement-events',event)[0]==401
  for _ in range(2):assert request('http://127.0.0.1:8129/api/v1/enforcement-events',event,'integration-test-key')[0]==200
  assert request('http://127.0.0.1:8129/api/v1/dashboard/summary')[1]['enforced_blocks']==2
  processes[0].terminate();processes[0].wait()
  code,r=request('http://127.0.0.1:3139/submit',{'input_type':'payload','content':'hello'});assert code==503 and r['handler_reached']==1
  print('PASS live allow/block/review, handler isolation, authenticated idempotent events, scanner outage')
 finally:
  for p in processes:
   if p.poll() is None:p.terminate()
  for p in processes:p.wait()
