"""Real HTTP integration and Chromium incident UI smoke test. Requires playwright."""
import json,os,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
def get(path):
 with urllib.request.urlopen('http://127.0.0.1:8000'+path) as r:return json.load(r)
with tempfile.TemporaryDirectory() as d:
 env={**os.environ,'PRAHARI_DB':d+'/qa.db','PRAHARI_DEMO_DATA':d+'/board','PRAHARI_POLICY':'demo-strict','PRAHARI_INTEGRATION_KEY':'incident-qa-key','PRAHARI_PSEUDONYM_KEY':'incident-qa-identity'}
 services=[subprocess.Popen([sys.executable,'-m','uvicorn','prahari.api:app','--port','8000','--no-access-log'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE),subprocess.Popen(['node','demo-app/server.mjs'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)]
 try:
  for _ in range(100):
   try:get('/ready');urllib.request.urlopen('http://127.0.0.1:3000/stats');break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('Services did not start')
  with sync_playwright() as p:
   browser=p.chromium.launch(executable_path=os.getenv('PRAHARI_BROWSER'),headless=True,args=['--no-sandbox','--disable-gpu','--disable-dev-shm-usage'])
   page=browser.new_page(viewport={'width':1440,'height':1000});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
   page.goto('http://127.0.0.1:3000');page.locator('#session-demo').click()
   page.wait_for_function("document.querySelector('#session-result').textContent.includes('Five failures recorded')")
   for _ in range(50):
    if get('/api/v1/telemetry/summary')['events']>=5:break
    time.sleep(.1)
   summary=get('/api/v1/telemetry/summary');assert summary['events']==5;assert summary['sessions']==1
   page.goto('http://127.0.0.1:8000');page.locator('#incidents button').first.wait_for();page.locator('#incidents button').first.click()
   page.wait_for_function("document.querySelector('#incident-detail').textContent.includes('Repeated authentication failures')")
   page.get_by_role('button',name='Investigate',exact=True).click()
   page.wait_for_function("document.querySelector('#incident-detail').textContent.includes('investigating')")
   with page.expect_download() as download:page.get_by_role('button',name='Export incident JSON').click()
   assert download.value.suggested_filename.endswith('.json')
   subprocess.run([sys.executable,'scripts/import_zeek.py','examples/zeek-port-probe.jsonl','--stream','qa-flow'],cwd=ROOT,env=env,check=True)
   subprocess.run([sys.executable,'scripts/import_zeek.py','examples/zeek-port-probe.jsonl','--stream','qa-flow'],cwd=ROOT,env=env,check=True)
   summary=get('/api/v1/telemetry/summary');assert summary['events']==17;assert summary['modes']=={'live':5,'replay':12}
   # Exercise live-follow ingestion and its persistent cursor on a local sensor fixture.
   log=Path(d)/'conn.log';rows=[json.loads(line) for line in (ROOT/'examples/zeek-port-probe.jsonl').read_text().splitlines()]
   stamp=time.time()-20
   for i,row in enumerate(rows):row['ts']=stamp+i
   log.write_text(''.join(json.dumps(row)+'\n' for row in rows))
   command=[sys.executable,'scripts/import_zeek.py',str(log),'--follow','--stream','follow-qa','--checkpoint',d+'/cursor.json']
   follower=subprocess.Popen(command,cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
   try:
    for _ in range(100):
     if get('/api/v1/telemetry/summary')['events']==29:break
     if follower.poll() is not None:raise RuntimeError(follower.stderr.read().decode())
     time.sleep(.05)
    assert get('/api/v1/telemetry/summary')['events']==29
   finally:follower.terminate();follower.wait()
   assert json.loads((Path(d)/'cursor.json').read_text())['offset']==log.stat().st_size
   follower=subprocess.Popen(command,cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
   try:
    time.sleep(.3);assert follower.poll() is None
    assert get('/api/v1/telemetry/summary')['events']==29
   finally:follower.terminate();follower.wait()
   page.locator('#incident-mode').select_option('replay');page.locator('#incident-refresh').click()
   page.wait_for_function("document.querySelector('#incidents').textContent.includes('destination ports')")
   page.locator('#incidents button').first.click();page.wait_for_function("document.querySelector('#incident-detail').textContent.includes('destination ports')")
   out=ROOT/'submission/screenshots';out.mkdir(exist_ok=True,parents=True)
   page.locator('section[aria-label="Live incidents"]').screenshot(path=str(out/'incidents-v2.png'))
   page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
   assert not errors,errors;browser.close()
   print('PASS: live session, stable cookie, authentication-failure incident, review, export, Zeek replay, duplicate replay, live-follow cursor restart, desktop/mobile UI')
 finally:
  for process in services:process.terminate()
  for process in services:process.wait()
