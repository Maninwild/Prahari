import os,sys,subprocess,tempfile,time,urllib.request,json
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'submission/screenshots';OUT.mkdir(exist_ok=True,parents=True)
with tempfile.TemporaryDirectory() as d:
 env={**os.environ,'PRAHARI_DB':d+'/qa.db','PRAHARI_DEMO_DATA':d+'/board','PRAHARI_POLICY':'demo-strict','PRAHARI_INTEGRATION_KEY':'browser-test-key'}
 services=[subprocess.Popen([sys.executable,'-m','uvicorn','prahari.api:app','--port','8000','--no-access-log'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE),subprocess.Popen(['node','demo-app/server.mjs'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)]
 try:
  for _ in range(100):
   try:urllib.request.urlopen('http://127.0.0.1:8000/ready');urllib.request.urlopen('http://127.0.0.1:3000/stats');break
   except OSError:time.sleep(.1)
  with sync_playwright() as p:
   b=p.chromium.launch(executable_path=os.getenv('PRAHARI_BROWSER'),headless=True,args=['--no-sandbox','--disable-gpu','--disable-dev-shm-usage'])
   page=b.new_page(viewport={'width':1440,'height':1100});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
   page.goto('http://127.0.0.1:8000/')
   page.get_by_role('button',name='Benign',exact=True).click();page.locator('#submit').click();page.wait_for_function("document.querySelector('#total').textContent==='1'")
   assert page.locator('#result h2').inner_text()=='Allow'
   page.get_by_role('button',name='XSS',exact=True).click();page.locator('#submit').click();page.wait_for_function("document.querySelector('#total').textContent==='2'")
   assert page.locator('#result h2').inner_text()=='Block'
   page.get_by_role('button',name='Confirm threat',exact=True).click();page.wait_for_function("document.querySelector('#result').textContent.includes('Analyst review: malicious')")
   with page.expect_download() as download:page.locator('#export').click()
   assert download.value.suggested_filename.endswith('.json')
   page.screenshot(path=str(OUT/'workspace.png'),full_page=True)
   page.locator('#filter').select_option('Allow');page.wait_for_function("document.querySelector('#page').textContent==='1–1 of 1'")
   page.locator('#history button').first.click();page.wait_for_function("document.querySelector('#result h2').textContent==='Allow'")
   page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(OUT/'mobile.png'),full_page=True)
   assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
   page.set_viewport_size({'width':1440,'height':1100});page.goto('http://127.0.0.1:3000/')
   page.get_by_role('button',name='Benign',exact=True).click();page.locator('#send').click();page.wait_for_function("document.querySelector('#result').textContent.includes('HTTP 200')")
   assert 'GET /products' in page.locator('#posts').inner_text()
   page.get_by_role('button',name='Block example',exact=True).click();page.locator('#send').click();page.wait_for_function("document.querySelector('#result').textContent.includes('HTTP 403')")
   assert json.loads(page.locator('#stats').inner_text())['handler_reached']==1
   page.get_by_role('button',name='Review example',exact=True).click();page.locator('#send').click();page.wait_for_function("document.querySelector('#result').textContent.includes('HTTP 409')")
   page.screenshot(path=str(OUT/'protected-board.png'),full_page=True)
   assert not errors,errors
   b.close();print('PASS real Chromium: scans, review, export, history filters, mobile layout, board acceptance and denial; no JavaScript errors')
 finally:
  for s in services:s.terminate()
  for s in services:s.wait()
