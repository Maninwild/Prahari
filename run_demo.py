"""Launch local scanner and protected Node app with a fresh shared event key."""
import os,sys,shutil,subprocess,secrets,time,urllib.request,socket,webbrowser
from pathlib import Path
os.chdir(Path(__file__).resolve().parent)
if not shutil.which('node'):sys.exit('Install Node.js 22 or newer, then run again.')
if int(subprocess.check_output(['node','--version'],text=True).strip().lstrip('v').split('.')[0])<22:sys.exit('Node.js 22 or newer is required.')
for port in (8000,3000):
 try:
  with socket.socket() as probe:probe.bind(('127.0.0.1',port))
 except OSError:sys.exit(f'Port {port} is occupied. Stop the old server or app before launching.')
identity_file=Path('data/pseudonym.key');identity_file.parent.mkdir(exist_ok=True)
if not identity_file.exists():identity_file.write_text(secrets.token_hex(32))
env={**os.environ,'PRAHARI_PSEUDONYM_KEY':os.getenv('PRAHARI_PSEUDONYM_KEY') or identity_file.read_text().strip(),'PRAHARI_INTEGRATION_KEY':os.getenv('PRAHARI_INTEGRATION_KEY') or secrets.token_hex(32),'PRAHARI_POLICY':'demo-strict'}
processes=[]
try:
 processes.append(subprocess.Popen([sys.executable,'-m','uvicorn','prahari.api:app','--host','127.0.0.1','--port','8000','--no-access-log'],env=env))
 for _ in range(100):
  time.sleep(.1)
  if processes[0].poll() is not None:sys.exit('Scanner failed to start. Stop the old Prahari terminal before launching this demo.')
  try:urllib.request.urlopen('http://127.0.0.1:8000/ready',timeout=.5);break
  except OSError:pass
 else:sys.exit('Scanner did not become ready.')
 processes.append(subprocess.Popen(['node','demo-app/server.mjs'],env=env))
 print('Open http://127.0.0.1:3000 for the protected demo. Ctrl+C stops both services.',flush=True)
 for _ in range(50):
  if processes[1].poll() is not None:sys.exit('The board failed to start; check its error above.')
  try:urllib.request.urlopen('http://127.0.0.1:3000/stats',timeout=.5);break
  except OSError:time.sleep(.1)
 else:sys.exit('The board did not become ready.')
 webbrowser.open('http://127.0.0.1:3000/')
 while all(p.poll() is None for p in processes):time.sleep(.5)
except KeyboardInterrupt:pass
finally:
 for p in processes:
  if p.poll() is None:p.terminate()
 for p in processes:p.wait()
