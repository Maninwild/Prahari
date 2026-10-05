"""Launch local scanner and protected Node app with a fresh shared event key."""

import os, sys, shutil, subprocess, secrets, time, urllib.request
from pathlib import Path

os.chdir(Path(__file__).resolve().parent)
if not shutil.which("node"):
    sys.exit("Install Node.js 22 or newer, then run again.")
env = {
    **os.environ,
    "PRAHARI_INTEGRATION_KEY": secrets.token_hex(32),
    "PRAHARI_POLICY": "demo-strict",
    "PRAHARI_URL": "http://127.0.0.1:8000",
}
processes = []
try:
    processes.append(
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "prahari.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
                "--no-access-log",
            ],
            env=env,
        )
    )
    for _ in range(100):
        time.sleep(0.1)
        if processes[0].poll() is not None:
            sys.exit(
                "Scanner failed to start. Stop the old Prahari terminal before launching this demo."
            )
        try:
            urllib.request.urlopen("http://127.0.0.1:8000/ready", timeout=0.5)
            break
        except OSError:
            pass
    else:
        sys.exit("Scanner did not become ready.")
    processes.append(subprocess.Popen(["node", "demo-app/server.mjs"], env=env))
    print(
        "Open http://127.0.0.1:3000 for the protected demo. Ctrl+C stops both services.",
        flush=True,
    )
    while all(p.poll() is None for p in processes):
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        p.wait()
