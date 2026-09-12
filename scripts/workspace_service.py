"""WSL/Linux local-only service manager. Run with the project's venv Python."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
ROOT=Path(__file__).resolve().parents[1]
STATE=ROOT/"var/service"
PID=STATE/"workspace.json"

def identity(pid):
    proc=Path("/proc")/str(pid)
    try:
        command=(proc/"cmdline").read_bytes().split(b"\0")
        if b"streamlit" not in command or str(ROOT/"runner_app.py").encode() not in command:
            return None
        return (proc/"stat").read_text().split()[21]
    except (OSError,IndexError):
        return None

def existing():
    if not PID.exists(): return None
    record=json.loads(PID.read_text())
    return record if identity(record["pid"])==record["start_ticks"] else None

def stop():
    record=existing()
    if record:
        os.kill(record["pid"],signal.SIGTERM)
        for _ in range(50):
            if identity(record["pid"]) is None: break
            time.sleep(.1)
        else: raise RuntimeError("Server did not stop; do not launch a competing process")
    PID.unlink(missing_ok=True)

def start():
    if existing(): return existing()
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (STATE/"workspace.log").open("ab") as log:
        child=subprocess.Popen([sys.executable,"-m","streamlit","run",str(ROOT/"runner_app.py"),
            "--server.address","127.0.0.1","--server.port","8505","--server.headless","true",
            "--browser.gatherUsageStats","false"],cwd=ROOT,stdin=subprocess.DEVNULL,
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    for _ in range(80):
        if child.poll() is not None: raise RuntimeError("Server failed; inspect var/service/workspace.log")
        ticks=identity(child.pid)
        if ticks:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8505/_stcore/health",timeout=.5) as response:
                    if response.read()==b"ok":
                        record={"pid":child.pid,"start_ticks":ticks,"url":"http://127.0.0.1:8505/"}
                        PID.write_text(json.dumps(record))
                        return record
            except OSError: pass
        time.sleep(.1)
    raise RuntimeError("Startup health timed out")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=["start","restart","stop","status"])
    action=p.parse_args().action
    if action in ("stop","restart"): stop()
    if action in ("start","restart"): print(json.dumps(start()))
    elif action=="status": print(json.dumps(existing()))
