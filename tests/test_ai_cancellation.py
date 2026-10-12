import sys,time
import pytest
from cvevidence.ai_process import run_worker,WorkerCancelled

def test_cancel_terminates_actual_worker_promptly():
    start=time.monotonic()
    with pytest.raises(WorkerCancelled):
        run_worker([sys.executable,'-c','import time; time.sleep(30)'],b'{}',env={},timeout=15,
            cancel_check=lambda:time.monotonic()-start>.3)
    assert time.monotonic()-start<3

def test_deadline_terminates_actual_worker_process_group(tmp_path):
    import subprocess,os
    pidfile=tmp_path/'pid'
    code='import os,time; open('+repr(str(pidfile))+',"w").write(str(os.getpid())); time.sleep(30)'
    with pytest.raises(subprocess.TimeoutExpired):run_worker([sys.executable,'-c',code],b'{}',env={},timeout=.5)
    pid=int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):os.kill(pid,0)
