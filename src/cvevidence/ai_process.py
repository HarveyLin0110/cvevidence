"""Bounded POSIX worker I/O for trusted, fixed commands only."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
from time import monotonic


class WorkerCancelled(RuntimeError):
    pass


class WorkerLimitError(ValueError):
    pass


def run_worker(argv, payload, *, env, timeout, max_output=16 * 1024 * 1024, cancel_check=None):
    if os.name != "posix" or timeout <= 0:
        raise subprocess.TimeoutExpired("AI worker", timeout)
    if len(payload) > 32000:
        raise WorkerLimitError("AI input limit exceeded")
    deadline = monotonic() + timeout
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            sent = 0
            while selector.get_map():
                if cancel_check is not None and cancel_check():raise WorkerCancelled("Cancelled by user")
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("AI worker", timeout)
                for key, mask in selector.select(min(remaining, 0.2)):
                    if mask & selectors.EVENT_WRITE:
                        try:
                            count = os.write(key.fd, payload[sent:sent + 4096])
                            sent += count
                        except BrokenPipeError:
                            sent = len(payload)
                        if sent >= len(payload):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                    else:
                        chunk = os.read(key.fd, min(65536, max_output - len(output) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > max_output:
                                raise WorkerLimitError("AI output limit exceeded")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("AI worker", timeout)
            process.wait(timeout=remaining)
        return process.returncode, bytes(output)
    finally:
        # Clean up descendants even if the worker itself already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for stream in (process.stdin, process.stdout):
            if stream and not stream.closed:
                stream.close()
