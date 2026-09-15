"""One-shot, resource-limited inspection containers. Never fall back in-process."""
import base64
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid

_slots = threading.BoundedSemaphore(2)
MAX_INPUT = 10 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024


def inspect_task(task, timeout=35):
    image = os.getenv("NETRA_INSPECTION_IMAGE", "netra-inspector:4.4.0")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,240}", image):
        return {"available": False, "error": "invalid_worker_image"}
    if not _slots.acquire(blocking=False):
        return {"available": False, "error": "inspection_capacity_exceeded"}
    name = "netra-inspect-" + uuid.uuid4().hex
    process = None
    try:
        encoded = json.dumps(task, ensure_ascii=True).encode()
        if len(encoded) > 15 * 1024 * 1024:
            return {"available": False, "error": "inspection_input_too_large"}
        network = "bridge" if task.get("operation") == "url" else "none"
        command = ["docker", "run", "--rm", "--pull=never", "--name", name,
            "--network", network, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user", "65532:65532",
            "--memory=768m", "--memory-swap=768m", "--cpus=1", "--pids-limit=64",
            "--ulimit", "cpu=25:25", "--ulimit", "fsize=2097152:2097152",
            "--ulimit", "nofile=64:64", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
            "--log-driver=none", "-i", image]
        # No environment variables, host paths, Docker socket or secrets are
        # passed into the container. The trusted CLI retains its normal config.
        with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
            incoming.write(encoded)
            incoming.seek(0)
            process = subprocess.Popen(command, stdin=incoming, stdout=outgoing,
                stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            deadline = time.monotonic() + max(1, min(35, timeout))
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    return {"available": False, "error": "inspection_timeout"}
                if os.fstat(outgoing.fileno()).st_size > MAX_OUTPUT:
                    return {"available": False, "error": "inspection_output_too_large"}
                time.sleep(0.05)
            if process.returncode != 0:
                return {"available": False, "error": "inspection_worker_unavailable"}
            outgoing.seek(0)
            raw = outgoing.read(MAX_OUTPUT + 1)
            if len(raw) > MAX_OUTPUT:
                return {"available": False, "error": "inspection_output_too_large"}
            result = json.loads(raw)
            if not isinstance(result, dict) or not isinstance(result.get("available"), bool):
                return {"available": False, "error": "invalid_worker_response"}
            return result
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
        return {"available": False, "error": "inspection_worker_unavailable"}
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
            # Killing the CLI does not kill a daemon-managed container.
            try:
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except (OSError, subprocess.SubprocessError):
                pass
        _slots.release()


def inspect_attachment(data, filename, content_type, timeout=35):
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        return {"available": False, "error": "attachment_size_limit"}
    return inspect_task({"operation": "attachment", "filename": str(filename)[:1024],
        "content_type": str(content_type)[:200], "data": base64.b64encode(data).decode("ascii")}, timeout=timeout)
