"""One-shot, resource-limited inspection containers. Never fall back in-process."""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid

_slots = threading.BoundedSemaphore(2)
MAX_INPUT = 10 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024


def _portable_attachment(task, timeout=35):
    """Run static inspection out of process where Docker is unavailable."""
    worker = os.path.join(os.path.dirname(__file__), "portable_inspection_worker.py")
    encoded = json.dumps(task, ensure_ascii=True).encode()
    if len(encoded) > 15 * 1024 * 1024:
        return {"available": False, "error": "inspection_input_too_large"}
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"}
    }
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONUTF8"] = "1"
    for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        environment[key] = "1"

    def limits():
        if os.name != "posix":
            return
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        # ONNX Runtime needs more virtual address space than the raster itself.
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))

    try:
        completed = subprocess.run(
            [sys.executable, "-I", worker], input=encoded,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=max(1, min(35, timeout)), check=False,
            env=environment, cwd=os.path.dirname(worker),
            preexec_fn=limits if os.name == "posix" else None,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        result = _portable_result(completed.stdout, completed.returncode)
        if not isinstance(result, dict) or not isinstance(result.get("available"), bool):
            return {"available": False, "error": "invalid_worker_response"}
        return result
    except subprocess.TimeoutExpired as exc:
        return _portable_result(exc.stdout or b"", -1)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError):
        return {"available": False, "error": "portable_inspection_worker_unavailable"}


def _portable_result(raw, returncode):
    if len(raw) > MAX_OUTPUT:
        return {"available": False, "error": "inspection_output_too_large"}
    result = None
    for line in raw.splitlines():
        try:
            candidate = json.loads(line)
            if isinstance(candidate, dict) and isinstance(candidate.get("available"), bool):
                if result and result.get("available") and not candidate.get("available"):
                    returncode = -1
                else:
                    result = candidate
        except (ValueError, UnicodeError):
            continue
    if result is None:
        return {"available": False, "error": "portable_inspection_worker_unavailable"}
    if returncode and result.get("available"):
        result.setdefault("limitations", []).append("Visual inspection exceeded the worker budget; completed PDF text and link checks were preserved. OCR and QR coverage may be incomplete.")
    return result


def inspect_task(task, timeout=35):
    image = os.getenv("NETRA_INSPECTION_IMAGE", "netra-inspector:4.6.0")
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


def inspect_attachment(data, filename, content_type, timeout=35, *, password=None):
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        return {"available": False, "error": "attachment_size_limit"}
    task = {"operation": "attachment", "filename": str(filename)[:1024],
        "content_type": str(content_type)[:200], "data": base64.b64encode(data).decode("ascii")}
    if password is not None:
        task.update(operation="pdf_unlock", password=password)
    # Native hosted runtimes do not supply a Docker daemon. An explicit mode
    # still wins; never silently fall back after a configured Docker failure.
    default_mode = "portable" if os.getenv("NETRA_DEPLOYMENT_MODE", "").lower() == "hosted" else "docker"
    mode = os.getenv("NETRA_INSPECTION_MODE", default_mode).strip().lower()
    if mode == "portable":
        if not _slots.acquire(blocking=False):
            return {"available": False, "error": "inspection_capacity_exceeded"}
        try:
            return _portable_attachment(task, timeout=timeout)
        finally:
            _slots.release()
    if mode != "docker":
        return {"available": False, "error": "invalid_inspection_mode"}
    if password is not None:
        return _private_pdf_task(task, timeout)
    return inspect_task(task, timeout=timeout)


def _private_pdf_task(task, timeout):
    """Password tasks use pipes, never the general Docker task's temp files."""
    if not _slots.acquire(blocking=False):
        return {"available": False, "error": "inspection_capacity_exceeded"}
    name = "netra-pdf-" + uuid.uuid4().hex
    image = os.getenv("NETRA_INSPECTION_IMAGE", "netra-inspector:4.6.0")
    try:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,240}", image):
            return {"available": False, "error": "invalid_worker_image"}
        command = ["docker", "run", "--rm", "--pull=never", "--name", name,
                   "--network=none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--user=65532:65532",
                   "--memory=768m", "--memory-swap=768m", "--cpus=1", "--pids-limit=64",
                   "--log-driver=none", "--tmpfs=/tmp:rw,noexec,nosuid,size=32m", "-i", image]
        completed = subprocess.run(command, input=json.dumps(task).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=min(35, timeout),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode or len(completed.stdout) > MAX_OUTPUT:
            raise ValueError("worker_failed")
        result = json.loads(completed.stdout)
        return result if isinstance(result, dict) else {"available": False, "error": "invalid_worker_response"}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"available": False, "error": "pdf_inspection_unavailable"}
    finally:
        task.pop("password", None)
        try:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            pass
        _slots.release()
