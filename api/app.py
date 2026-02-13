from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Histogram
from typing import Optional
import ipaddress
import os
import re
import subprocess
import time
import glob

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Capstone Ops API")
Instrumentator().instrument(app).expose(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ANSIBLE_DIR = os.path.join(BASE_DIR, "ansible")
PLAYBOOK_DIR = os.path.join(ANSIBLE_DIR, "ansible-zos-files")
INVENTORY_FILE = os.path.join(PLAYBOOK_DIR, "inventory.yml")

ALLOWED_PLAYBOOKS = ["ping.yml", "create_qsam.yml", "create_qsam_multiple.yml", "faulty_playbook.yml"]

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
PLAYBOOK_RUNS_TOTAL = Counter(
    "ansible_playbook_runs_total",
    "Total number of ansible playbook executions",
    ["playbook", "status"],
)

PLAYBOOK_DURATION_SECONDS = Histogram(
    "ansible_playbook_duration_seconds",
    "Duration of ansible playbook executions in seconds",
    ["playbook", "status"],
    buckets=[1, 5, 10, 30, 60, 120, 300],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _validate_ip(ip: str) -> str:
    """Raise HTTPException if *ip* is not a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address: '{ip}'. Provide a valid IPv4 or IPv6 address.",
        )
    return ip


def _available_playbooks() -> list[str]:
    """Return the whitelisted playbooks that exist in the playbooks dir."""
    return sorted(
        p for p in ALLOWED_PLAYBOOKS
        if os.path.isfile(os.path.join(PLAYBOOK_DIR, p))
    )


def _parse_recap(stdout: str) -> dict:
    """Extract the PLAY RECAP block and return a per-host summary dict.

    Example PLAY RECAP block::

        PLAY RECAP *************************************************************
        mainframe  : ok=2  changed=0  unreachable=0  failed=0  skipped=0  rescued=0  ignored=0

    Returns::

        {
            "mainframe": {
                "ok": 2, "changed": 0, "unreachable": 0,
                "failed": 0, "skipped": 0, "rescued": 0, "ignored": 0
            }
        }
    """
    recap: dict = {}
    in_recap = False
    for line in stdout.splitlines():
        if "PLAY RECAP" in line:
            in_recap = True
            continue
        if in_recap:
            stripped = line.strip()
            if not stripped:
                continue
            # Each recap line:  hostname : ok=N changed=N ...
            match = re.match(
                r"^(?P<host>\S+)\s*:\s*(?P<stats>.+)$", stripped
            )
            if match:
                host = match.group("host")
                stats_str = match.group("stats")
                stats: dict[str, int] = {}
                for pair in re.findall(r"(\w+)=(\d+)", stats_str):
                    stats[pair[0]] = int(pair[1])
                recap[host] = stats
    return recap


def _run_playbook(
    playbook: str,
    extra_vars: Optional[dict] = None,
    target_host: Optional[str] = None,
) -> dict:
    """Execute an ansible-playbook subprocess and return structured results."""

    if playbook not in ALLOWED_PLAYBOOKS:
        raise HTTPException(
            status_code=403,
            detail=f"Playbook '{playbook}' is not allowed. Available: {_available_playbooks()}",
        )

    playbook_path = os.path.join(PLAYBOOK_DIR, playbook)
    if not os.path.isfile(playbook_path):
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook}' not found on disk. Available: {_available_playbooks()}",
        )

    cmd = ["ansible-playbook", playbook_path, "-i", INVENTORY_FILE]

    # Merge caller-provided extra_vars with an optional target override.
    merged_vars: dict = dict(extra_vars) if extra_vars else {}
    if target_host:
        _validate_ip(target_host)
        merged_vars["ansible_host"] = target_host

    if merged_vars:
        ev = " ".join(f"{k}={v}" for k, v in merged_vars.items())
        cmd += ["--extra-vars", ev]

    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=PLAYBOOK_DIR)
    duration = round(time.time() - start, 2)

    recap = _parse_recap(proc.stdout)

    status = "successful" if proc.returncode == 0 else "failed"

    # Record Prometheus metrics
    PLAYBOOK_RUNS_TOTAL.labels(playbook=playbook, status=status).inc()
    PLAYBOOK_DURATION_SECONDS.labels(playbook=playbook, status=status).observe(duration)

    return {
        "return_code": proc.returncode,
        "status": status,
        "duration_seconds": duration,
        "recap": recap,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": " ".join(cmd),
    }


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class RunRequest(BaseModel):
    playbook: str = "ping.yml"
    extra_vars: Optional[dict] = None
    target_host: Optional[str] = None  # override ansible_host at runtime

    @field_validator("target_host")
    @classmethod
    def check_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(
                    f"Invalid IP address: '{v}'. Provide a valid IPv4 or IPv6 address."
                )
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/playbooks", summary="List available playbooks")
def list_playbooks():
    """Return the names of every playbook file in the playbooks directory."""
    return {"playbooks": _available_playbooks()}


@app.post("/run", summary="Run any playbook")
def run_playbook(req: RunRequest):
    """Generic endpoint – run an arbitrary playbook with optional extra vars
    and an optional *target_host* IP override."""
    result = _run_playbook(req.playbook, req.extra_vars, req.target_host)
    if result["return_code"] != 0:
        raise HTTPException(status_code=500, detail=result)
    return result


@app.post("/ops/ping", summary="Ping the mainframe")
def ping_mainframe(target_host: Optional[str] = Query(default=None)):
    """Quick connectivity check via the ``ping.yml`` playbook.
    Optionally override the target with ``?target_host=<ip>``."""
    if target_host:
        _validate_ip(target_host)
    result = _run_playbook("ping.yml", target_host=target_host)
    if result["return_code"] != 0:
        raise HTTPException(status_code=500, detail=result)
    return result


@app.post("/ops/create-qsam", summary="Create QSAM data set")
def create_qsam(
    data_set_name: Optional[str] = Query(default=None),
    target_host: Optional[str] = Query(default=None),
):
    """Create a single QSAM sequential data set via ``create_qsam.yml``."""
    if target_host:
        _validate_ip(target_host)

    extra: dict = {}
    if data_set_name:
        extra["data_set_name"] = data_set_name

    result = _run_playbook(
        "create_qsam.yml", extra_vars=extra or None, target_host=target_host
    )
    if result["return_code"] != 0:
        raise HTTPException(status_code=500, detail=result)
    return result


@app.post("/ops/create-qsam-multiple", summary="Create multiple QSAM data sets")
def create_qsam_multiple(
    zos_username: Optional[str] = Query(default=None),
    target_host: Optional[str] = Query(default=None),
):
    """Create multiple QSAM sequential data sets via ``create_qsam_multiple.yml``."""
    if target_host:
        _validate_ip(target_host)

    extra: dict = {}
    if zos_username:
        extra["zos_username"] = zos_username

    result = _run_playbook(
        "create_qsam_multiple.yml", extra_vars=extra or None, target_host=target_host
    )
    if result["return_code"] != 0:
        raise HTTPException(status_code=500, detail=result)
    return result


@app.post("/ops/faulty", summary="Run faulty playbook (testing)")
def run_faulty_playbook(target_host: Optional[str] = Query(default=None)):
    """Intentionally failing playbook for Prometheus / Grafana observability testing."""
    if target_host:
        _validate_ip(target_host)
    result = _run_playbook("faulty_playbook.yml", target_host=target_host)
    if result["return_code"] != 0:
        raise HTTPException(status_code=500, detail=result)
    return result


@app.get("/health", summary="Health check")
def health():
    return {"ok": True}


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(BASE_DIR, "static")


@app.get("/", include_in_schema=False)
def serve_frontend():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
