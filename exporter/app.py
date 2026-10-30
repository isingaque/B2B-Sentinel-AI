import os
from threading import Lock
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Duty AI demo metrics exporter", docs_url=None, redoc_url=None)
SCENARIOS = ("cpu_high", "disk_full", "database_down", "nginx_down", "packet_loss")
_state = {name: 0 for name in SCENARIOS}
_lock = Lock()

def verify(token):
    if token != os.getenv("DEMO_TOKEN", "change_me_shared_demo_secret"):
        raise HTTPException(403, "Invalid internal token")

@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    with _lock:
        lines = ["# HELP demo_incident_active Demo event switch", "# TYPE demo_incident_active gauge"]
        lines.extend(f'demo_incident_active{{scenario="{name}",instance="node-01"}} {active}' for name, active in _state.items())
        return "\n".join(lines) + "\n"

@app.post("/trigger/{scenario}")
def trigger(scenario: str, x_demo_token: str | None = Header(None)):
    verify(x_demo_token)
    if scenario not in _state:
        raise HTTPException(404, "Unknown scenario")
    with _lock:
        _state[scenario] = 1
    return {"scenario": scenario, "state": "active"}

@app.post("/reset")
def reset(x_demo_token: str | None = Header(None)):
    verify(x_demo_token)
    with _lock:
        for k in _state:
            _state[k] = 0
    return {"state": "inactive"}
