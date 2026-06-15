#!/usr/bin/env python3
"""
NeuroSploit v3.3.0 — minimalist web GUI server.

A tiny, dependency-free (Python stdlib only) web front-end for the autonomous
engine. It exposes just the essential options — target URL, backend, model,
collaborator, and the RL / Playwright-MCP toggles — and launches an engagement.

    python3 webgui/server.py            # serves http://127.0.0.1:8787

No npm, no build step, no FastAPI. It talks to neurosploit_agent directly.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from neurosploit_agent import backends, models               # noqa: E402
from neurosploit_agent.agent_loader import AgentLibrary       # noqa: E402
from neurosploit_agent.config import RunConfig                # noqa: E402
from neurosploit_agent.orchestrator import run_engagement     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
_RUNS = {}                      # run_id -> {log:[], done:bool, result:dict}
_LOCK = threading.Lock()
_PROV_FOR_BACKEND = {"claude": "anthropic", "codex": "openai", "grok": "xai"}


def _info():
    lib = AgentLibrary()
    det = backends.detect()
    provs = {}
    for p in models.PROVIDERS.values():
        provs[p.key] = {"label": p.label,
                        "models": [{"id": m.id, "label": m.label} for m in p.models]}
    return {
        "version": "3.3.0",
        "agents": lib.counts(),
        "backends": [{"key": b.key, "label": b.label, "version": b.version()} for b in det],
        "providers": provs,
        "backend_provider": _PROV_FOR_BACKEND,
    }


def _start_run(params):
    run_id = "run-%d" % (len(_RUNS) + 1)
    with _LOCK:
        _RUNS[run_id] = {"log": [], "done": False, "result": None}

    def progress(msg):
        with _LOCK:
            _RUNS[run_id]["log"].append(msg)

    def worker():
        try:
            backend = params.get("backend") or (backends.detect()[0].key if backends.detect() else "claude")
            provider = params.get("provider") or _PROV_FOR_BACKEND.get(backend, "anthropic")
            mlist = models.list_models(provider)
            model = params.get("model") or (mlist[0].id if mlist else "")
            url = params["url"]
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            cfg = RunConfig(
                target=url, scope=params.get("scope") or url, backend=backend,
                provider=provider, model=model, collaborator=params.get("collaborator", ""),
                use_rl=bool(params.get("rl", True)), use_mcp=bool(params.get("mcp", True)),
                dry_run=bool(params.get("dry_run", False)),
            )
            res = run_engagement(cfg, progress=progress)
            with _LOCK:
                _RUNS[run_id]["result"] = {
                    "returncode": res["returncode"], "workdir": res["workdir"],
                    "findings": res["findings"], "agents_ran": res["agents_ran"],
                }
        except Exception as e:  # surface errors to the UI
            progress(f"ERROR: {e}")
            with _LOCK:
                _RUNS[run_id]["result"] = {"error": str(e)}
        finally:
            with _LOCK:
                _RUNS[run_id]["done"] = True

    threading.Thread(target=worker, daemon=True).start()
    return run_id


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
        elif self.path == "/api/info":
            self._send(200, json.dumps(_info()))
        elif self.path.startswith("/api/status/"):
            rid = self.path.rsplit("/", 1)[-1]
            with _LOCK:
                st = _RUNS.get(rid)
                self._send(200 if st else 404, json.dumps(st or {"error": "unknown run"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path != "/api/run":
            return self._send(404, json.dumps({"error": "not found"}))
        n = int(self.headers.get("Content-Length", 0))
        try:
            params = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, json.dumps({"error": "bad json"}))
        if not params.get("url"):
            return self._send(400, json.dumps({"error": "url required"}))
        rid = _start_run(params)
        self._send(200, json.dumps({"run_id": rid}))


def main():
    host = os.getenv("NEUROSPLOIT_GUI_HOST", "127.0.0.1")
    port = int(os.getenv("NEUROSPLOIT_GUI_PORT", "8787"))
    print(f"NeuroSploit v3.3.0 GUI → http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
