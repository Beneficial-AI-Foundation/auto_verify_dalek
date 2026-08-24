#!/usr/bin/env python3
"""Minimal localhost logging reverse proxy for the Anthropic API.

Usage: wire_proxy.py PORT OUT_DIR

Spawned by agentproc.start_wire_proxy(); the claude subprocess is routed here
via ANTHROPIC_BASE_URL. Each request body is appended as one JSON line to
OUT_DIR/wire_requests.jsonl; the response (including SSE streams) is piped
back unmodified. Best-effort by design: a proxy bug must never fail a proof
round, so upstream errors are passed through and local errors answer 502.

Upstream defaults to https://api.anthropic.com; override with WIRE_UPSTREAM
(used by the self-test in harness/gates/tests).
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("WIRE_UPSTREAM", "https://api.anthropic.com")
# Hop-by-hop / recomputed headers never forwarded in either direction.
HOP = {"host", "content-length", "connection", "keep-alive",
       "transfer-encoding", "upgrade", "proxy-authorization", "te", "trailer"}


class Handler(BaseHTTPRequestHandler):
    out_dir = ""
    _lock = threading.Lock()

    # HTTP/1.0 (the BaseHTTPRequestHandler default) on purpose: we forward
    # bodies without Content-Length, so connection-close delimits them.

    def log_message(self, format, *args):
        sys.stdout.write("[wire] " + (format % args) + "\n")
        sys.stdout.flush()

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self._log_request(body)

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP}
        req = urllib.request.Request(
            UPSTREAM + self.path, data=body or None,
            headers=headers, method=self.command)
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            resp = e  # response-like: pass upstream status/body through
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"wire_proxy upstream error: {e}".encode())
            return
        status = getattr(resp, "status", None) or resp.code
        self.send_response(status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP:
                self.send_header(k, v)
        self.end_headers()
        try:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()   # SSE: forward deltas as they arrive
        except (BrokenPipeError, ConnectionResetError):
            pass  # claude hung up mid-stream (killed round); nothing to do
        finally:
            resp.close()

    def _log_request(self, body):
        try:
            parsed = json.loads(body) if body else None
        except Exception:
            parsed = {"_raw": body.decode("utf-8", "replace")[:100000]}
        rec = {"ts": time.time(), "method": self.command,
               "path": self.path, "body": parsed}
        try:
            with self._lock, open(os.path.join(self.out_dir,
                                               "wire_requests.jsonl"),
                                  "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as e:
            self.log_message("request log failed: %s", e)


def main():
    port, out_dir = int(sys.argv[1]), sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    Handler.out_dir = out_dir
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[wire] listening on 127.0.0.1:{port} -> {out_dir} "
          f"(upstream {UPSTREAM})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
