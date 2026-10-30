"""Bounded, metadata-only HAR: no bodies, credentials, cookies or query values."""
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


def redacted_url(url):
    try:
        value = urlsplit(url)
        host = value.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if value.port:
            host += f":{value.port}"
        return urlunsplit((value.scheme, host, value.path[:2048], "", ""))
    except ValueError:
        return ""


class HarRecorder:
    def __init__(self, limit=500):
        self.limit = limit
        self.rows = []
        self.active = {}
        self.total = 0

    def request(self, request):
        self.total += 1
        if len(self.rows) >= self.limit:
            return
        row = {"startedDateTime": datetime.now(timezone.utc).isoformat(),
               "time": 0, "request": {"method": request.method, "url": redacted_url(request.url),
               "httpVersion": "", "cookies": [], "headers": [], "queryString": [],
               "headersSize": -1, "bodySize": -1},
               "response": {"status": 0, "statusText": "", "httpVersion": "",
               "cookies": [], "headers": [], "content": {"size": -1, "mimeType": ""},
               "redirectURL": "", "headersSize": -1, "bodySize": -1},
               "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
               "_timingScope": "request event to response headers; body timing unavailable"}
        self.rows.append(row)
        self.active[id(request)] = (row, time.monotonic())

    def response(self, response, headers):
        entry = self.active.pop(id(response.request), None)
        if entry is None:
            return
        row, started = entry
        row["time"] = round((time.monotonic() - started) * 1000, 3)
        row["timings"]["wait"] = row["time"]
        row["response"]["status"] = response.status
        row["response"]["content"]["mimeType"] = headers.get("content-type", "").split(";")[0][:128]
        row["response"]["redirectURL"] = redacted_url(headers.get("location", ""))

    def write(self, path):
        document = {"log": {"version": "1.2", "creator": {"name": "SCYTHE", "version": "1"},
                    "entries": self.rows, "_privacy": "No bodies, headers, cookies, URL userinfo, queries or fragments",
                    "_truncated": self.total > self.limit, "_totalRequests": self.total}}
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"))
        os.chmod(temporary, 0o660)  # nosec B103 -- scan IPC requires shared UID/GID, no world access
        os.replace(temporary, path)
