import datetime
import json
import ssl
import time
import urllib.request
import uuid

import jwt

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

SECRET = "scythe-local-test-secret-change-before-production-2026"
payload = {
    "sub": "0b464f83-b69a-457a-a12b-d4dfa59792cc",
    "email": "live-url-test@example.test",
    "iss": "scythe-auth-v1",
    "aud": "scythe-clients",
    "jti": str(uuid.uuid4()),
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
}
token = jwt.encode(payload, SECRET, algorithm="HS256")

test_urls = [
    ("http://43.128.92.128/interactivelogin?continue=https://accounts.google.com/", "Phishing (IP host + OAuth)"),
    ("http://www.umaplastoware.com/aaq/linkedinhardxxx/900/index.php", "Phishing (Compromised domain)"),
    ("http://206.189.191.231/zbi/ameli-carte-vitale/index.php", "Phishing (IP banking phish)"),
    ("https://phantom-app-4eu8.vercel.app/login", "Phishing (PaaS Vercel abuse)"),
    ("https://www.bbc.com/", "Benign (BBC News)"),
    ("https://www.python.org/", "Benign (Python.org)"),
    ("https://www.stackoverflow.com/", "Benign (StackOverflow)"),
    ("https://www.wikipedia.org/", "Benign (Wikipedia)"),
]

print("=" * 75)
print("LIVE HTTP CONTAINER SCAN RESULTS (https://localhost:8443/api/scans/quick)")
print("=" * 75)
for url, desc in test_urls:
    req = urllib.request.Request(
        "https://localhost:8443/api/scans/quick",
        data=json.dumps({"url": url}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST"
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, context=CTX, timeout=10) as resp:
        data = json.loads(resp.read())
        lat = (time.perf_counter() - t0) * 1000
        print(f"URL:     {url[:60]:<60} [{desc}]")
        print(f"Verdict: Status {resp.status} | Risk: {data.get('risk_level')} (Score: {data.get('risk_score')}) | Model: {data.get('model_version')} | Latency: {lat:.1f}ms")
    time.sleep(0.5)
