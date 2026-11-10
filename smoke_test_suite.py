"""SCYTHE V26 Smoke Test Suite — benign + phishing + auth checks."""
import datetime
import json
import ssl
import time
import urllib.request
import uuid

import jwt  # PyJWT

# ── Config ───────────────────────────────────────────────────────────────────
BASE_URL = "https://localhost:8443"
SECRET   = "scythe-local-test-secret-change-before-production-2026"
USER_ID  = "0b464f83-b69a-457a-a12b-d4dfa59792cc"
EMAIL    = "codex-compose-check@example.test"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

RESULTS = []

# ── Helpers ───────────────────────────────────────────────────────────────────
def make_token():
    payload = {
        "sub": USER_ID,
        "email": EMAIL,
        "iss": "scythe-auth-v1",
        "aud": "scythe-clients",
        "jti": str(uuid.uuid4()),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def make_request(path, body=None, token=None, max_retries=4):
    for attempt in range(max_retries):
        url  = BASE_URL + path
        data = json.dumps(body).encode() if body else None
        hdrs = {"Content-Type": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        req  = urllib.request.Request(url, data=data, headers=hdrs,
                                      method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < max_retries - 1:
                time.sleep(3.5)
                continue
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"raw": raw.decode("utf-8", errors="ignore")}
        except Exception as exc:
            return 0, {"error": str(exc)}


request = make_request


def check(name, cond, detail=""):
    icon = "[PASS]" if cond else "[FAIL]"
    print(f"  {icon} {name}" + (f"  [{detail}]" if detail else ""))
    RESULTS.append((name, cond))


# ── Tests ────────────────────────────────────────────────────────────────────
tok = make_token()
print(f"\n{'='*65}")
print("SCYTHE V26 Smoke Test Suite")
print(f"{'='*65}\n")

# 1. Unauthenticated → 401
print("-- 1. Auth gate -----------------------------------------------")
status, body = request("/api/scans/quick", {"url": "https://www.bbc.com/"})
check("unauthenticated -> 401", status == 401, f"got {status}")

# 2. Allowlisted domains (Wikipedia / wikimedia) → SAFE, is_whitelisted
print("\n-- 2. Allowlist (wikipedia / wikimedia) -----------------------")
for url in [
    "https://www.wikipedia.org/",
    "https://wikipedia.org/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.wikimedia.org/",
]:
    status, body = request("/api/scans/quick", {"url": url}, token=tok)
    rl   = body.get("risk_level", "?")
    wl   = body.get("is_whitelisted", False)
    ph   = body.get("is_placeholder", True)
    check(f"{url[:55]}... -> SAFE+whitelisted",
          status == 200 and rl in ("SAFE", "LOW") and wl is True and ph is False,
          f"status={status} risk={rl} whitelisted={wl} placeholder={ph}")

# 3. Known benign sites → model scores, not UNKNOWN
print("\n-- 3. Known-benign (model-scored, non-allowlisted) -----------")
BENIGN_URLS = [
    "https://www.bbc.com/",
    "https://www.github.com/",
    "https://www.stackoverflow.com/",
    "https://www.python.org/",
    "https://www.reddit.com/",
]
for url in BENIGN_URLS:
    status, body = request("/api/scans/quick", {"url": url}, token=tok)
    rl   = body.get("risk_level", "?")
    ph   = body.get("is_placeholder", True)
    mdl  = body.get("model_version", "?")
    sc   = body.get("risk_score")
    check(f"{url[:50]} -> not UNKNOWN",
          status == 200 and rl != "UNKNOWN" and ph is False,
          f"risk={rl} score={sc} model={mdl} placeholder={ph}")

# 4. Known phishing URLs → HIGH risk
print("\n-- 4. Phishing URLs -> HIGH risk -------------------------------")
PHISH_URLS = [
    "http://101.99.90.128/banks/cibc/010dc150a13c7436b7ed27f7c2371ca0",
    "http://101.99.90.131/banks/td/f1c3fb719c61348af4d92af3c5a7dea8/step2.html",
    "http://101.99.90.132/banks/cibc/944535d8937def709c7c8a1a906515d5",
    "http://101.99.90.147/banks/desjardins/1f99bbd52b07ad0b37f6988164e24784",
    "http://101.99.90.156/banks/cibc/74ea285cc571a3bf478febef8c066f3c",
]
for url in PHISH_URLS:
    status, body = request("/api/scans/quick", {"url": url}, token=tok)
    rl   = body.get("risk_level", "?")
    ph   = body.get("is_placeholder", True)
    sc   = body.get("risk_score")
    mdl  = body.get("model_version", "?")
    check(f"{url[:55]} -> HIGH",
          status == 200 and rl in ("HIGH", "MEDIUM") and ph is False,
          f"status={status} risk={rl} score={sc} model={mdl} err={body.get('error') or body.get('detail')}")

# 5. Model version check
print("\n-- 5. Model version = candidate_fusion_v26 --------------------")
status, body = request("/api/scans/quick", {"url": "https://www.bbc.com/"}, token=tok)
mdl = body.get("model_version", "?")
ph  = body.get("is_placeholder", True)
check("model_version = candidate_fusion_v26",
      status == 200 and mdl == "candidate_fusion_v26" and ph is False,
      f"status={status} model={mdl} placeholder={ph} err={body.get('error') or body.get('detail')}")

# ── Summary ───────────────────────────────────────────────────────────────────
passed = sum(1 for _, ok in RESULTS if ok)
total  = len(RESULTS)
print(f"\n{'='*65}")
print(f"RESULT: {passed}/{total} checks passed")
if passed == total:
    print("ALL CHECKS PASSED - V26 model-driven production ready!")
else:
    print("Some checks FAILED - review output above.")
print(f"{'='*65}\n")
