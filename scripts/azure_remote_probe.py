import json
import urllib.request

def main():
    results = {"openphish": [], "phishstats": []}
    
    # 1. OpenPhish live feed
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "SCYTHE-Cloud-Test/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            results["openphish"] = [l.strip() for l in lines if l.strip().startswith("http")][:10]
    except Exception as e:
        results["openphish_err"] = str(e)

    # 2. PhishStats live feed
    try:
        req = urllib.request.Request("https://phishstats.info:2096/api/v3/recent?_limit=10", headers={"User-Agent": "SCYTHE-Cloud-Test/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            results["phishstats"] = [item["url"] for item in data if isinstance(item, dict) and "url" in item]
    except Exception as e:
        results["phishstats_err"] = str(e)

    output = {
        "status": "live_cloud_probe_success",
        "openphish_fresh_count": len(results["openphish"]),
        "openphish_samples": results["openphish"][:3],
        "phishstats_fresh_count": len(results["phishstats"]),
        "phishstats_samples": results["phishstats"][:3]
    }
    print(json.dumps(output))

if __name__ == "__main__":
    main()
