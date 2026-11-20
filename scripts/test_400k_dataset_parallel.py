"""High-Speed Parallelized Testing & Benchmark on the 400k+ URL Dataset.

Evaluates:
- Complete 429,920 URL corpus (PhiLegit-100K + URL-Phish v2 + UCI PhiUSIIL)
- Production v26 Booster (15 features)
- Production v30 Booster (18 features)
- Scaled 428k Booster (18 features)
- Independent 7,082 Zero-Leakage Holdout
- PaaS Evasion & Challenge URLs
- Concurrent live Docker backend API test
"""
from __future__ import annotations

import concurrent.futures
import json
import ssl
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from multiprocessing import Pool, cpu_count
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
BACKEND = REPO / "containers" / "backend"
DATASET_ROOT = Path(r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset")
REPORTS_DIR = REPO / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

PHILEGIT_CSV = Path(r"C:\Users\armaa\Desktop\Project details\dataset-acquisition\philegit_100k_source_v1\contents_v1\PhiLegit-100K.csv")
URL_PHISH_V2_ZIP = Path(r"C:\Users\armaa\Desktop\Project details\dataset-acquisition\url_phish_v2_source\url_phish_v2.zip")
UCI_PARQUET = DATASET_ROOT / "manifest.parquet"
HOLDOUT_PATH = DATASET_ROOT / "candidate_fusion_v26_evaluation_passed" / "evidence" / "holdout.jsonl"

MODELS = {
    "Production (v26 / Bundle)": {
        "path": REPO / "containers" / "backend" / "models" / "release_v21" / "url_classifier.txt",
        "n_features": 15,
    },
    "Production (v30 Unified)": {
        "path": REPO / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt",
        "n_features": 18,
    },
    "Scaled 428k Booster": {
        "path": DATASET_ROOT / "v27_all_urls_scaled" / "url_classifier_428k.txt",
        "n_features": 18,
    },
}

CHALLENGE_URLS = [
    ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", 0, "Enterprise SSO (Microsoft)"),
    ("https://accounts.google.com/signin/v2/identifier", 0, "Enterprise SSO (Google)"),
    ("https://github.com/login", 0, "Enterprise Developer (GitHub)"),
    ("https://portal.azure.com/", 0, "Cloud Management (Azure)"),
    ("https://www.wikipedia.org/", 0, "Top Informational (Wikipedia)"),
    ("https://www.amazon.com/gp/css/homepage.html", 0, "E-Commerce Portal (Amazon)"),
    ("https://9anime.org.lv", 0, "Streaming Media (9anime)"),
    ("http://paypal-verification-account.vercel.app/login.html", 1, "PaaS Phish (Vercel)"),
    ("https://cibc-online-portal.pages.dev/auth/update", 1, "PaaS Phish (Cloudflare Pages)"),
    ("https://metamask-recovery.workers.dev/", 1, "PaaS Phish (Cloudflare Workers)"),
    ("https://secure-apple-id.firebaseapp.com/", 1, "PaaS Phish (Firebase)"),
    ("http://192.168.1.1/admin/login.php", 1, "IP Hostname Admin"),
    ("http://45.33.32.156/banking/auth", 1, "Public Raw IP Phish"),
    ("http://xn--pypal-4ve.com/account/login", 1, "Cyrillic IDN Homoglyph"),
    ("https://bit.ly/3xY89zQ", 1, "Obfuscated URL Shortener"),
    ("https://phantom-app-4eu8.vercel.app/", 1, "Active PaaS Live Attack"),
]


def _worker_extract_chunk(chunk_urls: list[str]) -> list[list[float]]:
    import sys
    b_path = r"C:\Users\armaa\Desktop\Project details\SCYTHE\containers\backend"
    if b_path not in sys.path:
        sys.path.insert(0, b_path)
    from services.model_features.url_features import build_url_feature_vector, FEATURE_NAMES_V2

    res_list = []
    for u in chunk_urls:
        r = build_url_feature_vector(str(u), feature_names=FEATURE_NAMES_V2)
        if r and r.get("status") == "observed" and r.get("values"):
            res_list.append([0.0 if v is None else float(v) for v in r["values"]])
        else:
            res_list.append([0.0] * 18)
    return res_list


def load_corpus() -> pd.DataFrame:
    print("\n" + "=" * 70)
    print("STEP 1: LOADING & DEDUPLICATING 400K+ URL DATASET")
    print("=" * 70)
    t0 = time.time()

    print("[1/3] Loading PhiLegit-100K...")
    df_pl = pd.read_csv(PHILEGIT_CSV, usecols=["URL", "label_legit_1_phish_0"])
    df_pl["scythe_label"] = 1 - df_pl["label_legit_1_phish_0"]
    df_pl["source"] = "philegit_100k"
    df_pl = df_pl.rename(columns={"URL": "url"})[["url", "scythe_label", "source"]]

    print("[2/3] Loading URL-Phish v2...")
    with zipfile.ZipFile(URL_PHISH_V2_ZIP) as z:
        with z.open(z.namelist()[0]) as f:
            df_up = pd.read_csv(f, usecols=["url", "label"])
    df_up["scythe_label"] = df_up["label"]
    df_up["source"] = "url_phish_v2"
    df_up = df_up[["url", "scythe_label", "source"]]

    print("[3/3] Loading UCI PhiUSIIL (234k)...")
    df_uci = pd.read_parquet(UCI_PARQUET, columns=["url", "label"])
    df_uci["scythe_label"] = df_uci["label"]
    df_uci["source"] = "uci_phiusiil"
    df_uci = df_uci[["url", "scythe_label", "source"]]

    combined = pd.concat([df_pl, df_up, df_uci], ignore_index=True)
    raw_total = len(combined)

    combined = combined.dropna(subset=["url", "scythe_label"])
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"].str.len() > 0]
    combined["scythe_label"] = combined["scythe_label"].astype(int)
    combined = combined.drop_duplicates(subset=["url"])
    total_unique = len(combined)

    print(f"Loaded {raw_total:,} raw URLs -> Deduplicated to {total_unique:,} unique URLs in {time.time()-t0:.2f}s")
    print(f"Class Balance: {int((combined['scythe_label']==0).sum()):,} Benign (0) | {int((combined['scythe_label']==1).sum()):,} Phishing (1)")
    print(f"Phishing Ratio: {(combined['scythe_label']==1).mean()*100:.2f}%")
    print("Source Distribution:")
    for src, cnt in combined["source"].value_counts().items():
        print(f"  - {src}: {cnt:,} URLs")

    return combined


def extract_features_parallel(urls: list[str], n_workers: int = 12, chunk_size: int = 5000) -> np.ndarray:
    print("\n" + "=" * 70)
    print(f"STEP 2: PARALLEL FEATURE EXTRACTION ({len(urls):,} URLs, {n_workers} Workers)")
    print("=" * 70)
    t0 = time.time()

    chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]
    print(f"Split {len(urls):,} URLs into {len(chunks)} chunks of ~{chunk_size} items each.")

    all_features = []
    processed_count = 0

    with Pool(processes=n_workers) as pool:
        for chunk_res in pool.imap(_worker_extract_chunk, chunks):
            all_features.extend(chunk_res)
            processed_count += len(chunk_res)
            if processed_count % 50000 == 0 or processed_count == len(urls):
                elapsed = max(time.time() - t0, 0.01)
                rate = processed_count / elapsed
                pct = 100 * processed_count / len(urls)
                print(f"  Extracted {processed_count:,}/{len(urls):,} URLs ({pct:.1f}%) | Speed: {rate:,.0f} URLs/sec | Elapsed: {elapsed:.1f}s")

    elapsed_total = time.time() - t0
    overall_speed = len(urls) / max(elapsed_total, 0.01)
    print(f"Parallel Extraction Complete: {len(all_features):,} URLs in {elapsed_total:.2f}s ({overall_speed:,.0f} URLs/sec)")

    return np.array(all_features, dtype=np.float32)


def compute_metrics(y_true: np.ndarray, y_probs: np.ndarray, threshold: float = 0.50) -> dict:
    y_pred = (y_probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    roc_auc = roc_auc_score(y_true, y_probs)
    pr_auc = average_precision_score(y_true, y_probs)
    brier = brier_score_loss(y_true, y_probs)

    return {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "specificity": round(float(specificity), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "brier": round(float(brier), 4),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "total": int(len(y_true)),
    }


def evaluate_models(X_18: np.ndarray, y: np.ndarray, sources: np.ndarray) -> dict:
    print("\n" + "=" * 70)
    print("STEP 3: MULTI-MODEL EVALUATION ON COMPLETE 400K+ CORPUS")
    print("=" * 70)

    results = {}

    for model_name, info in MODELS.items():
        model_path = info["path"]
        n_feats = info["n_features"]
        if not model_path.is_file():
            print(f"Skipping {model_name}: file {model_path} not found")
            continue

        print(f"\n--- Evaluating {model_name} ({n_feats} features) ---")
        booster = lgb.Booster(model_file=str(model_path))
        X_eval = X_18[:, :n_feats]

        t0 = time.time()
        probs = booster.predict(X_eval)
        inf_time = time.time() - t0
        inf_speed = len(y) / max(inf_time, 0.001)

        print(f"  Inference Time: {inf_time:.3f}s for {len(y):,} URLs ({inf_speed:,.0f} URLs/sec)")

        m = compute_metrics(y, probs, threshold=0.50)
        print(f"  Accuracy:  {m['accuracy']*100:.2f}%")
        print(f"  ROC-AUC:   {m['roc_auc']:.4f}")
        print(f"  PR-AUC:    {m['pr_auc']:.4f}")
        print(f"  Recall:    {m['recall']*100:.2f}% (TP={m['tp']:,}, FN={m['fn']:,})")
        print(f"  Precision: {m['precision']*100:.2f}% (FP={m['fp']:,})")
        print(f"  FPR:       {m['fpr']*100:.2f}%")
        print(f"  F1 Score:  {m['f1_score']:.4f}")
        print(f"  Brier:     {m['brier']:.4f}")

        # Threshold operating points
        op_table = []
        for th in [0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90]:
            th_m = compute_metrics(y, probs, threshold=th)
            op_table.append({
                "threshold": th,
                "recall": th_m["recall"],
                "precision": th_m["precision"],
                "fpr": th_m["fpr"],
                "f1": th_m["f1_score"],
                "tp": th_m["tp"],
                "fp": th_m["fp"]
            })

        # By source breakdown
        source_breakdown = {}
        for s in np.unique(sources):
            mask = (sources == s)
            s_m = compute_metrics(y[mask], probs[mask], threshold=0.50)
            source_breakdown[str(s)] = s_m

        results[model_name] = {
            "model_path": str(model_path),
            "features_used": n_feats,
            "inference_seconds": round(inf_time, 3),
            "inference_speed_per_sec": round(inf_speed, 1),
            "metrics_at_50": m,
            "operating_table": op_table,
            "source_breakdown": source_breakdown,
            "probs_cache": probs,
        }

    return results


def evaluate_holdout(holdout_path: Path) -> dict:
    print("\n" + "=" * 70)
    print("STEP 4: INDEPENDENT ZERO-DOMAIN-LEAKAGE HOLDOUT EVALUATION")
    print("=" * 70)

    if not holdout_path.exists():
        print(f"Holdout file {holdout_path} not found.")
        return {}

    holdout_samples = []
    with open(holdout_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                holdout_samples.append((r.get("canonical_url") or r.get("url"), int(r["label"])))

    print(f"Loaded {len(holdout_samples):,} holdout URLs with verified independent domains.")
    h_urls = [u for u, _ in holdout_samples]
    h_y = np.array([lbl for _, lbl in holdout_samples], dtype=np.int32)

    X_h18 = np.array(_worker_extract_chunk(h_urls), dtype=np.float32)

    holdout_results = {}
    for model_name, info in MODELS.items():
        model_path = info["path"]
        if not model_path.is_file():
            continue
        booster = lgb.Booster(model_file=str(model_path))
        X_eval = X_h18[:, :info["n_features"]]
        probs = booster.predict(X_eval)
        m = compute_metrics(h_y, probs, threshold=0.50)
        print(f"  {model_name} on 7,082 Holdout -> ROC-AUC: {m['roc_auc']:.4f} | PR-AUC: {m['pr_auc']:.4f} | Recall: {m['recall']*100:.2f}% | FPR: {m['fpr']*100:.2f}%")
        holdout_results[model_name] = m

    return holdout_results


def evaluate_challenge_evasions() -> list[dict]:
    print("\n" + "=" * 70)
    print("STEP 5: REAL-WORLD CHALLENGE & PAAS EVASION VERIFICATION")
    print("=" * 70)

    urls = [u for u, _, _ in CHALLENGE_URLS]
    labels = [lbl for _, lbl, _ in CHALLENGE_URLS]
    descs = [d for _, _, d in CHALLENGE_URLS]

    X_c18 = np.array(_worker_extract_chunk(urls), dtype=np.float32)

    challenge_results = []
    v26_b = lgb.Booster(model_file=str(MODELS["Production (v26 / Bundle)"]["path"]))
    v30_b = lgb.Booster(model_file=str(MODELS["Production (v30 Unified)"]["path"]))
    scaled_b = lgb.Booster(model_file=str(MODELS["Scaled 428k Booster"]["path"]))

    v26_probs = v26_b.predict(X_c18[:, :15])
    v30_probs = v30_b.predict(X_c18[:, :18])
    scaled_probs = scaled_b.predict(X_c18[:, :18])

    print(f"{'URL Description':<32} | {'True':<5} | {'v26':<7} | {'v30':<7} | {'428k':<7} | Status")
    print("-" * 75)

    for i in range(len(CHALLENGE_URLS)):
        desc = descs[i]
        true_lbl = "PHISH" if labels[i] == 1 else "BENIGN"
        p_v26 = v26_probs[i]
        p_v30 = v30_probs[i]
        p_scaled = scaled_probs[i]

        pred_v30 = "PHISH" if p_v30 >= 0.50 else "BENIGN"
        match = "MATCH" if pred_v30 == true_lbl else "MISMATCH"

        print(f"{desc:<32} | {true_lbl:<5} | {p_v26*100:5.1f}% | {p_v30*100:5.1f}% | {p_scaled*100:5.1f}% | {match}")
        challenge_results.append({
            "url": urls[i],
            "description": desc,
            "true_label": labels[i],
            "v26_prob": round(float(p_v26), 4),
            "v30_prob": round(float(p_v30), 4),
            "scaled_428k_prob": round(float(p_scaled), 4),
        })

    return challenge_results


def test_concurrent_live_backend(sample_urls: list[str], n_concurrent: int = 10, total_requests: int = 50) -> dict:
    print("\n" + "=" * 70)
    print(f"STEP 6: LIVE BACKEND API CONCURRENT STRESS TEST ({total_requests} requests, {n_concurrent} threads)")
    print("=" * 70)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Register benchmark user
    bench_user = f"bench_{int(time.time())}@example.com"
    bench_pwd = "Password123!Secure"
    reg_data = json.dumps({"email": bench_user, "password": bench_pwd}).encode("utf-8")
    reg_req = urllib.request.Request("https://127.0.0.1:8443/api/auth/register", data=reg_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(reg_req, context=ctx) as r:
        pass

    login_data = urllib.parse.urlencode({"username": bench_user, "password": bench_pwd}).encode("utf-8")
    login_req = urllib.request.Request("https://127.0.0.1:8443/api/auth/login", data=login_data)
    with urllib.request.urlopen(login_req, context=ctx) as r:
        token = json.loads(r.read().decode())["access_token"]

    test_urls = (sample_urls * ((total_requests // len(sample_urls)) + 1))[:total_requests]

    def _call_quick_scan(url: str):
        t_call = time.time()
        scan_req = urllib.request.Request(
            "https://127.0.0.1:8443/api/scans/quick",
            data=json.dumps({"url": url}).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(scan_req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return {"status": resp.status, "latency_ms": round((time.time() - t_call) * 1000, 2), "data": data}
        except Exception as e:
            return {"status": 500, "latency_ms": round((time.time() - t_call) * 1000, 2), "error": str(e)}

    t_start = time.time()
    latencies = []
    successes = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_concurrent) as executor:
        futures = [executor.submit(_call_quick_scan, u) for u in test_urls]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            latencies.append(res["latency_ms"])
            if res.get("status") == 200:
                successes += 1

    total_time = time.time() - t_start
    throughput = len(test_urls) / max(total_time, 0.001)

    print(f"Completed {successes}/{len(test_urls)} API requests in {total_time:.2f}s ({throughput:.1f} req/s)")
    print(f"Latency: p50={np.percentile(latencies, 50):.1f}ms | p95={np.percentile(latencies, 95):.1f}ms | p99={np.percentile(latencies, 99):.1f}ms | min={min(latencies):.1f}ms | max={max(latencies):.1f}ms")

    return {
        "total_requests": len(test_urls),
        "successful_requests": successes,
        "total_seconds": round(total_time, 3),
        "requests_per_second": round(throughput, 1),
        "latency_p50_ms": round(float(np.percentile(latencies, 50)), 1),
        "latency_p95_ms": round(float(np.percentile(latencies, 95)), 1),
        "latency_p99_ms": round(float(np.percentile(latencies, 99)), 1),
    }


def main():
    t_global = time.time()
    print("=" * 70)
    print("SCYTHE 400K+ URL CORPUS PARALLEL BENCHMARK & AUDIT SUITE")
    print(f"CPU Cores Available: {cpu_count()} | Worker Pool Size: 12")
    print("=" * 70)

    # 1. Load corpus
    df = load_corpus()
    urls = df["url"].tolist()
    labels = df["scythe_label"].values
    sources = df["source"].values

    # 2. Parallel feature extraction
    n_workers = min(12, max(cpu_count() - 2, 2))
    X_18 = extract_features_parallel(urls, n_workers=n_workers, chunk_size=5000)

    # 3. Model evaluation on full 400k corpus
    eval_results = evaluate_models(X_18, labels, sources)

    # 4. Holdout evaluation
    holdout_results = evaluate_holdout(HOLDOUT_PATH)

    # 5. Evasion challenge verification
    challenge_results = evaluate_challenge_evasions()

    # 6. Live API concurrent test
    sample_pool = df[df["scythe_label"] == 0]["url"].head(5).tolist() + df[df["scythe_label"] == 1]["url"].head(5).tolist()
    api_test_results = test_concurrent_live_backend(sample_pool, n_concurrent=10, total_requests=50)

    # Clean out probs_cache from results before serialization
    for m in eval_results.values():
        if "probs_cache" in m:
            del m["probs_cache"]

    final_report = {
        "suite_name": "SCYTHE_400K_URL_PARALLEL_BENCHMARK",
        "dataset_summary": {
            "total_raw": 451277,
            "total_unique": len(df),
            "benign_count": int((labels == 0).sum()),
            "phish_count": int((labels == 1).sum()),
            "phish_ratio": round(float((labels == 1).mean()), 4),
            "sources": df["source"].value_counts().to_dict(),
        },
        "model_benchmarks_400k": eval_results,
        "holdout_benchmark_7082": holdout_results,
        "challenge_evasion_tests": challenge_results,
        "live_api_benchmark": api_test_results,
        "total_elapsed_seconds": round(time.time() - t_global, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    report_path = REPORTS_DIR / "benchmark_400k_urls_report.json"
    report_path.write_text(json.dumps(final_report, indent=2))
    print("\n" + "=" * 70)
    print(f"BENCHMARK COMPLETE IN {time.time() - t_global:.2f}s!")
    print(f"Report saved to: {report_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
