"""Benchmark URL classifiers across release candidates v26, v27, v28, and v30.

Evaluates statistical metrics: ROC-AUC, PR-AUC, Precision, Recall, FPR,
and per-URL inference latency on held-out validation cohorts and challenge categories.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
DATASET_ROOT = Path(r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset")
BACKEND = REPO / "containers" / "backend"
sys.path.insert(0, str(BACKEND))

from services.model_features.url_features import (  # noqa: E402
    FEATURE_NAMES_V1,
    FEATURE_NAMES_V2,
    build_url_feature_vector,
)

CANDIDATES = {
    "v26": REPO / "models" / "releases" / "candidate_fusion_v26" / "url_classifier.txt",
    "v27": REPO / "models" / "releases" / "candidate_fusion_v27" / "url_classifier.txt",
    "v28": REPO / "models" / "releases" / "candidate_fusion_v28" / "url_classifier.txt",
    "v30": REPO / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt",
}

CHALLENGE_URLS = [
    ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", 0, "Enterprise SSO (Microsoft)"),
    ("https://accounts.google.com/signin/v2/identifier", 0, "Enterprise SSO (Google)"),
    ("https://github.com/login", 0, "Enterprise Developer (GitHub)"),
    ("https://portal.azure.com/", 0, "Cloud Management (Azure)"),
    ("https://www.wikipedia.org/", 0, "Top Informational (Wikipedia)"),
    ("https://www.amazon.com/gp/css/homepage.html", 0, "E-Commerce Portal (Amazon)"),
    ("http://paypal-verification-account.vercel.app/login.html", 1, "PaaS Phish (Vercel)"),
    ("https://cibc-online-portal.pages.dev/auth/update", 1, "PaaS Phish (Cloudflare Pages)"),
    ("https://metamask-recovery.workers.dev/", 1, "PaaS Phish (Cloudflare Workers)"),
    ("https://secure-apple-id.firebaseapp.com/", 1, "PaaS Phish (Firebase)"),
    ("http://192.168.1.1/admin/login.php", 1, "IP Hostname Admin"),
    ("http://45.33.32.156/banking/auth", 1, "Public Raw IP Phish"),
    ("http://xn--pypal-4ve.com/account/login", 1, "Cyrillic IDN Homoglyph"),
    ("https://bit.ly/3xY89zQ", 1, "Obfuscated URL Shortener"),
]


def load_boosters() -> dict[str, lgb.Booster]:
    boosters = {}
    for name, path in CANDIDATES.items():
        if not path.is_file():
            print(f"Warning: {path} not found")
            continue
        boosters[name] = lgb.Booster(model_file=str(path))
    return boosters


def extract_features(urls: list[str], feature_names: tuple[str, ...]) -> np.ndarray:
    rows = []
    n_feats = len(feature_names)
    for u in urls:
        res = build_url_feature_vector(str(u), feature_names=feature_names)
        if res and res.get("status") == "observed" and res.get("values"):
            vec = [0.0 if v is None else float(v) for v in res["values"]]
        else:
            vec = [0.0] * n_feats
        rows.append(vec)
    return np.array(rows, dtype=np.float32)


def main():
    print("=" * 75)
    print("SCYTHE URL BENCHMARK SUITE: v26 vs v27 vs v28 vs v30")
    print("=" * 75)

    boosters = load_boosters()
    for name, b in boosters.items():
        print(f"Loaded {name}: {b.num_feature()} features, {b.num_trees()} trees")

    # 1. Load validation dataset
    val_path = DATASET_ROOT / "prospective_collection_v1" / "url_candidate_v2" / "validation.parquet"
    if not val_path.exists():
        print(f"Dataset {val_path} not found")
        return

    print(f"\n[1/3] Loading holdout validation split ({val_path.name})...")
    df = pd.read_parquet(val_path)
    # Stratified subsample of 10,000 for fast benchmarking
    sample_size = min(10000, len(df))
    df_sample = df.sample(sample_size, random_state=42)
    urls = df_sample["url"].tolist()
    y_true = df_sample["label"].values.astype(int)

    n_phish = int(y_true.sum())
    n_benign = len(y_true) - n_phish
    print(f"Benchmarking on {len(y_true)} holdout URLs ({n_benign} benign, {n_phish} phishing)")

    # Pre-extract features for v1 (15 features) and v2 (18 features)
    print("\n[2/3] Extracting features...")
    t0 = time.time()
    X_v1 = extract_features(urls, FEATURE_NAMES_V1)
    X_v2 = extract_features(urls, FEATURE_NAMES_V2)
    ext_time = time.time() - t0
    print(f"Extracted {len(urls)} samples in {ext_time:.2f}s ({1000 * ext_time / len(urls):.3f} ms/URL)")

    # 2. Evaluate each booster
    print("\n[3/3] Model Performance Comparison:")
    print("-" * 88)
    print(f"{'Candidate':<12} | {'ROC-AUC':<8} | {'PR-AUC':<8} | {'Precision':<10} | {'Recall':<8} | {'FPR':<8} | {'Latency':<8}")
    print("-" * 88)

    results = {}
    for name, booster in boosters.items():
        X = X_v1 if booster.num_feature() == 15 else X_v2

        # Measure inference latency
        t_start = time.perf_counter()
        preds = booster.predict(X)
        total_inf_time = time.perf_counter() - t_start
        latency_ms = (total_inf_time / len(urls)) * 1000

        roc = roc_auc_score(y_true, preds)
        pr = average_precision_score(y_true, preds)

        # Standard operating threshold (0.50)
        binary_preds = (preds >= 0.50).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, binary_preds).ravel()
        prec = precision_score(y_true, binary_preds, zero_division=0)
        rec = recall_score(y_true, binary_preds, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        results[name] = {
            "roc_auc": roc,
            "pr_auc": pr,
            "precision": prec,
            "recall": rec,
            "fpr": fpr,
            "latency_ms": latency_ms,
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
        }

        print(f"{name:<12} | {roc:<8.4f} | {pr:<8.4f} | {prec * 100:<9.2f}% | {rec * 100:<7.2f}% | {fpr * 100:<7.2f}% | {latency_ms:.3f} ms")

    # 3. Challenge scenario tests
    print("\n" + "=" * 88)
    print("ADVERSARIAL & EDGE-CASE CHALLENGE TESTS")
    print("=" * 88)
    header = f"{'Scenario':<34} | {'v26':<8} | {'v27':<8} | {'v28':<8} | {'v30':<8} | True"
    print(header)
    print("-" * len(header))

    for raw_url, true_label, desc in CHALLENGE_URLS:
        row_str = f"{desc:<34}"
        for name, booster in boosters.items():
            fnames = FEATURE_NAMES_V1 if booster.num_feature() == 15 else FEATURE_NAMES_V2
            res = build_url_feature_vector(raw_url, feature_names=fnames)
            vec = [0.0 if v is None else float(v) for v in res["values"]] if res and res.get("values") else [0.0] * len(fnames)
            p = float(booster.predict([vec])[0])
            row_str += f" | {p:<8.4f}"
        row_str += f" | {true_label}"
        print(row_str)

    # Save benchmark report to JSON
    out_file = REPO / "docs" / "URL_CLASSIFIER_BENCHMARK_REPORT.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved structured benchmark to {out_file}")


if __name__ == "__main__":
    main()
