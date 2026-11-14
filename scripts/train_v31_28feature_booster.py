"""Train SCYTHE 28-Feature LightGBM URL Classifier (V3 Contract) on the Full 400K+ Corpus.

- Features: 28 features (18 V2 + 10 V3 lexical/reputation/structural signals)
- Training Corpus: 429,920 unique URLs (PhiLegit-100K + URL-Phish v2 + UCI PhiUSIIL)
- Zero-Leakage: Excludes all 7,082 holdout domains from training & validation
- Holdout Evaluation: Evaluated on independent 7,082 holdout set
- Packaging: Builds release candidate candidate_fusion_v31 with full cryptographic verification
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
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
import tldextract

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
BACKEND = REPO / "containers" / "backend"
DATASET_ROOT = Path(r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset")
V30_DIR = REPO / "models" / "releases" / "candidate_fusion_v30"
OUT_DIR = REPO / "models" / "releases" / "candidate_fusion_v31"
OUT_DIR.mkdir(parents=True, exist_ok=True)

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from services.model_features.url_features import (
    FEATURE_NAMES_V3,
    build_url_feature_vector,
)
from services.model_release import sha256, verify_release

PHILEGIT_CSV = Path(r"C:\Users\armaa\Desktop\Project details\dataset-acquisition\philegit_100k_source_v1\contents_v1\PhiLegit-100K.csv")
URL_PHISH_V2_ZIP = Path(r"C:\Users\armaa\Desktop\Project details\dataset-acquisition\url_phish_v2_source\url_phish_v2.zip")
UCI_PARQUET = DATASET_ROOT / "manifest.parquet"
HOLDOUT_PATH = DATASET_ROOT / "candidate_fusion_v26_evaluation_passed" / "evidence" / "holdout.jsonl"

SEED = 42
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_registrable_domain(url: str) -> str:
    try:
        ext = _extractor(url)
        return getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", None) or ""
    except Exception:
        return ""


def load_holdout_domains() -> set[str]:
    domains = set()
    with open(HOLDOUT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                d = r.get("registrable_domain")
                if d:
                    domains.add(d.lower())
    print(f"Loaded {len(domains)} protected holdout domains to strictly exclude.")
    return domains


def _worker_extract_v3_chunk(chunk_urls: list[str]) -> list[list[float]]:
    import sys
    b_path = r"C:\Users\armaa\Desktop\Project details\SCYTHE\containers\backend"
    if b_path not in sys.path:
        sys.path.insert(0, b_path)
    from services.model_features.url_features import build_url_feature_vector, FEATURE_NAMES_V3

    res_list = []
    for u in chunk_urls:
        r = build_url_feature_vector(str(u), feature_names=FEATURE_NAMES_V3)
        if r and r.get("status") == "observed" and r.get("values"):
            res_list.append([0.0 if v is None else float(v) for v in r["values"]])
        else:
            res_list.append([0.0] * 28)
    return res_list


def extract_features_parallel(urls: list[str], n_workers: int = 12, chunk_size: int = 5000) -> np.ndarray:
    t0 = time.time()
    chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]
    all_features = []
    processed = 0

    with Pool(processes=n_workers) as pool:
        for chunk_res in pool.imap(_worker_extract_v3_chunk, chunks):
            all_features.extend(chunk_res)
            processed += len(chunk_res)
            if processed % 50000 == 0 or processed == len(urls):
                rate = processed / max(time.time() - t0, 0.01)
                print(f"  Extracted {processed:,}/{len(urls):,} URLs ({100*processed/len(urls):.1f}%) | rate={rate:,.0f}/s")

    print(f"Extraction complete in {time.time()-t0:.2f}s ({len(urls)/(time.time()-t0):,.0f} URLs/s)")
    return np.array(all_features, dtype=np.float32)


def main():
    t_start = time.time()
    print("=" * 70)
    print("SCYTHE V31: TRAINING 28-FEATURE LIGHTGBM BOOSTER ON 400K+ URL CORPUS")
    print("=" * 70)

    holdout_domains = load_holdout_domains()

    # 1. Load & Deduplicate Data
    print("\n[1/5] Loading datasets...")
    df_pl = pd.read_csv(PHILEGIT_CSV, usecols=["URL", "label_legit_1_phish_0"])
    df_pl["scythe_label"] = 1 - df_pl["label_legit_1_phish_0"]
    df_pl = df_pl.rename(columns={"URL": "url"})[["url", "scythe_label"]]

    with zipfile.ZipFile(URL_PHISH_V2_ZIP) as z:
        with z.open(z.namelist()[0]) as f:
            df_up = pd.read_csv(f, usecols=["url", "label"])
    df_up["scythe_label"] = df_up["label"]
    df_up = df_up[["url", "scythe_label"]]

    df_uci = pd.read_parquet(UCI_PARQUET, columns=["url", "label"])
    df_uci["scythe_label"] = df_uci["label"]
    df_uci = df_uci[["url", "scythe_label"]]

    combined = pd.concat([df_pl, df_up, df_uci], ignore_index=True)
    combined = combined.dropna(subset=["url", "scythe_label"])
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"].str.len() > 0]
    combined["scythe_label"] = combined["scythe_label"].astype(int)

    # Exclude holdout domains
    print("Resolving registrable domains for zero-leakage holdout exclusion...")
    combined["reg_domain"] = combined["url"].apply(get_registrable_domain)
    before_excl = len(combined)
    combined = combined[~combined["reg_domain"].str.lower().isin(holdout_domains)]
    print(f"Excluded {before_excl - len(combined):,} URLs matching holdout domains.")

    combined = combined.drop_duplicates(subset=["url", "scythe_label"])
    total_unique = len(combined)
    print(f"Total Unique Training Candidates: {total_unique:,}")
    print(f"Class Balance: {int((combined['scythe_label']==0).sum()):,} Benign (0) | {int((combined['scythe_label']==1).sum()):,} Phishing (1)")

    # Shuffle
    rng = np.random.default_rng(SEED)
    perm = rng.permutation(total_unique)
    urls_all = combined["url"].iloc[perm].tolist()
    y_all = combined["scythe_label"].iloc[perm].values.astype(np.int32)

    # 2. Extract 28 features in parallel
    print(f"\n[2/5] Parallel extraction of 28 V3 features across 12 workers...")
    n_workers = min(12, max(cpu_count() - 2, 2))
    X_all = extract_features_parallel(urls_all, n_workers=n_workers, chunk_size=5000)

    # 3. Train/Val Split (90/10)
    n_val = int(total_unique * 0.10)
    X_train, y_train = X_all[n_val:], y_all[n_val:]
    X_val, y_val = X_all[:n_val], y_all[:n_val]
    print(f"\nTrain set: {len(X_train):,} ({y_train.sum():,} phish, {(y_train==0).sum():,} benign)")
    print(f"Val set:   {len(X_val):,} ({y_val.sum():,} phish, {(y_val==0).sum():,} benign)")

    # 4. Train LightGBM Booster
    print(f"\n[3/5] Training 28-feature LightGBM booster...")
    model = lgb.LGBMClassifier(
        n_estimators=600,
        num_leaves=127,
        learning_rate=0.03,
        subsample=0.85,
        colsample_bytree=0.80,
        class_weight="balanced",
        reg_alpha=0.1,
        reg_lambda=0.5,
        random_state=SEED,
        n_jobs=-1,
        verbose=-1,
    )
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(100)],
    )

    # Validation Metrics
    val_probs = model.predict_proba(X_val)[:, 1]
    roc_val = roc_auc_score(y_val, val_probs)
    pr_val = average_precision_score(y_val, val_probs)
    brier_val = brier_score_loss(y_val, val_probs)
    val_pred = (val_probs >= 0.50).astype(int)
    acc_val = accuracy_score(y_val, val_pred)
    rec_val = recall_score(y_val, val_pred)
    prec_val = precision_score(y_val, val_pred)
    f1_val = f1_score(y_val, val_pred)

    print("\n" + "=" * 65)
    print(f"VALIDATION METRICS ({len(X_val):,} URLs):")
    print(f"  Accuracy:  {acc_val*100:.2f}%")
    print(f"  ROC-AUC:   {roc_val:.4f}")
    print(f"  PR-AUC:    {pr_val:.4f}")
    print(f"  Recall:    {rec_val*100:.2f}%")
    print(f"  Precision: {prec_val*100:.2f}%")
    print(f"  F1 Score:  {f1_val:.4f}")
    print(f"  Brier:     {brier_val:.4f}")

    # 5. Evaluate on Independent Holdout Set (7,082 URLs)
    print("\n[4/5] Evaluating on Independent 7,082 Zero-Leakage Holdout...")
    holdout_samples = []
    with open(HOLDOUT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                holdout_samples.append((r.get("canonical_url") or r.get("url"), int(r["label"])))

    h_urls = [u for u, _ in holdout_samples]
    h_y = np.array([lbl for _, lbl in holdout_samples], dtype=np.int32)
    h_X = np.array(_worker_extract_v3_chunk(h_urls), dtype=np.float32)

    h_probs = model.predict_proba(h_X)[:, 1]
    roc_h = roc_auc_score(h_y, h_probs)
    pr_h = average_precision_score(h_y, h_probs)
    brier_h = brier_score_loss(h_y, h_probs)
    h_pred = (h_probs >= 0.50).astype(int)
    acc_h = accuracy_score(h_y, h_pred)
    rec_h = recall_score(h_y, h_pred)
    prec_h = precision_score(h_y, h_pred)
    f1_h = f1_score(h_y, h_pred)
    tn_h, fp_h, fn_h, tp_h = confusion_matrix(h_y, h_pred).ravel()
    fpr_h = fp_h / (fp_h + tn_h)

    print(f"  Holdout Accuracy:  {acc_h*100:.2f}%")
    print(f"  Holdout ROC-AUC:   {roc_h:.4f}")
    print(f"  Holdout PR-AUC:    {pr_h:.4f}")
    print(f"  Holdout Recall:    {rec_h*100:.2f}% (TP={tp_h}, FN={fn_h})")
    print(f"  Holdout Precision: {prec_h*100:.2f}% (FP={fp_h})")
    print(f"  Holdout FPR:       {fpr_h*100:.2f}%")
    print(f"  Holdout F1 Score:  {f1_h:.4f}")

    # Threshold Operating Table on Holdout
    print("\nHOLDOUT OPERATING POINTS:")
    for th in [0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90]:
        p_th = (h_probs >= th).astype(int)
        tn, fp, fn, tp = confusion_matrix(h_y, p_th).ravel()
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"  th={th:.2f} -> Recall: {r*100:6.2f}% | Precision: {p*100:6.2f}% | FPR: {fp_rate*100:6.2f}% | TP={tp:<4} FP={fp:<4}")

    # 6. Save Model & Build Release Bundle candidate_fusion_v31
    print("\n[5/5] Packaging candidate_fusion_v31 release bundle...")

    # Copy shared files from v30
    for fname in ["quick_classifier.txt", "deep_classifier.txt", "visual_classifier.json",
                  "visual_feature_contract.json", "approved_policy.json", "threshold.json", "thresholds.json"]:
        src = V30_DIR / fname
        if src.is_file():
            shutil.copy2(src, OUT_DIR / fname)

    # Save url_classifier.txt (v31)
    url_model_path = OUT_DIR / "url_classifier.txt"
    model.booster_.save_model(str(url_model_path))
    url_model_sha256 = sha256(url_model_path)

    # Write url_feature_contract.json
    url_contract = {
        "features": list(FEATURE_NAMES_V3),
        "parameters": {
            "learning_rate": 0.03,
            "n_estimators": model.booster_.num_trees(),
            "name": "url_lgbm_leaves127_trees600_v31_28features",
            "num_leaves": 127,
            "n_features": 28,
        },
        "positive_label": 1,
        "scoring_backend": "lightgbm_native_booster",
        "selected_C": None,
        "selected_candidate": "url_lgbm_leaves127_trees600_v31_28features",
        "version": "url_classifier_v31",
        "model_name": "url_classifier_v31",
        "model_sha256": url_model_sha256,
        "training_rows": len(X_train),
        "validation_rows": len(X_val),
        "val_roc_auc": round(float(roc_val), 4),
        "val_pr_auc": round(float(pr_val), 4),
        "holdout_roc_auc": round(float(roc_h), 4),
        "holdout_pr_auc": round(float(pr_h), 4),
    }
    url_contract_path = OUT_DIR / "url_feature_contract.json"
    url_contract_path.write_text(json.dumps(url_contract, indent=2), encoding="utf-8")
    url_contract_sha256 = sha256(url_contract_path)

    # Update feature_contract.json
    fc_src = V30_DIR / "feature_contract.json"
    fc = json.loads(fc_src.read_text(encoding="utf-8"))
    vis_model_sha256 = sha256(OUT_DIR / "visual_classifier.json")
    vis_contract_sha256 = sha256(OUT_DIR / "visual_feature_contract.json")

    for path_key in ("deep_url", "quick_url"):
        fc["components_by_path"][path_key]["url"]["artifact_file"] = "url_classifier.txt"
        fc["components_by_path"][path_key]["url"]["artifact_sha256"] = url_model_sha256
        fc["components_by_path"][path_key]["url"]["contract_file"] = "url_feature_contract.json"
        fc["components_by_path"][path_key]["url"]["contract_sha256"] = url_contract_sha256
        fc["components_by_path"][path_key]["url"]["model_version"] = "url_classifier_v31"

        fc["components_by_path"][path_key]["visual"]["artifact_file"] = "visual_classifier.json"
        fc["components_by_path"][path_key]["visual"]["artifact_sha256"] = vis_model_sha256
        fc["components_by_path"][path_key]["visual"]["contract_file"] = "visual_feature_contract.json"
        fc["components_by_path"][path_key]["visual"]["contract_sha256"] = vis_contract_sha256
        fc["components_by_path"][path_key]["visual"]["model_version"] = "paired_visual_head_v2"

    fc_path = OUT_DIR / "feature_contract.json"
    fc_path.write_text(json.dumps(fc, indent=2), encoding="utf-8")
    fc_sha256 = sha256(fc_path)

    # Write release.json
    release_info = {
        "release_id": "candidate_fusion_v31",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "description": "SCYTHE V31: 28-feature unified LightGBM booster + Tranco Top-10k conditional filter",
        "url_classifier_sha256": url_model_sha256,
        "feature_contract_sha256": fc_sha256,
        "val_roc_auc": round(float(roc_val), 4),
        "holdout_roc_auc": round(float(roc_h), 4),
    }
    (OUT_DIR / "release.json").write_text(json.dumps(release_info, indent=2), encoding="utf-8")

    # Generate checksums.sha256
    manifest_lines = []
    for item in sorted(OUT_DIR.iterdir()):
        if item.is_file() and item.name != "checksums.sha256":
            h = sha256(item)
            manifest_lines.append(f"{h}  {item.name}")
    checksums_path = OUT_DIR / "checksums.sha256"
    checksums_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    bundle_digest = sha256(checksums_path)

    print(f"\nBundle Checksums Digest (SHA256): {bundle_digest}")
    print(f"Candidate v31 Directory: {OUT_DIR}")

    # Verify release
    ok = verify_release(OUT_DIR)
    print(f"Release Verification: {'PASS (100%)' if ok else 'FAIL'}")

    print("\n" + "=" * 70)
    print(f"TRAINING & QUALIFICATION COMPLETE IN {time.time()-t_start:.1f}s!")
    print("=" * 70)


if __name__ == "__main__":
    main()
