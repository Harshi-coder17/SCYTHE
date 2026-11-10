"""Test the actual v30 production URL classifier on 5,000+ real URLs.

Loads raw URLs from the prospective holdout validation dataset,
runs production feature extraction (18 features, Contract v2),
evaluates using the sealed candidate_fusion_v30 LightGBM booster,
and computes complete metrics, latency, and sample predictions.
"""
import sys
import time
import pathlib
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    precision_score,
    recall_score,
    accuracy_score,
    confusion_matrix,
    brier_score_loss,
)

ROOT = pathlib.Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
BACKEND = ROOT / "containers" / "backend"
sys.path.insert(0, str(BACKEND))

from services.model_features.url_features import build_url_feature_vector, FEATURE_NAMES_V2  # noqa: E402

DATA_PATH = pathlib.Path(
    r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset\prospective_collection_v1\url_candidate_v2\validation.parquet"
)
MODEL_PATH = ROOT / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt"


def main():
    print("=" * 75)
    print("SCYTHE V30 PRODUCTION URL CLASSIFIER: 5,000+ ACTUAL URLS BENCHMARK")
    print("=" * 75)

    # 1. Load Model
    assert MODEL_PATH.is_file(), f"Model file missing: {MODEL_PATH}"
    booster = lgb.Booster(model_file=str(MODEL_PATH))
    print(f"[*] Loaded v30 LightGBM booster ({booster.num_trees()} trees, {len(booster.feature_name())} features)")

    # 2. Load Dataset
    assert DATA_PATH.is_file(), f"Dataset missing: {DATA_PATH}"
    df = pd.read_parquet(DATA_PATH)
    print(f"[*] Loaded dataset from {DATA_PATH.name}: {len(df):,} total URLs available")

    # 3. Create a balanced 5,000 URL test set (2,500 benign, 2,500 phishing)
    benign_df = df[df["label"] == 0]
    phish_df = df[df["label"] == 1]
    print(f"    Available Benign: {len(benign_df):,} | Available Phishing: {len(phish_df):,}")

    n_sample_per_class = 2500
    sample_benign = benign_df.sample(n=n_sample_per_class, random_state=42)
    sample_phish = phish_df.sample(n=n_sample_per_class, random_state=42)

    test_5k = pd.concat([sample_benign, sample_phish]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    n_urls = len(test_5k)
    print(f"[*] Selected stratified benchmark set of {n_urls:,} actual URLs (2,500 benign, 2,500 phishing)\n")

    # 4. Feature Extraction & Scoring Loop
    print("[*] Running production feature extraction (18 features) and model inference...")
    start_time = time.perf_counter()

    feature_matrix = []
    valid_indices = []
    ground_truth = []
    failed_extractions = 0

    t_extract_start = time.perf_counter()
    for idx, row in test_5k.iterrows():
        raw_url = str(row["url"])
        label = int(row["label"])
        res = build_url_feature_vector(raw_url, feature_names=FEATURE_NAMES_V2)
        if res.get("status") == "observed" and res.get("values") is not None:
            feature_matrix.append(res["values"])
            valid_indices.append(idx)
            ground_truth.append(label)
        else:
            # Fallback for malformed URLs
            failed_extractions += 1

    t_extract_end = time.perf_counter()
    extract_time = t_extract_end - t_extract_start

    X = np.array(feature_matrix, dtype=np.float32)
    y_true = np.array(ground_truth, dtype=np.int32)

    t_infer_start = time.perf_counter()
    y_scores = booster.predict(X)
    t_infer_end = time.perf_counter()
    infer_time = t_infer_end - t_infer_start
    total_time = time.perf_counter() - start_time

    # 5. Evaluate Metrics at 0.5 Threshold and 0.8 Threshold
    threshold = 0.50
    y_pred = (y_scores >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    roc_auc = roc_auc_score(y_true, y_scores)
    pr_auc = average_precision_score(y_true, y_scores)
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    brier = brier_score_loss(y_true, y_scores)

    avg_extract_us = (extract_time / len(y_true)) * 1e6
    avg_infer_us = (infer_time / len(y_true)) * 1e6
    avg_total_us = (total_time / len(y_true)) * 1e6

    print("\n" + "=" * 75)
    print("BENCHMARK RESULTS ON 5,000 ACTUAL REAL-WORLD URLS")
    print("=" * 75)
    print(f"Total Evaluated URLs:        {len(y_true):,}")
    print(f"Ground Truth Distribution:   {tn + fp:,} Benign (Label 0), {tp + fn:,} Phishing (Label 1)")
    print(f"Extraction Success Rate:     {len(y_true) / n_urls * 100:.2f}% ({failed_extractions} malformed URLs dropped)")
    print("-" * 75)
    print(f"ROC-AUC:                     {roc_auc:.4f}  (Discrimination ability across all thresholds)")
    print(f"PR-AUC:                      {pr_auc:.4f}  (Precision-Recall Area under curve)")
    print(f"Accuracy:                    {acc * 100:.2f}% ({tp + tn:,} / {len(y_true):,} correct predictions)")
    print(f"Precision:                   {prec * 100:.2f}% ({tp:,} true phishing / {tp + fp:,} total flagged)")
    print(f"Recall (Sensitivity):        {rec * 100:.2f}% ({tp:,} detected / {tp + fn:,} actual phishing)")
    print(f"False Positive Rate (FPR):   {fpr * 100:.2f}% ({fp:,} false positives out of {tn + fp:,} benign URLs)")
    print(f"False Negative Rate (FNR):   {fnr * 100:.2f}% ({fn:,} missed phishing out of {tp + fn:,})")
    print(f"Brier Score (Calibration):   {brier:.4f}")
    print("-" * 75)
    print("Confusion Matrix:")
    print(f"  [TN: {tn:5,d}]  [FP: {fp:5,d}]  (Actual Benign:   {tn + fp:,})")
    print(f"  [FN: {fn:5,d}]  [TP: {tp:5,d}]  (Actual Phishing: {tp + fn:,})")
    print("-" * 75)
    print("Performance & Latency:")
    print(f"  Feature Extraction Latency: {avg_extract_us:.1f} microseconds / URL")
    print(f"  Model Inference Latency:    {avg_infer_us:.2f} microseconds / URL ({len(y_true) / infer_time:,.0f} URLs/sec)")
    print(f"  Total Pipeline Latency:     {avg_total_us:.1f} microseconds / URL ({len(y_true) / total_time:,.0f} URLs/sec)")
    print("=" * 75)

    # 6. Sample Predictions Inspection
    test_5k_valid = test_5k.iloc[valid_indices].copy()
    test_5k_valid["pred_score"] = y_scores
    test_5k_valid["predicted_label"] = y_pred

    print("\nSAMPLE CONFIRMED PHISHING DETECTIONS (Top Confidence):")
    sample_phish_detected = test_5k_valid[(test_5k_valid["label"] == 1) & (test_5k_valid["predicted_label"] == 1)].sort_values(
        by="pred_score", ascending=False
    ).head(10)
    for i, (_, r) in enumerate(sample_phish_detected.iterrows(), 1):
        print(f"  {i:2d}. Score: {r['pred_score']:.4f} | {r['url'][:75]}")

    print("\nSAMPLE CONFIRMED BENIGN SITES (Top Clean):")
    sample_benign_detected = test_5k_valid[(test_5k_valid["label"] == 0) & (test_5k_valid["predicted_label"] == 0)].sort_values(
        by="pred_score", ascending=True
    ).head(10)
    for i, (_, r) in enumerate(sample_benign_detected.iterrows(), 1):
        print(f"  {i:2d}. Score: {r['pred_score']:.4f} | {r['url'][:75]}")

    # 7. Also run on the FULL 21,997 holdout set
    print("\n" + "=" * 75)
    print(f"EVALUATING FULL UNTOUCHED HOLDOUT SET ({len(df):,} URLs)...")
    print("=" * 75)
    full_features = []
    full_labels = []
    for idx, row in df.iterrows():
        raw_url = str(row["url"])
        label = int(row["label"])
        res = build_url_feature_vector(raw_url, feature_names=FEATURE_NAMES_V2)
        if res.get("status") == "observed" and res.get("values") is not None:
            full_features.append(res["values"])
            full_labels.append(label)

    X_full = np.array(full_features, dtype=np.float32)
    y_full = np.array(full_labels, dtype=np.int32)
    scores_full = booster.predict(X_full)
    preds_full = (scores_full >= threshold).astype(int)

    tn_f, fp_f, fn_f, tp_f = confusion_matrix(y_full, preds_full).ravel()
    print(f"Full Set Total:             {len(y_full):,} URLs")
    print(f"Full ROC-AUC:               {roc_auc_score(y_full, scores_full):.4f}")
    print(f"Full PR-AUC:                {average_precision_score(y_full, scores_full):.4f}")
    print(f"Full Accuracy:              {accuracy_score(y_full, preds_full) * 100:.2f}%")
    print(f"Full Recall:                {recall_score(y_full, preds_full) * 100:.2f}% ({tp_f:,} / {tp_f + fn_f:,})")
    print(f"Full Precision:             {precision_score(y_full, preds_full) * 100:.2f}% ({tp_f:,} / {tp_f + fp_f:,})")
    print(f"Full False Positive Rate:   {fp_f / (fp_f + tn_f) * 100:.2f}% ({fp_f:,} / {tn_f + fp_f:,})")
    print(f"Confusion Matrix: [TN: {tn_f:,}, FP: {fp_f:,}, FN: {fn_f:,}, TP: {tp_f:,}]")
    print("=" * 75)


if __name__ == "__main__":
    main()
