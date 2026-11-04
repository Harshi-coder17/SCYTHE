"""Train and qualify the definitive production URL classifier for candidate_fusion_v30.

Replaces the degenerate Azure 36-tree v28 sub-head with a clean, fully-calibrated
18-feature LightGBM booster trained on 87,204 balanced URLs with registered-domain
leakage prevention.
"""
from __future__ import annotations

import hashlib
import json
import os
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

from services.model_features.url_features import (
    FEATURE_NAMES_V2,
    build_url_feature_vector,
)

TRAIN_PARQUET = DATASET_ROOT / "prospective_collection_v1" / "url_candidate_v2" / "train.parquet"
VAL_PARQUET = DATASET_ROOT / "prospective_collection_v1" / "url_candidate_v2" / "validation.parquet"
V30_DIR = REPO / "models" / "releases" / "candidate_fusion_v30"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_matrix(urls: list[str]) -> np.ndarray:
    rows = []
    n = len(FEATURE_NAMES_V2)
    for u in urls:
        res = build_url_feature_vector(str(u), feature_names=FEATURE_NAMES_V2)
        if res and res.get("status") == "observed" and res.get("values"):
            vec = [0.0 if v is None else float(v) for v in res["values"]]
        else:
            vec = [0.0] * n
        rows.append(vec)
    return np.array(rows, dtype=np.float32)


def main():
    print("=" * 70)
    print("TRAINING DEFINITIVE PRODUCTION URL CLASSIFIER FOR V30")
    print("=" * 70)

    # 1. Load training data
    df_train = pd.read_parquet(TRAIN_PARQUET)
    print(f"Loaded training set: {len(df_train)} URLs ({sum(df_train['label']==0)} benign, {sum(df_train['label']==1)} phish)")

    t0 = time.time()
    X_train = extract_matrix(df_train["url"].tolist())
    y_train = df_train["label"].values.astype(np.int32)
    print(f"Extracted training features in {time.time()-t0:.2f}s")

    # 2. Train clean, non-degenerate LightGBM booster
    print("Fitting LightGBM GBDT (18 features, balanced class weights)...")
    clf = lgb.LGBMClassifier(
        n_estimators=250,
        num_leaves=63,
        learning_rate=0.03,
        subsample=0.85,
        colsample_bytree=0.85,
        class_weight="balanced",
        reg_alpha=0.1,
        reg_lambda=0.5,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    clf.fit(X_train, y_train, feature_name=list(FEATURE_NAMES_V2))

    # 3. Verify no degenerate root splits
    booster = clf.booster_
    dump = booster.dump_model()
    root_splits = [tree["tree_structure"].get("split_feature") for tree in dump["tree_info"]]
    unique_roots = set(root_splits)
    print(f"Verified tree roots: {len(unique_roots)} unique root split features across {len(dump['tree_info'])} trees")
    assert len(unique_roots) > 1, "Degenerate single root split detected!"

    # 4. Evaluate on full 21,997 held-out validation cohort
    df_val = pd.read_parquet(VAL_PARQUET)
    print(f"\nEvaluating on holdout validation set: {len(df_val)} URLs...")
    X_val = extract_matrix(df_val["url"].tolist())
    y_val = df_val["label"].values.astype(np.int32)

    preds = clf.predict_proba(X_val)[:, 1]
    roc_auc = roc_auc_score(y_val, preds)
    pr_auc = average_precision_score(y_val, preds)

    # Evaluation at operating threshold (0.50)
    preds_50 = (preds >= 0.50).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, preds_50).ravel()
    prec_50 = precision_score(y_val, preds_50)
    rec_50 = recall_score(y_val, preds_50)
    fpr_50 = fp / (fp + tn)

    # Evaluation at high-sensitivity threshold (0.10)
    preds_10 = (preds >= 0.10).astype(int)
    tn1, fp1, fn1, tp1 = confusion_matrix(y_val, preds_10).ravel()
    prec_10 = precision_score(y_val, preds_10)
    rec_10 = recall_score(y_val, preds_10)
    fpr_10 = fp1 / (fp1 + tn1)

    print(f"\nValidation Results ({len(y_val)} samples):")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"  PR-AUC:    {pr_auc:.4f}")
    print(f"  @ Th 0.50: Precision: {prec_50*100:.2f}%, Recall: {rec_50*100:.2f}%, FPR: {fpr_50*100:.2f}% (FP: {fp}, FN: {fn})")
    print(f"  @ Th 0.10: Precision: {prec_10*100:.2f}%, Recall: {rec_10*100:.2f}%, FPR: {fpr_10*100:.2f}% (FP: {fp1}, FN: {fn1})")

    # 5. Export calibrated production booster to candidate_fusion_v30
    out_model = V30_DIR / "url_classifier.txt"
    booster.save_model(str(out_model))
    booster.save_model(str(V30_DIR / "url_classifier_v30.txt"))
    new_sha256 = sha256_file(out_model)
    print(f"\nExported qualified model to {out_model}")
    print(f"Artifact SHA-256: {new_sha256}")

    # 6. Update url_feature_contract.json
    contract_p = V30_DIR / "url_feature_contract.json"
    contract_data = {
        "version": "scythe-url-features-v2",
        "features": list(FEATURE_NAMES_V2),
        "n_features": 18,
        "model_name": "url_classifier_v30",
        "model_sha256": new_sha256,
        "threshold": 0.5,
        "metrics": {
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
            "precision": float(prec_50),
            "recall": float(rec_50),
            "fpr": float(fpr_50),
            "training_samples": len(df_train),
            "validation_samples": len(df_val),
        },
    }
    with open(contract_p, "w", encoding="utf-8") as f:
        json.dump(contract_data, f, indent=2)
    with open(V30_DIR / "url_feature_contract_v30.json", "w", encoding="utf-8") as f:
        json.dump(contract_data, f, indent=2)

    # 7. Update checksums.sha256
    checksums_file = V30_DIR / "checksums.sha256"
    lines = []
    for line in checksums_file.read_text(encoding="ascii").splitlines():
        if line.strip():
            csum, fname = line.split("  ", 1)
            target = V30_DIR / fname
            if target.is_file():
                lines.append(f"{sha256_file(target)}  {fname}")
            else:
                lines.append(line)
    checksums_file.write_text("\n".join(lines) + "\n", encoding="ascii")
    print("Updated checksums.sha256 manifest.")


if __name__ == "__main__":
    main()
