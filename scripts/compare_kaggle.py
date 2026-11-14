import csv
import random
import numpy as np
import lightgbm as lgb
from pathlib import Path
from sklearn.metrics import (
    roc_auc_score, average_precision_score, precision_recall_fscore_support,
    accuracy_score, brier_score_loss
)

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
sys_backend = REPO / "containers" / "backend"
import sys; sys.path.insert(0, str(sys_backend))

from services.model_features.url_features import (
    build_url_feature_vector,
    FEATURE_NAMES_V2,
    FEATURE_NAMES_V3,
)

v30_path = REPO / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt"
v31_path = REPO / "models" / "releases" / "candidate_fusion_v31" / "url_classifier.txt"
b30 = lgb.Booster(model_file=str(v30_path))
b31 = lgb.Booster(model_file=str(v31_path))

# Find Kaggle 428k dataset
candidates = [
    Path(r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset\kaggle_400k_urls\malicious_phish.csv"),
    Path(r"C:\Users\armaa\Desktop\Project details\lightgbm_dataset\archive\malicious_phish.csv"),
    Path(r"C:\Users\armaa\Desktop\Project details\data\malicious_phish.csv"),
]
csv_path = next((p for p in candidates if p.is_file()), None)
if not csv_path:
    csv_path = next(Path(r"C:\Users\armaa\Desktop\Project details").rglob("*.csv"))

print("Reading CSV:", csv_path)

rows = []
with open(csv_path, encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    header = next(reader)
    for r in reader:
        if len(r) >= 2:
            url, t = r[0].strip(), r[1].strip().lower()
            label = 0 if t == "benign" else 1
            rows.append((url, label))

print(f"Total rows in CSV: {len(rows)}")

# Sample 15,000 URLs randomly with fixed seed 42
random.seed(42)
sample_rows = random.sample(rows, 15000)

y_true = []
feats_v30 = []
feats_v31 = []

for url, lbl in sample_rows:
    r2 = build_url_feature_vector(url, feature_names=FEATURE_NAMES_V2)
    r3 = build_url_feature_vector(url, feature_names=FEATURE_NAMES_V3)
    if r2.get("status") == "observed" and r3.get("status") == "observed":
        y_true.append(lbl)
        feats_v30.append(r2["values"])
        feats_v31.append(r3["values"])

y_true = np.array(y_true)
X30 = np.array(feats_v30)
X31 = np.array(feats_v31)

print(f"Extracted features for {len(y_true)} samples.")

pred_v30 = b30.predict(X30)
pred_v31 = b31.predict(X31)

def eval_m(y_t, y_p, thresh=0.5):
    y_pred_bin = (y_p >= thresh).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_t, y_pred_bin, average="binary", zero_division=0)
    acc = accuracy_score(y_t, y_pred_bin)
    roc = roc_auc_score(y_t, y_p)
    pr = average_precision_score(y_t, y_p)
    brier = brier_score_loss(y_t, y_p)
    fp = np.sum((y_pred_bin == 1) & (y_t == 0))
    tn = np.sum((y_pred_bin == 0) & (y_t == 0))
    fn = np.sum((y_pred_bin == 0) & (y_t == 1))
    tp = np.sum((y_pred_bin == 1) & (y_t == 1))
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    return {
        "roc_auc": roc, "pr_auc": pr, "accuracy": acc,
        "precision": p, "recall": r, "f1": f1,
        "brier": brier, "fpr": fpr, "fnr": fnr,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "total_benign": int(fp + tn), "total_phish": int(tp + fn)
    }

m30 = eval_m(y_true, pred_v30)
m31 = eval_m(y_true, pred_v31)

print("\n" + "=" * 80)
print("HEAD-TO-HEAD ON 15,000 SAMPLES FROM 428k URL CORPUS")
print("=" * 80)
print(f"{'Metric':<24} | {'V30 (18-feat, 250 trees)':<24} | {'V31 (28-feat, 600 trees)':<24} | Delta")
print("-" * 80)
for k in ["roc_auc", "pr_auc", "accuracy", "precision", "recall", "f1", "brier", "fpr", "fnr"]:
    v30_val = m30[k]
    v31_val = m31[k]
    delta = v31_val - v30_val
    sign = "+" if delta > 0 else ""
    print(f"{k:<24} | {v30_val:>24.4f} | {v31_val:>24.4f} | {sign}{delta:.4f}")

print("-" * 80)
print(f"{'False Positives':<24} | {m30['fp']:>18}/{m30['total_benign']} | {m31['fp']:>18}/{m31['total_benign']} | {m31['fp'] - m30['fp']:>+d}")
print(f"{'False Negatives (Misses)':<24} | {m30['fn']:>18}/{m30['total_phish']} | {m31['fn']:>18}/{m31['total_phish']} | {m31['fn'] - m30['fn']:>+d}")
print("=" * 80)
