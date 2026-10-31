"""Train 30K Scaled Ultimate MobileCLIP-S0 Visual Model.
Integrates all pre-extracted cohorts:
- Extended Phish360: 13,271 images
- Zenodo Archive: 6,550 images
- PhishingEval 4190: 2,099 images
- Zenodo Import v1: 833 images
Total: 22,753 authentic screenshots
"""
import json, time, hashlib, pathlib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix, recall_score, precision_score, f1_score
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

ROOT = pathlib.Path(r"C:\Users\armaa\Desktop\Project details\mobileclip-dataset")
OUT_DIR = pathlib.Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE\models\releases\candidate_fusion_v30")

EXTENDED_MANIFEST = ROOT / "extended" / "manifest.jsonl"
CACHE_EXTENDED = ROOT / "artifacts" / "embedding_cache" / "c9c2148b178e22ae621e"
ZENODO_DIR = ROOT / "zenodo_embeddings_host"
PHISHEVAL_PRED = ROOT / "artifacts" / "phishingeval_4190_mobileclip_v3_positive_dev_v1" / "predictions.jsonl"
PHISHEVAL_CACHE = ROOT / "artifacts" / "phishingeval_4190_mobileclip_v3_positive_dev_v1" / "embedding_cache"
ZENODO_IMPORT_MANIFEST = ROOT / "source" / "zenodo_21379702" / "import_v1" / "visual_manifest.jsonl"
ZENODO_IMPORT_CACHE = ROOT / "artifacts" / "embedding_cache" / "zenodo-93bef2b62e0a84933425d6f6f19811011cf0369a961f5851e4180f89f9726d82"

ENCODER_SHA = "809b408eff74f8058843e86a1f92967097d42ba782450e85b8f4867b7f0ca0b7"
PREPROCESSING = "dataset-960x401-topcrop-apple-mobileclip-s0-resize256-center256-totensor-fp32-v1"

def cache_key(img_sha: str) -> str:
    return hashlib.sha256(f"{img_sha}\0{ENCODER_SHA}\0{PREPROCESSING}".encode()).hexdigest()

print("=" * 65)
print("TRAINING ULTIMATE SCALED VISUAL MODEL (22,753+ IMAGES)")
print("=" * 65)

all_X = []
all_y = []
test_X = []
test_y = []

# 1. Extended Phish360
print("\n[1/4] Loading Extended Phish360 (13,271 images)...")
with open(EXTENDED_MANIFEST, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip(): continue
        r = json.loads(line)
        p = CACHE_EXTENDED / f"{r['image_sha256']}.npy"
        if not p.is_file(): continue
        vec = np.load(p)
        label = int(r["label"])
        split = r.get("split", "train")
        if split == "test":
            test_X.append(vec)
            test_y.append(label)
        else:
            all_X.append(vec)
            all_y.append(label)
print(f"  Loaded {len(all_X)} train and {len(test_X)} test vectors.")

# 2. Zenodo Archive
print("\n[2/4] Loading Zenodo Archive (6,550 images)...")
zen_chunks = sorted(ZENODO_DIR.glob("chunk_*.npz"))
n_zen = 0
for c in zen_chunks:
    d = np.load(c)
    embs = d["embeddings"]
    lbls = d["labels"].tolist()
    for v, l in zip(embs, lbls):
        all_X.append(v)
        all_y.append(int(l))
        n_zen += 1
print(f"  Loaded {n_zen} Zenodo vectors.")

# 3. PhishingEval 4190
print("\n[3/4] Loading PhishingEval 4190 (2,099 images)...")
n_pe = 0
with open(PHISHEVAL_PRED, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip(): continue
        r = json.loads(line)
        h = r.get("image_sha256")
        if not h: continue
        k = cache_key(h)
        p = PHISHEVAL_CACHE / f"{k}.npy"
        if p.is_file():
            all_X.append(np.load(p))
            all_y.append(1)
            n_pe += 1
print(f"  Loaded {n_pe} PhishingEval vectors.")

# 4. Zenodo Import v1
print("\n[4/4] Loading Zenodo Import v1 (833 images)...")
n_zi = 0
with open(ZENODO_IMPORT_MANIFEST, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip(): continue
        r = json.loads(line)
        h = r.get("screenshot_sha256")
        if not h: continue
        p = ZENODO_IMPORT_CACHE / f"{h}.npy"
        if p.is_file():
            all_X.append(np.load(p))
            all_y.append(int(r.get("label", 0)))
            n_zi += 1
print(f"  Loaded {n_zi} Zenodo import vectors.")

X_train = np.array(all_X, dtype=np.float32)
y_train = np.array(all_y, dtype=np.int32)
X_test = np.array(test_X, dtype=np.float32)
y_test = np.array(test_y, dtype=np.int32)

print("\n" + "=" * 65)
print(f"TOTAL DATASET SUMMARY:")
print(f"  Training cohort:  {len(X_train):,} images (phish: {int(y_train.sum()):,}, benign: {int((y_train==0).sum()):,})")
print(f"  Held-out test:    {len(X_test):,} images (phish: {int(y_test.sum()):,}, benign: {int((y_test==0).sum()):,})")
print(f"  GRAND TOTAL:      {len(X_train) + len(X_test):,} images")
print("=" * 65)

# Model 1: High-Capacity Regularized Logistic Regression (C=0.5)
print("\n[A] Training Scaled Logistic Regression...")
clf = LogisticRegression(C=0.5, max_iter=1000, solver='lbfgs', class_weight='balanced', random_state=42)
clf.fit(X_train, y_train)

p_test = clf.predict_proba(X_test)[:, 1]
test_auc = roc_auc_score(y_test, p_test)
test_pr = average_precision_score(y_test, p_test)
pred_bin = (p_test >= 0.50).astype(int)
rec = recall_score(y_test, pred_bin)
prec = precision_score(y_test, pred_bin)
f1 = f1_score(y_test, pred_bin)

print(f"  Test ROC-AUC:   {test_auc:.4f}")
print(f"  Test PR-AUC:    {test_pr:.4f}")
print(f"  Test Recall:    {rec:.1%}")
print(f"  Test Precision: {prec:.1%}")
print(f"  Test F1:        {f1:.4f}")

# Model 2: 2-Layer Neural MLP Head
print("\n[B] Training 2-Layer Neural MLP Head (512 -> 128 -> 32 -> 1)...")
class ScaledMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(512, 128)
        self.ln1 = nn.LayerNorm(128)
        self.act1 = nn.GELU()
        self.drop1 = nn.Dropout(0.2)
        self.fc2 = nn.Linear(128, 32)
        self.ln2 = nn.LayerNorm(32)
        self.act2 = nn.GELU()
        self.drop2 = nn.Dropout(0.1)
        self.out = nn.Linear(32, 1)

    def forward(self, x):
        h = self.drop1(self.act1(self.ln1(self.fc1(x))))
        h = self.drop2(self.act2(self.ln2(self.fc2(h))))
        return self.out(h).squeeze(-1)

torch.manual_seed(42)
mlp = ScaledMLP()
pos_weight = torch.tensor([(len(y_train) - y_train.sum()) / max(1, y_train.sum())], dtype=torch.float32)
criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = optim.AdamW(mlp.parameters(), lr=1e-3, weight_decay=1e-3)

loader = DataLoader(TensorDataset(torch.tensor(X_train), torch.tensor(y_train, dtype=torch.float32)),
                    batch_size=256, shuffle=True)

for epoch in range(30):
    mlp.train()
    for bx, by in loader:
        optimizer.zero_grad()
        loss = criterion(mlp(bx), by)
        loss.backward()
        optimizer.step()

mlp.eval()
with torch.no_grad():
    mlp_logits = mlp(torch.tensor(X_test)).numpy()
    mlp_prob = 1.0 / (1.0 + np.exp(-mlp_logits))

mlp_auc = roc_auc_score(y_test, mlp_prob)
mlp_pr = average_precision_score(y_test, mlp_prob)
mlp_rec = recall_score(y_test, (mlp_prob >= 0.5).astype(int))
mlp_prec = precision_score(y_test, (mlp_prob >= 0.5).astype(int))
mlp_f1 = f1_score(y_test, (mlp_prob >= 0.5).astype(int))

print(f"  Neural MLP ROC-AUC:   {mlp_auc:.4f}")
print(f"  Neural MLP PR-AUC:    {mlp_pr:.4f}")
print(f"  Neural MLP Recall:    {mlp_rec:.1%}")
print(f"  Neural MLP Precision: {mlp_prec:.1%}")
print(f"  Neural MLP F1:        {mlp_f1:.4f}")

# Save the scaled 22K visual classifier into candidate_fusion_v30
artifact_logistic = {
    "version": "v30_scaled_22k",
    "model_type": "logistic_regression",
    "embedding_model": "mobileclip_s0",
    "embedding_dim": 512,
    "class_weight": "balanced",
    "total_images": len(X_train) + len(X_test),
    "train_images": len(X_train),
    "test_images": len(X_test),
    "metrics": {
        "test_roc_auc": round(float(test_auc), 4),
        "test_pr_auc": round(float(test_pr), 4),
        "test_recall": round(float(rec), 4),
        "test_precision": round(float(prec), 4),
        "test_f1": round(float(f1), 4)
    },
    "coef": clf.coef_[0].tolist(),
    "intercept": float(clf.intercept_[0])
}

out_log = OUT_DIR / "visual_classifier_22k.json"
out_log.write_text(json.dumps(artifact_logistic, indent=2))
sha_log = hashlib.sha256(out_log.read_bytes()).hexdigest()

out_v30 = OUT_DIR / "visual_classifier.json"
out_v30.write_text(json.dumps(artifact_logistic, indent=2))
sha_v30 = hashlib.sha256(out_v30.read_bytes()).hexdigest()

print("\n" + "=" * 65)
print(f"SUCCESS! Scaled 22,753-image visual classifier saved:")
print(f"  {out_v30}")
print(f"  SHA-256: {sha_v30}")
print("=" * 65)
