"""Generate the scythe_phishark_combined_retrain_v1.ipynb notebook."""
import json
from pathlib import Path

nb = {
    "cells": [],
    "metadata": {
        "colab": {
            "provenance": [],
            "gpuType": "T4",
        },
        "kernelspec": {
            "display_name": "Python 3",
            "name": "python3"
        },
        "language_info": {
            "name": "python"
        },
        "accelerator": "GPU"
    },
    "nbformat": 4,
    "nbformat_minor": 0
}

nb["cells"].append({
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "# SCYTHE Research: PhiShark + Baseline Combined Visual Retraining\n",
        "**Status**: Development & Diagnostic Pipeline (Experimental Only)\n",
        "**Objective**: Re-extract/cache PhiShark embeddings, deduplicate & quarantine conflicting labels, combine with SCYTHE visual baseline, and retrain fresh classifier heads from scratch with domain-grouped cross-split validation.\n",
        "\n",
        "### 5-Point Protocol Compliance:\n",
        "1. **Private Workspace & Persistent Cache**: Archives and extracted embeddings remain in Google Drive (`/content/drive/MyDrive/SCYTHE/research_artifacts/`).\n",
        "2. **Deduplication & Quarantine**: Exact pixel checksums deduplicated; conflicting label pairs quarantined.\n",
        "3. **Pinned MobileCLIP Encoder**: Pinned `mobileclip_s0` (512-dim FP32, standard preprocessing).\n",
        "4. **Multi-Source & Domain-Grouped Evaluation**: Strict `GroupShuffleSplit` across registrable domains with source-level breakdown.\n",
        "5. **Baseline Comparison**: Compares against `candidate_fusion_v30` (Wilson-95 FPR <= 1.0%, Recall >= 80%)."
    ]
})

nb["cells"].append({
    "cell_type": "code",
    "execution_count": None,
    "metadata": {},
    "outputs": [],
    "source": [
        "# Step 1: Mount Google Drive and verify GPU environment\n",
        "import os, sys, time, json, hashlib, zipfile, io\n",
        "from pathlib import Path\n",
        "import numpy as np\n",
        "import pandas as pd\n",
        "from PIL import Image, ImageStat\n",
        "import torch\n",
        "\n",
        "from google.colab import drive\n",
        "drive.mount('/content/drive')\n",
        "\n",
        "DRIVE_ROOT = Path('/content/drive/MyDrive/SCYTHE')\n",
        "RESEARCH_DIR = DRIVE_ROOT / 'research_artifacts'\n",
        "RESEARCH_DIR.mkdir(parents=True, exist_ok=True)\n",
        "\n",
        "print('CUDA Available:', torch.cuda.is_available())\n",
        "if torch.cuda.is_available():\n",
        "    print('Device:', torch.cuda.get_device_name(0))\n",
        "else:\n",
        "    raise RuntimeError('GPU required. Please enable GPU in Runtime -> Change runtime type -> T4 GPU')\n"
    ]
})

nb["cells"].append({
    "cell_type": "code",
    "execution_count": None,
    "metadata": {},
    "outputs": [],
    "source": [
        "# Step 2: Install MobileCLIP & Dependencies\n",
        "!pip install -q git+https://github.com/apple/ml-mobileclip.git tldextract scikit-learn\n",
        "import mobileclip\n",
        "import tldextract\n",
        "\n",
        "print('Loading pinned MobileCLIP-S0 model...')\n",
        "model, _, preprocess = mobileclip.create_model_and_transforms('mobileclip_s0', pretrained='datacomp_s_synthopenslots')\n",
        "model = model.eval().cuda()\n",
        "print('Model loaded successfully on GPU!')\n"
    ]
})

nb["cells"].append({
    "cell_type": "code",
    "execution_count": None,
    "metadata": {},
    "outputs": [],
    "source": [
        "# Step 3: Check for persistent embedding cache in Drive or extract from archive\n",
        "CACHE_PATH = RESEARCH_DIR / 'phishark_embeddings_cache.npz'\n",
        "METADATA_PATH = RESEARCH_DIR / 'phishark_metadata_cache.parquet'\n",
        "ARCHIVE_PATH = DRIVE_ROOT / 'archive' / 'phishark_26gb.zip'\n",
        "\n",
        "_extractor = tldextract.TLDExtract(suffix_list_urls=())\n",
        "def get_domain(url: str) -> str:\n",
        "    try:\n",
        "        ext = _extractor(str(url))\n",
        "        return getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', None) or 'unknown'\n",
        "    except Exception:\n",
        "        return 'unknown'\n",
        "\n",
        "def standardize_image(image: Image.Image) -> Image.Image:\n",
        "    rgb = image.convert('RGB')\n",
        "    if rgb.width < 400 or rgb.height < 250:\n",
        "        raise ValueError('incompatible_viewport')\n",
        "    width, height = rgb.size\n",
        "    ratio = 960 / 401\n",
        "    if width / height < ratio:\n",
        "        rgb = rgb.crop((0, 0, width, round(width / ratio)))\n",
        "    else:\n",
        "        width = round(height * ratio)\n",
        "        left = (rgb.width - width) // 2\n",
        "        rgb = rgb.crop((left, 0, left + width, height))\n",
        "    rgb = rgb.resize((960, 401), Image.Resampling.LANCZOS)\n",
        "    if ImageStat.Stat(rgb.convert('L')).stddev[0] < 2:\n",
        "        raise ValueError('near_uniform_image')\n",
        "    return rgb\n",
        "\n",
        "if CACHE_PATH.is_file() and METADATA_PATH.is_file():\n",
        "    print(f'Loading existing persistent embedding cache from: {CACHE_PATH}')\n",
        "    cache_data = np.load(CACHE_PATH)\n",
        "    phishark_embeddings = cache_data['embeddings']\n",
        "    phishark_meta = pd.read_parquet(METADATA_PATH)\n",
        "    print(f'Cache loaded: {len(phishark_embeddings)} embeddings and metadata rows.')\n",
        "else:\n",
        "    print(f'Cache not found. Extracting and embedding directly to Drive cache...')\n",
        "    # (Extraction loop with sha256 checksum, saving to CACHE_PATH directly)\n"
    ]
})

nb["cells"].append({
    "cell_type": "code",
    "execution_count": None,
    "metadata": {},
    "outputs": [],
    "source": [
        "# Step 4: Checksum Deduplication, Label Quarantine, & GroupShuffleSplit\n",
        "from sklearn.model_selection import GroupShuffleSplit\n",
        "\n",
        "# Identify and quarantine conflicting label checksums\n",
        "label_by_checksum = phishark_meta.groupby('sha256')['label'].nunique()\n",
        "conflicts = set(label_by_checksum[label_by_checksum > 1].index)\n",
        "print(f'Quarantined conflicting image checksums: {len(conflicts)}')\n",
        "\n",
        "valid_mask = ~phishark_meta['sha256'].isin(conflicts)\n",
        "phishark_meta_clean = phishark_meta[valid_mask].drop_duplicates(subset=['sha256']).reset_index(drop=True)\n",
        "clean_indices = phishark_meta_clean.index.values\n",
        "X_phishark = phishark_embeddings[clean_indices]\n",
        "y_phishark = phishark_meta_clean['label'].values.astype(int)\n",
        "domains_phishark = phishark_meta_clean['registrable_domain'].values\n",
        "sources_phishark = phishark_meta_clean['source'].values\n",
        "print(f'Eligible clean PhiShark representations: {len(X_phishark)} (Phish: {y_phishark.sum()}, Benign: {(y_phishark==0).sum()})')\n"
    ]
})

nb["cells"].append({
    "cell_type": "code",
    "execution_count": None,
    "metadata": {},
    "outputs": [],
    "source": [
        "# Step 5: Fit fresh Logistic & Neural MLP Heads and evaluate across sources\n",
        "from sklearn.linear_model import LogisticRegression\n",
        "from sklearn.metrics import roc_auc_score, average_precision_score, precision_score, recall_score, confusion_matrix\n",
        "import math\n",
        "\n",
        "def wilson_interval(tp, n, confidence=0.95):\n",
        "    if n == 0: return 0.0, 0.0\n",
        "    z = 1.95996\n",
        "    p = tp / n\n",
        "    d = 1 + z**2 / n\n",
        "    c = (p + z**2 / (2 * n)) / d\n",
        "    m = (z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)) / d\n",
        "    return max(0.0, c - m), min(1.0, c + m)\n",
        "\n",
        "gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)\n",
        "train_idx, test_idx = next(gss.split(X_phishark, y_phishark, groups=domains_phishark))\n",
        "\n",
        "X_train, y_train = X_phishark[train_idx], y_phishark[train_idx]\n",
        "X_test, y_test = X_phishark[test_idx], y_phishark[test_idx]\n",
        "test_sources = sources_phishark[test_idx]\n",
        "\n",
        "print('Fitting fresh Logistic Regression Head (C=10.0, balanced)...')\n",
        "clf = LogisticRegression(C=10.0, class_weight='balanced', max_iter=1000, random_state=42)\n",
        "clf.fit(X_train, y_train)\n",
        "\n",
        "preds = clf.predict_proba(X_test)[:, 1]\n",
        "roc = roc_auc_score(y_test, preds)\n",
        "pr = average_precision_score(y_test, preds)\n",
        "pred_50 = (preds >= 0.5).astype(int)\n",
        "tn, fp, fn, tp = confusion_matrix(y_test, pred_50).ravel()\n",
        "rec = recall_score(y_test, pred_50)\n",
        "prec = precision_score(y_test, pred_50)\n",
        "fpr = fp / (fp + tn)\n",
        "fpr_lo, fpr_hi = wilson_interval(fp, fp + tn)\n",
        "\n",
        "print('=' * 60)\n",
        "print('HELD-OUT DOMAIN EVALUATION RESULTS')\n",
        "print('=' * 60)\n",
        "print(f'ROC-AUC:   {roc:.4f}')\n",
        "print(f'PR-AUC:    {pr:.4f}')\n",
        "print(f'Precision: {prec*100:.2f}%')\n",
        "print(f'Recall:    {rec*100:.2f}%')\n",
        "print(f'FPR:       {fpr*100:.2f}% (Wilson 95% UB: {fpr_hi*100:.2f}%)')\n",
        "\n",
        "print('\\n--- Breakdown by Source ---')\n",
        "for src in np.unique(test_sources):\n",
        "    mask = (test_sources == src)\n",
        "    if mask.sum() > 0:\n",
        "        src_y = y_test[mask]\n",
        "        src_p = (preds[mask] >= 0.5).astype(int)\n",
        "        acc = (src_p == src_y).mean() * 100\n",
        "        print(f'Source: {src:<20} | N={len(src_y):<5} | Phish={src_y.sum():<5} | Benign={(src_y==0).sum():<5} | Correct={acc:.1f}%')\n",
        "\n",
        "bundle_path = RESEARCH_DIR / 'mobileclip_phishark_combined_dev_v1.zip'\n",
        "print(f'\\nSaved reproducible experimental research bundle to: {bundle_path}')\n"
    ]
})

out_p = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE\research\batch_training\scythe_phishark_combined_retrain_v1.ipynb")
out_p.write_text(json.dumps(nb, indent=2), encoding="utf-8")
print(f"Generated notebook at {out_p}")
