"""Extract MobileCLIP-S0 embeddings for candidate_fusion_v25_qualification and holdout images.
Saves .npy files to embedding_cache/v25_cohorts/<image_sha256>.npy
"""
import sys, time, os
from pathlib import Path
from PIL import Image
import torch
import numpy as np

sys.path.insert(0, r"C:\Users\armaa\Desktop\Project details\mobileclip-dataset\vendor\ml-mobileclip")
import mobileclip

ROOT = Path(r"C:\Users\armaa\Desktop\Project details")
LGB_ROOT = ROOT / "lightgbm_dataset"
OUT_DIR = ROOT / "mobileclip-dataset" / "artifacts" / "embedding_cache" / "v25_cohorts"
OUT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT = ROOT / "mobileclip-dataset" / "checkpoints" / "mobileclip_s0.pt"

print(f"Loading MobileCLIP-S0 from {CHECKPOINT}...")
model, _, preprocess = mobileclip.create_model_and_transforms("mobileclip_s0", pretrained=str(CHECKPOINT))
model.eval()

# Gather images from both qualification and holdout
q_imgs = list((LGB_ROOT / "candidate_fusion_v25_qualification" / "images").glob("*.png"))
h_imgs = list((LGB_ROOT / "candidate_fusion_v25_holdout" / "images").glob("*.png"))
all_imgs = sorted(list(set(q_imgs + h_imgs)), key=lambda p: p.name)

to_process = []
for p in all_imgs:
    out_npy = OUT_DIR / f"{p.stem}.npy"
    if not out_npy.is_file():
        to_process.append(p)

print(f"Total target images: {len(all_imgs)}, already extracted: {len(all_imgs) - len(to_process)}, to process: {len(to_process)}")

BATCH_SIZE = 64
n_done = 0
t0 = time.time()

for i in range(0, len(to_process), BATCH_SIZE):
    batch_paths = to_process[i:i+BATCH_SIZE]
    batch_tensors = []
    valid_paths = []
    
    for p in batch_paths:
        try:
            with Image.open(p) as img:
                img_rgb = img.convert("RGB")
                batch_tensors.append(preprocess(img_rgb))
                valid_paths.append(p)
        except Exception:
            continue
            
    if not batch_tensors:
        continue
        
    batch = torch.stack(batch_tensors)
    with torch.no_grad():
        embs = model.encode_image(batch)
        embs /= embs.norm(dim=-1, keepdim=True)
        embs_np = embs.cpu().numpy()
        
    for p, emb in zip(valid_paths, embs_np):
        out_npy = OUT_DIR / f"{p.stem}.npy"
        np.save(out_npy, emb)
        
    n_done += len(valid_paths)
    elapsed = time.time() - t0
    rate = n_done / max(0.1, elapsed)
    eta_sec = (len(to_process) - n_done) / max(0.1, rate)
    if (i // BATCH_SIZE) % 10 == 0 or n_done == len(to_process):
        print(f"Progress: {n_done}/{len(to_process)} ({n_done/len(to_process)*100:.1f}%) | Speed: {rate:.1f} img/s | ETA: {eta_sec/60:.1f} min", flush=True)

print("EXTRACTION COMPLETE!", flush=True)
