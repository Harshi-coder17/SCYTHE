"""Extract MobileCLIP-S0 embeddings for consolidated_fleet_v1 images.
Saves .npy files to embedding_cache/consolidated_fleet_v1/<image_sha256>.npy
"""
import sys, time, os
from pathlib import Path
from PIL import Image
import torch
import numpy as np

sys.path.insert(0, r"C:\Users\armaa\Desktop\Project details\mobileclip-dataset\vendor\ml-mobileclip")
import mobileclip

ROOT = Path(r"C:\Users\armaa\Desktop\Project details")
IMG_DIR = ROOT / "lightgbm_dataset" / "consolidated_fleet_v1" / "images"
OUT_DIR = ROOT / "mobileclip-dataset" / "artifacts" / "embedding_cache" / "consolidated_fleet_v1"
OUT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT = ROOT / "mobileclip-dataset" / "checkpoints" / "mobileclip_s0.pt"

print(f"Loading MobileCLIP-S0 from {CHECKPOINT}...")
model, _, preprocess = mobileclip.create_model_and_transforms("mobileclip_s0", pretrained=str(CHECKPOINT))
model.eval()

# Gather images that need extraction
all_imgs = sorted(list(IMG_DIR.glob("*.png")))
to_process = []
for p in all_imgs:
    out_npy = OUT_DIR / f"{p.stem}.npy"
    if not out_npy.is_file():
        to_process.append(p)

print(f"Total images: {len(all_imgs)}, already extracted: {len(all_imgs) - len(to_process)}, to process: {len(to_process)}")

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
        except Exception as e:
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
    if (i // BATCH_SIZE) % 5 == 0 or n_done == len(to_process):
        print(f"Progress: {n_done}/{len(to_process)} ({n_done/len(to_process)*100:.1f}%) | Speed: {rate:.1f} img/s | ETA: {eta_sec/60:.1f} min")

print("EXTRACTION COMPLETE!")
