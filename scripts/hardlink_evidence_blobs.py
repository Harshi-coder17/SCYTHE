import os
from pathlib import Path

root = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE\models\releases\candidate_fusion_v31")
v26 = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE\models\releases\candidate_fusion_v26")
blobs_junction = root / "evidence" / "blobs"

# 1. Remove the junction
if blobs_junction.exists():
    os.rmdir(blobs_junction)
    print("Junction removed.")

# 2. Create real blobs directory
blobs_junction.mkdir(parents=True, exist_ok=True)

# 3. Hardlink each file from v26/evidence/blobs
src_blobs = v26 / "evidence" / "blobs"
count = 0
for f in src_blobs.iterdir():
    if f.is_file():
        dst = blobs_junction / f.name
        if not dst.exists():
            os.link(f, dst)
            count += 1

print(f"Hardlinked {count} blobs into real directory.")
first_blob = next(blobs_junction.iterdir())
print("First blob:", first_blob)
print("Resolved first blob:", first_blob.resolve())
print("is_relative_to root?", first_blob.resolve().is_relative_to(root.resolve()))
