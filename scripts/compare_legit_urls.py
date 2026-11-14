import lightgbm as lgb
from pathlib import Path

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
sys_backend = REPO / "containers" / "backend"
import sys; sys.path.insert(0, str(sys_backend))

from services.model_features.url_features import build_url_feature_vector, FEATURE_NAMES_V2, FEATURE_NAMES_V3

v30 = lgb.Booster(model_file=str(REPO / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt"))
v31 = lgb.Booster(model_file=str(REPO / "models" / "releases" / "candidate_fusion_v31" / "url_classifier.txt"))

legit_urls = [
    "https://www.python.org/downloads/release/python-3110/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://www.nist.gov/cyberframework",
    "https://news.ycombinator.com/item?id=30000000",
    "https://www.nature.com/articles/s41586-021-03819-2",
    "https://arxiv.org/abs/2103.00020",
    "https://www.bbc.com/news/technology-58000000",
    "https://www.cdc.gov/flu/about/index.html",
    "https://www.who.int/emergencies/disease-outbreak-news",
]

print("=" * 85)
print(f"{'Legitimate Deep URL':<55} | {'V30 (18f)':<10} | {'V31 (28f)':<10} | Delta")
print("=" * 85)
for u in legit_urls:
    f2 = build_url_feature_vector(u, feature_names=FEATURE_NAMES_V2)["values"]
    f3 = build_url_feature_vector(u, feature_names=FEATURE_NAMES_V3)["values"]
    s30 = float(v30.predict([f2])[0])
    s31 = float(v31.predict([f3])[0])
    print(f"{u[:53]:<55} | {s30:>9.4f}  | {s31:>9.4f}  | {s31 - s30:>+.4f}")
print("=" * 85)
