import json
import sys
import lightgbm as lgb

sys.path.insert(0, "C:/Users/armaa/Desktop/Project details/lightgbm_dataset/_deps")
sys.path.insert(0, "C:/Users/armaa/Desktop/Project details/SCYTHE/containers/backend")
from services.model_features.url_features import build_url_feature_vector

v26_booster = lgb.Booster(model_file="C:/Users/armaa/Desktop/Project details/SCYTHE/models/releases/candidate_fusion_v26/url_classifier.txt")
ch_booster = lgb.Booster(model_file="C:/Users/armaa/Desktop/Project details/lightgbm_dataset/challenger_234k_eval/challenger_url_classifier.txt")

live_urls = [
    "https://imediachile.cl/secupdf/10625.html",
    "http://hse-review.top/",
    "https://phantom-app-4eu8.vercel.app/"
]

print("=" * 65)
print("EVALUATING LIVE ZERO-DAY PHISHING CAPTURED FROM AZURE CLOUD")
print("=" * 65)

for u in live_urls:
    feats = build_url_feature_vector(u)["values"]
    v26_p = float(v26_booster.predict([feats])[0])
    ch_p = float(ch_booster.predict([feats])[0])
    print(f"URL: {u}")
    print(f"  v26 Model Score:        {v26_p * 100:.2f} / 100  ({'HIGH RISK' if v26_p >= 0.5 else 'LOW RISK'})")
    print(f"  234k Challenger Score:  {ch_p * 100:.4f} / 100 ({'HIGH RISK' if ch_p >= 0.99997 else 'LOW RISK'})")
    print("-" * 65)
