import lightgbm as lgb
from pathlib import Path

REPO = Path(r"C:\Users\armaa\Desktop\Project details\SCYTHE")
sys_backend = REPO / "containers" / "backend"
import sys; sys.path.insert(0, str(sys_backend))

from services.model_features.url_features import build_url_feature_vector, FEATURE_NAMES_V2, FEATURE_NAMES_V3

v30 = lgb.Booster(model_file=str(REPO / "models" / "releases" / "candidate_fusion_v30" / "url_classifier.txt"))
v31 = lgb.Booster(model_file=str(REPO / "models" / "releases" / "candidate_fusion_v31" / "url_classifier.txt"))

challenge_urls = [
    # Category A: TLD & Credential path abuse (phishing)
    ("http://secure-login-apple-support.top/auth/verify/login.php?session=9238", 1, "TLD Abuse + Credential Path"),
    ("http://account-update-paypal-notice.xyz/signin/index.html", 1, "TLD Abuse + Paypal Spoof"),
    ("http://microsoft-online-reauth.buzz/portal/login", 1, "High Abuse TLD + Microsoft"),
    ("http://amazon-prime-account-recovery.click/auth/ap/signin", 1, "High Abuse TLD + Amazon"),
    ("http://dga-kjh8347fhdsjklhfsd.top/index", 1, "DGA Hostname + Abuse TLD"),
    ("http://x8273hjs927dhs.work/verify?token=123", 1, "DGA + Credential Token"),
    ("http://login.chase.com.security-verify.cc/login.aspx", 1, "TLD in Subdomain Chase Spoof"),
    ("http://bankofamerica.com.account-update.net/auth", 1, "TLD in Subdomain BoA Spoof"),
    ("http://192.168.1.1:8080/secure/login", 1, "Raw IP + Non-standard Port"),
    ("http://verify-identity-help.org:8443/auth/reset-password", 1, "Non-standard Port + Credential"),
    ("http://9anime.org.lv", 0, "Anime Streaming Domain"),
    
    # Category B: Legitimate Complex / Deep URLs
    ("https://www.google.com/search?q=machine+learning+tutorial&oq=ml", 0, "Legitimate Google Search"),
    ("https://github.com/microsoft/vscode/pull/12345/commits", 0, "Legitimate GitHub Commit Path"),
    ("https://aws.amazon.com/console/home?region=us-east-1#services", 0, "Legitimate AWS Console"),
    ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", 0, "Legitimate Microsoft SSO"),
    ("https://en.wikipedia.org/wiki/Phishing_detection_methods", 0, "Legitimate Deep Wikipedia"),
    ("https://stackoverflow.com/questions/1234567/python-lightgbm-parameters", 0, "Legitimate StackOverflow"),
    ("https://docs.docker.com/compose/compose-file/compose-file-v3/", 0, "Legitimate Deep Technical Docs"),
    ("https://store.steampowered.com/app/1091500/Cyberpunk_2077/", 0, "Legitimate Steam Store"),
]

print("=" * 110)
print(f"{'Target URL':<58} | {'True':<5} | {'V30 Score':<10} | {'V31 Score':<10} | Analysis")
print("=" * 110)
for url, true_lbl, desc in challenge_urls:
    f2 = build_url_feature_vector(url, feature_names=FEATURE_NAMES_V2)["values"]
    f3 = build_url_feature_vector(url, feature_names=FEATURE_NAMES_V3)["values"]
    s30 = float(v30.predict([f2])[0])
    s31 = float(v31.predict([f3])[0])
    
    v30_correct = (s30 >= 0.5) == bool(true_lbl)
    v31_correct = (s31 >= 0.5) == bool(true_lbl)
    
    if v30_correct and v31_correct:
        status = "Both Correct"
    elif v31_correct:
        status = ">> V31 WON <<"
    elif v30_correct:
        status = "V30 Won"
    else:
        status = "Both Failed"
    
    url_disp = url[:55] + "..." if len(url) > 58 else url
    print(f"{url_disp:<58} | {true_lbl:<5} | {s30:>9.4f}  | {s31:>9.4f}  | {status:<15} ({desc})")
print("=" * 110)
