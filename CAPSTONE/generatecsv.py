import requests
import pandas as pd
import re
import zipfile
from urllib.parse import urlparse

# Suspicious keywords list
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "payment"]

def extract_features(url, label, tranco_rank=0):
    parsed = urlparse(url)
    domain = parsed.netloc
    
    url_length = len(url)
    num_subdirs = url.count('/')
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
    suspicious_words = 1 if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS) else 0
    
    # TLD risk (heuristic)
    tld = domain.split(".")[-1] if "." in domain else ""
    risky_tlds = ["ru", "tk", "cn", "ga", "cf", "ml", "gq"]
    tld_risk = "high" if tld in risky_tlds else "low"
    
    return {
        "url": url,
        "url_length": url_length,
        "num_subdirs": num_subdirs,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "has_ip": has_ip,
        "suspicious_words": suspicious_words,
        # placeholders for large-scale run (to avoid slow lookups)
        "domain_age_days": -1,
        "ssl_valid": -1,
        "dns_record": -1,
        "tranco_rank": tranco_rank,
        "tld_risk": tld_risk,
        "label": label
    }

# ----------- Fetch phishing URLs (PhishTank dump) -----------
def get_phishtank(limit=75000):
    url = "http://data.phishtank.com/data/online-valid.json"
    print("Fetching phishing data from PhishTank...")
    r = requests.get(url, timeout=60)
    data = r.json()
    urls = [item['url'] for item in data[:limit]]
    return [extract_features(u, "phishing") for u in urls]

# ----------- Fetch benign URLs (Tranco Top 1M) ---------------
def get_tranco(limit=75000):
    print("Fetching benign data from Tranco top list...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    
    r = requests.get(tranco_url, timeout=60)
    open("tranco.zip", "wb").write(r.content)
    
    with zipfile.ZipFile("tranco.zip", "r") as zip_ref:
        zip_ref.extractall(".")
    
    benign_df = pd.read_csv("top-1m.csv", header=None, names=["rank", "domain"])
    benign_rows = []
    for _, row in benign_df.head(limit).iterrows():
        url = "http://" + row["domain"]
        benign_rows.append(extract_features(url, "benign", tranco_rank=row["rank"]))
    return benign_rows

# ----------- Build Dataset -----------------------------------
def build_dataset(phish_limit=75000, benign_limit=75000, out_file="phishing_dataset_150k.csv"):
    phishing = get_phishtank(phish_limit)
    benign = get_tranco(benign_limit)
    
    df = pd.DataFrame(phishing + benign)
    df.to_csv(out_file, index=False)
    print(f"✅ Dataset saved to {out_file} with {len(df)} rows.")

if __name__ == "__main__":
    build_dataset()
