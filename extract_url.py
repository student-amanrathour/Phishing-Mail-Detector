import csv
import os
import re
from urllib.parse import urlparse

SAFE_DOMAIN_PATH = "data/safe_domain.csv"

def load_safe_domain(limit=1000000):
    if not os.path.exists(SAFE_DOMAIN_PATH):
        print("[WARN] Safe Domain list not found")
        return set()

    with open(SAFE_DOMAIN_PATH, newline="") as f:
        read = csv.reader(f)
        return {row[1].strip().lower() for row in read if row}

SAFE_DOMAIN = load_safe_domain(1000000)

def extract_url(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = ".".join(hostname.split(".")[-2:]) #example.com

    is_safe_domain = 1 if domain in SAFE_DOMAIN else 0

    feature = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
        "nb_dots": hostname.count("."),
        "nb_hyphens": hostname.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_eq": url.count("="),
        "nb_slash": url.count("/"),
        "https_token": 1 if "https" in url.lower() else 0,
        "nb_subdomains": len(hostname.split(".")) - 2 if hostname.count(".") > 1 else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "punycode": 1 if "xn--" in hostname else 0,
        "is_safe_domain": is_safe_domain,
    }

    return feature
