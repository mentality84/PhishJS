#!/usr/bin/env python3
import os
import re
import hashlib
import requests
from bs4 import BeautifulSoup
import jsbeautifier
from urllib.parse import urljoin, urlparse
from collections import deque
import urllib3
import random

# --------------------------
# CONFIG
# --------------------------
OUTPUT_DIR = "js_analysis"
MAX_DEPTH = 2      # how deep to crawl
MAX_PAGES = 50     # safety limit for crawl

# Rotate common browser UA strings to avoid fingerprinting
UA_STRINGS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.46",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15"
]
HEADERS = {"User-Agent": random.choice(UA_STRINGS)}

# Suppress SSL warnings (phishing sites often have bad certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suspicious keywords to hunt in JS
SUSPICIOUS_KEYWORDS = [
    "eval", "atob", "fromCharCode", "Function", "document.write", "CryptoJS"
]

# --------------------------
# Helpers
# --------------------------
def fetch_page(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return None

def extract_links(base_url, html):
    """Find internal links in page"""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full_url = urljoin(base_url, href)
        if urlparse(full_url).netloc == urlparse(base_url).netloc:
            links.append(full_url.split("#")[0])  # strip fragments
    return list(set(links))

def extract_js_links(base_url, html):
    """Find JS script URLs in page"""
    soup = BeautifulSoup(html, "html.parser")
    js_links = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            if src.startswith("http"):
                js_links.append(src)
            else:
                js_links.append(urljoin(base_url, src))
    return list(set(js_links))

def download_file(url, folder):
    os.makedirs(folder, exist_ok=True)
    fname = url.split("/")[-1].split("?")[0] or "script.js"
    path = os.path.join(folder, fname)
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            with open(path, "wb") as f:
                f.write(r.content)
            return path
    except Exception as e:
        print(f"[-] Failed to download {url}: {e}")
    return None

def sha256sum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def beautify_js(input_path, output_path):
    with open(input_path, "r", errors="ignore") as f:
        raw = f.read()
    opts = jsbeautifier.default_options()
    cleaned = jsbeautifier.beautify(raw, opts)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(cleaned)
    return cleaned

def extract_indicators(js_code):
    urls = re.findall(r"(https?://[a-zA-Z0-9./?=_-]+)", js_code)
    suspicious_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in js_code]
    return list(set(urls)), suspicious_hits

# --------------------------
# Main
# --------------------------
def crawl_and_analyze(start_url):
    print(f"[+] Starting crawl at {start_url}")

    visited_pages = set()
    js_seen = set()
    queue = deque([(start_url, 0)])
    report = []

    while queue and len(visited_pages) < MAX_PAGES:
        url, depth = queue.popleft()
        if url in visited_pages or depth > MAX_DEPTH:
            continue

        html = fetch_page(url)
        if not html:
            continue

        visited_pages.add(url)
        print(f"[+] Crawled {url} (depth {depth})")

        # Extract and enqueue links
        for link in extract_links(url, html):
            if link not in visited_pages:
                queue.append((link, depth + 1))

        # Extract JS files
        js_links = extract_js_links(url, html)
        for js_url in js_links:
            if js_url in js_seen:
                continue
            js_seen.add(js_url)

            print(f"    -> Downloading {js_url}")
            raw_path = download_file(js_url, os.path.join(OUTPUT_DIR, "raw"))
            if not raw_path:
                continue

            # hash
            file_hash = sha256sum(raw_path)

            # beautify
            cleaned_path = raw_path.replace("/raw/", "/cleaned/")
            js_code = beautify_js(raw_path, cleaned_path)

            # extract indicators
            urls, hits = extract_indicators(js_code)

            report.append({
                "file": raw_path,
                "hash": file_hash,
                "urls": urls,
                "suspicious": hits
            })

    # Save report
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report_path = os.path.join(OUTPUT_DIR, "report.txt")
    with open(report_path, "w") as f:
        for item in report:
            f.write(f"\n=== {item['file']} ===\n")
            f.write(f"SHA256: {item['hash']}\n")
            f.write("Suspicious: " + ", ".join(item['suspicious']) + "\n")
            f.write("URLs:\n" + "\n".join(item['urls']) + "\n")

    print(f"[+] Crawl + Analysis complete. Report saved to {report_path}")


if __name__ == "__main__":
    target = input("Enter phishing site URL: ").strip()
    crawl_and_analyze(target)
