#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDORHunter - Insecure Direct Object Reference (IDOR) scanner
by : mammadow1337"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Install it with: pip install -r requirements.txt")
    sys.exit(1)

BANNER = r"""
  ___ ___   ___  ___ _  _          _
 |_ _|   \ / _ \| _ \ || |_  _ _ _| |_ ___ _ _
  | || |) | (_) |   / __ | || | ' \  _/ -_) '_|
 |___|___/ \___/|_|_\_||_\_,_|_||_\__\___|_|

        IDORHunter v1.0 — IDOR Vulnerability Scanner
                    by : mammadow1337
"""

DEFAULT_HEADERS = {
    "User-Agent": "IDORHunter/1.0 (+https://github.com/mammadow1337)",
    "Accept": "*/*",
}

ID_PATTERNS = [
    r"[?&](id|user_id|userid|uid|account_id|accountid|order_id|orderid|invoice_id|profile_id|file_id|doc_id|document_id|item_id|product_id|message_id|ticket_id|customer_id|employee_id|record_id|object_id|obj_id)=(\\d+)",
]

SUCCESS_MARKERS = [
    "email", "e-mail", "phone", "username", "user_name", "first_name",
    "last_name", "address", "balance", "token", "api_key", "apikey",
    "password", "ssn", "dob", "birth", "invoice", "order", "profile",
]


def print_banner():
    print("\033[1;36m" + BANNER + "\033[0m")


def normalize_url(url):
    url = url.strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    return url


def extract_ids(url):
    found = []
    for pattern in ID_PATTERNS:
        for match in re.finditer(pattern, url, re.I):
            found.append({
                "param": match.group(1),
                "value": match.group(2),
            })
    return found


def build_test_url(url, param, value):
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [str(value)]
    return parsed._replace(query=urlencode(query, doseq=True)).geturl()


def response_score(response):
    body = response.text.lower()
    score = sum(marker in body for marker in SUCCESS_MARKERS)
    if response.status_code == 200 and len(response.text) > 300:
        score += 1
    return score


def scan_target(target, baseline, session, delay, verbose):
    url, param, original_value = target["url"], target["param"], target["value"]
    results = []
    for candidate in target["test_values"]:
        if str(candidate) == str(original_value):
            continue
        test_url = build_test_url(url, param, candidate)
        try:
            response = session.get(test_url, timeout=15, allow_redirects=False)
        except requests.RequestException as exc:
            if verbose:
                print(f"  [!] Request failed: {test_url} - {exc}")
            continue

        score = response_score(response)
        flagged = response.status_code == 200 and score > baseline["score"] and response.text != baseline["body"]
        results.append({
            "url": test_url, "parameter": param, "tested_value": candidate,
            "status_code": response.status_code, "content_length": len(response.text),
            "score": score, "baseline_score": baseline["score"], "flagged": flagged,
        })

        if flagged:
            print(f"\033[1;31m[+] Possible IDOR\033[0m {test_url}")
            print(f"    Parameter: {param} | Tested: {candidate} | Status: {response.status_code} | Score: {score}")
        elif verbose:
            print(f"[-] No anomaly: {test_url} (status {response.status_code}, score {score})")

        if delay:
            time.sleep(delay)
    return results


def prepare_targets(args):
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    for item in args.header:
        if ":" not in item:
            print(f"[!] Invalid header format: {item}")
            sys.exit(1)
        name, value = item.split(":", 1)
        session.headers[name.strip()] = value.strip()

    targets = []
    with open(args.url_list, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            url = normalize_url(raw_line)
            if not url:
                continue
            ids = extract_ids(url)
            if not ids:
                if args.verbose:
                    print(f"[!] No numeric ID parameter detected: {url}")
                continue
            for match in ids:
                original = int(match["value"])
                test_values = [original + offset for offset in args.range if original + offset > 0]
                targets.append({"url": url, "param": match["param"], "value": match["value"], "test_values": test_values})
    return targets, session


def get_baselines(targets, session):
    baselines = {}
    for target in targets:
        key = (target["url"], target["param"])
        if key in baselines:
            continue
        try:
            response = session.get(target["url"], timeout=15, allow_redirects=False)
            baselines[key] = {"status_code": response.status_code, "body": response.text, "score": response_score(response)}
        except requests.RequestException:
            baselines[key] = {"status_code": 0, "body": "", "score": 0}
    return baselines


def parse_args():
    parser = argparse.ArgumentParser(prog="IDORHunter", description="IDORHunter - a lightweight IDOR parameter scanner")
    parser.add_argument("-u", "--url", help="Scan a single URL containing an ID parameter")
    parser.add_argument("-l", "--url-list", help="File containing URLs, one per line")
    parser.add_argument("-r", "--range", type=int, nargs="+", default=[1, 2, 3], help="ID offsets to test")
    parser.add_argument("-c", "--cookie", help="Raw Cookie header")
    parser.add_argument("-H", "--header", action="append", default=[], help="Additional header, repeatable")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Concurrent workers")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("-o", "--output", help="Save JSON results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show non-flagged requests")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.no_banner:
        print_banner()
    if not args.url and not args.url_list:
        print("[!] Provide a target with -u/--url or a list with -l/--url-list")
        sys.exit(1)

    if args.url:
        with open(".idorhunter_tmp_urls.txt", "w", encoding="utf-8") as handle:
            handle.write(args.url + "\n")
        args.url_list = ".idorhunter_tmp_urls.txt"

    targets, session = prepare_targets(args)
    if not targets:
        print("[!] No testable numeric ID parameters were found.")
        sys.exit(1)

    print(f"[*] Loaded {len(targets)} testable parameter(s).")
    print(f"[*] Testing offsets: {', '.join(map(str, args.range))}")
    print("[*] Starting scan...\n")

    baselines = get_baselines(targets, session)
    jobs = [(t, baselines[(t["url"], t["param"])]) for t in targets]
    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_target, t, b, session, args.delay, args.verbose) for t, b in jobs]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    flagged = [r for r in all_results if r["flagged"]]
    print("\n" + "=" * 60)
    print(f"Scan complete: {len(all_results)} request(s), {len(flagged)} possible IDOR finding(s).")
    print("=" * 60)

    if args.output:
        payload = {"tool": "IDORHunter", "author": "mammadow1337", "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "total_requests": len(all_results), "findings": flagged, "all_results": all_results}
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        print(f"[*] Results saved to: {args.output}")

    if args.url:
        try:
            os.remove(".idorhunter_tmp_urls.txt")
        except OSError:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
