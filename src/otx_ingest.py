"""OTX phishing-pulse ingestion.

Pulls pulses matching phishing-related queries from AlienVault OTX, extracts
indicators of all relevant types (URL, domain, hostname, IPv4) and writes a
deduplicated CSV of raw indicators to data/raw/otx_phishing.csv.

Usage:
    python -m src.otx_ingest --max-rows 8000
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time
from pathlib import Path
from typing import Iterable

import requests
from dotenv import load_dotenv
from tqdm import tqdm

OTX_BASE = "https://otx.alienvault.com/api/v1"
SEARCH_ENDPOINT = f"{OTX_BASE}/search/pulses"
PULSE_ENDPOINT = f"{OTX_BASE}/pulses"

# OTX indicator types we keep. OTX uses "URL", "domain", "hostname", "IPv4".
KEEP_TYPES = {"URL", "domain", "hostname", "IPv4"}

# Queries broaden coverage beyond a single keyword.
DEFAULT_QUERIES = ["phishing", "phish", "credential theft", "smishing"]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUT_PATH = RAW_DIR / "otx_phishing.csv"


def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"X-OTX-API-KEY": api_key, "User-Agent": "phishing-dataset/0.1"})
    return s


def search_pulses(sess: requests.Session, query: str, max_pages: int = 200) -> Iterable[dict]:
    """Yield pulse summaries for a search query, paginated."""
    page = 1
    while page <= max_pages:
        params = {"q": query, "page": page, "limit": 50}
        try:
            r = sess.get(SEARCH_ENDPOINT, params=params, timeout=30)
        except requests.RequestException as e:
            print(f"[warn] search '{query}' page={page}: {e}", file=sys.stderr)
            time.sleep(2)
            page += 1
            continue
        if r.status_code == 429:
            time.sleep(5)
            continue
        if r.status_code != 200:
            print(f"[warn] search '{query}' page={page} -> {r.status_code}", file=sys.stderr)
            return
        data = r.json()
        results = data.get("results") or []
        if not results:
            return
        for p in results:
            yield p
        if not data.get("next"):
            return
        page += 1


def fetch_pulse_indicators(sess: requests.Session, pulse_id: str) -> list[dict]:
    """Fetch full indicator list for a pulse (handles pagination)."""
    indicators: list[dict] = []
    page = 1
    while True:
        url = f"{PULSE_ENDPOINT}/{pulse_id}/indicators"
        try:
            r = sess.get(url, params={"page": page, "limit": 500}, timeout=30)
        except requests.RequestException as e:
            print(f"[warn] pulse {pulse_id} page={page}: {e}", file=sys.stderr)
            return indicators
        if r.status_code == 429:
            time.sleep(5)
            continue
        if r.status_code != 200:
            return indicators
        data = r.json()
        results = data.get("results") or []
        indicators.extend(results)
        if not data.get("next"):
            return indicators
        page += 1


def ingest(max_rows: int, queries: list[str]) -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise SystemExit("OTX_API_KEY not set (check .env)")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    sess = _session(api_key)

    seen: set[tuple[str, str]] = set()  # (type, indicator)
    rows_written = 0

    with OUT_PATH.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["indicator", "indicator_type", "pulse_id", "pulse_name", "created"])

        seen_pulses: set[str] = set()
        for q in queries:
            if rows_written >= max_rows:
                break
            print(f"[info] querying OTX: '{q}'")
            for pulse in tqdm(search_pulses(sess, q), desc=f"pulses[{q}]", unit="pulse"):
                pid = pulse.get("id")
                if not pid or pid in seen_pulses:
                    continue
                seen_pulses.add(pid)

                # Use indicators inlined in the pulse if present, else fetch.
                inds = pulse.get("indicators")
                if not inds:
                    inds = fetch_pulse_indicators(sess, pid)

                for ind in inds:
                    itype = ind.get("type")
                    ival = (ind.get("indicator") or "").strip()
                    if not ival or itype not in KEEP_TYPES:
                        continue
                    key = (itype, ival.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    writer.writerow([
                        ival,
                        itype,
                        pid,
                        pulse.get("name", ""),
                        pulse.get("created", ""),
                    ])
                    rows_written += 1
                    if rows_written >= max_rows:
                        break
                if rows_written >= max_rows:
                    break

    print(f"[done] wrote {rows_written} indicators to {OUT_PATH}")
    return rows_written


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=8000,
                    help="Max phishing indicators to collect.")
    ap.add_argument("--queries", nargs="*", default=DEFAULT_QUERIES,
                    help="OTX search queries to iterate.")
    args = ap.parse_args()
    ingest(args.max_rows, args.queries)


if __name__ == "__main__":
    main()
