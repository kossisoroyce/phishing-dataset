"""Benign indicator source — Tranco research list.

Tranco (https://tranco-list.eu/) provides a research-grade ranking of popular
domains aggregated over a 30-day window. We download the latest top list and
sample the top-N domains as benign examples.

Usage:
    python -m src.benign_source --n 6000
"""
from __future__ import annotations

import argparse
import csv
import io
import sys
import zipfile
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUT_PATH = RAW_DIR / "tranco_benign.csv"

# Tranco "latest" permalink — always returns the most recent daily list.
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def fetch_tranco(n: int) -> list[str]:
    print(f"[info] downloading Tranco top-1m list ...")
    r = requests.get(TRANCO_URL, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8")
            domains: list[str] = []
            reader = csv.reader(text)
            for row in reader:
                if len(row) < 2:
                    continue
                domains.append(row[1].strip().lower())
                if len(domains) >= n:
                    break
    return domains


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6000,
                    help="Number of top Tranco domains to keep.")
    args = ap.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    try:
        domains = fetch_tranco(args.n)
    except Exception as e:
        print(f"[error] could not fetch Tranco: {e}", file=sys.stderr)
        raise SystemExit(1)

    with OUT_PATH.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["indicator", "indicator_type", "rank"])
        for rank, d in enumerate(domains, start=1):
            w.writerow([d, "domain", rank])
    print(f"[done] wrote {len(domains)} benign domains to {OUT_PATH}")


if __name__ == "__main__":
    main()
