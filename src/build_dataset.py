"""Build the labelled phishing dataset.

Pipeline:
    1. Load raw OTX phishing indicators (data/raw/otx_phishing.csv).
    2. Load raw Tranco benign domains      (data/raw/tranco_benign.csv).
    3. Drop benign rows whose eTLD+1 appears in the phishing set (leakage).
    4. Sample to the requested target/balance.
    5. Run feature extraction.
    6. Write data/processed/phishing_dataset.csv.

Usage:
    python -m src.build_dataset --target 10000 --benign-ratio 0.5
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
import tldextract
from tqdm import tqdm

from src.features import extract

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROC_DIR = PROJECT_ROOT / "data" / "processed"

OTX_PATH = RAW_DIR / "otx_phishing.csv"
BENIGN_PATH = RAW_DIR / "tranco_benign.csv"
OUT_PATH = PROC_DIR / "phishing_dataset.csv"


def _registrable(value: str, itype: str) -> str:
    if itype == "IPv4":
        return value
    ext = tldextract.extract(value)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return value.lower()


def build(target: int, benign_ratio: float, seed: int) -> None:
    if not OTX_PATH.exists():
        raise SystemExit(f"missing {OTX_PATH} — run `python -m src.otx_ingest` first")
    if not BENIGN_PATH.exists():
        raise SystemExit(f"missing {BENIGN_PATH} — run `python -m src.benign_source` first")

    phish = pd.read_csv(OTX_PATH)
    phish["source"] = "OTX"
    phish["label"] = 1
    phish = phish[["indicator", "indicator_type", "source", "pulse_id", "label"]]
    phish = phish.drop_duplicates(subset=["indicator_type", "indicator"])

    benign = pd.read_csv(BENIGN_PATH)
    benign["source"] = "tranco"
    benign["pulse_id"] = ""
    benign["label"] = 0
    benign = benign[["indicator", "indicator_type", "source", "pulse_id", "label"]]
    benign = benign.drop_duplicates(subset=["indicator_type", "indicator"])

    # Leakage filter: drop benign rows whose registrable domain occurs in phish.
    phish_regs = {
        _registrable(v, t) for v, t in zip(phish["indicator"], phish["indicator_type"])
    }
    benign["_reg"] = [
        _registrable(v, t) for v, t in zip(benign["indicator"], benign["indicator_type"])
    ]
    before = len(benign)
    benign = benign[~benign["_reg"].isin(phish_regs)].drop(columns=["_reg"])
    print(f"[info] leakage filter dropped {before - len(benign)} benign rows")

    n_benign_target = int(round(target * benign_ratio))
    n_phish_target = target - n_benign_target

    if len(phish) < n_phish_target:
        print(f"[warn] only {len(phish)} phishing rows available; "
              f"requested {n_phish_target}. Using all.")
        n_phish_target = len(phish)
    if len(benign) < n_benign_target:
        print(f"[warn] only {len(benign)} benign rows available; "
              f"requested {n_benign_target}. Using all.")
        n_benign_target = len(benign)

    phish_s = phish.sample(n=n_phish_target, random_state=seed)
    benign_s = benign.sample(n=n_benign_target, random_state=seed)

    df = pd.concat([phish_s, benign_s], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    print(f"[info] extracting features for {len(df)} rows ...")
    feats = [
        extract(ind, itype)
        for ind, itype in tqdm(
            zip(df["indicator"], df["indicator_type"]), total=len(df), unit="row"
        )
    ]
    feat_df = pd.DataFrame(feats)
    out = pd.concat([df.reset_index(drop=True), feat_df], axis=1)

    PROC_DIR.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT_PATH, index=False)
    print(f"[done] wrote {len(out)} rows ({out['label'].sum()} phishing / "
          f"{(out['label'] == 0).sum()} benign) to {OUT_PATH}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=10000)
    ap.add_argument("--benign-ratio", type=float, default=0.5,
                    help="Fraction of `target` to be benign (label=0).")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    build(args.target, args.benign_ratio, args.seed)


if __name__ == "__main__":
    main()
