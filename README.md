# Phishing Dataset Builder

Build a labelled, feature-engineered phishing dataset (~10K rows) using
**AlienVault OTX** for phishing indicators and **Tranco** for benign domains.
Features are derived from the phishing-detection literature (see
[`parameters.md`](./parameters.md) for the full schema and citations).

## Layout

```
phishing-dataset/
  parameters.md              # feature schema + paper references
  requirements.txt
  .env.example               # copy to .env and add OTX_API_KEY
  src/
    otx_ingest.py            # phishing indicators from OTX
    benign_source.py         # benign domains from Tranco
    features.py              # feature extraction
    build_dataset.py         # orchestrator -> processed CSV
  data/
    raw/                     # otx_phishing.csv, tranco_benign.csv
    processed/               # phishing_dataset.csv (final 10K)
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then put your OTX_API_KEY in .env
```

> **Security note:** the API key was shared over chat during scaffolding.
> Rotate it at <https://otx.alienvault.com/settings> before sharing this repo.

## Build the dataset

```bash
# 1. Pull phishing indicators (URL/domain/hostname/IPv4) from OTX
python -m src.otx_ingest --max-rows 8000

# 2. Pull benign domains from Tranco (top-N)
python -m src.benign_source --n 6000

# 3. Build the labelled, featured dataset
python -m src.build_dataset --target 10000 --benign-ratio 0.5
```

Output: `data/processed/phishing_dataset.csv` with columns

```
indicator, indicator_type, source, pulse_id, label,
url_length, hostname_length, path_length, query_length,
num_dots, num_hyphens, num_at, num_question, num_equals,
num_underscore, num_ampersand, num_tilde, num_percent, num_slash,
num_digits, digit_letter_ratio, num_subdomains,
longest_token_length, avg_token_length, hostname_entropy,
has_https, has_port, has_ip_in_hostname, has_punycode,
has_at_symbol, has_double_slash_in_path,
tld, tld_length, is_suspicious_tld,
num_suspicious_keywords, brand_in_subdomain, brand_in_path
```

## Label strategy

- **`label = 1`** — indicators from OTX pulses matching phishing-related
  queries (`phishing`, `phish`, `credential theft`, `smishing`).
- **`label = 0`** — top-ranked Tranco domains (research-grade aggregation of
  Alexa / Umbrella / Majestic / Cloudflare Radar).
- **Leakage filter:** benign rows whose eTLD+1 also appears in the phishing
  set are dropped before sampling.

## Tuning

- Change `--max-rows` in `otx_ingest` to widen the phishing pool (more pages
  = more API calls = slower).
- Change `--benign-ratio` to skew the class balance.
- Edit `SUSPICIOUS_TLDS`, `BRAND_TOKENS`, `SUSPICIOUS_KEYWORDS` in
  `src/features.py` to adjust heuristic features.
- For network-dependent features (WHOIS age, DNS, TLS, page content), add a
  second-pass enrichment script — see the *Optional features* section of
  `parameters.md`.

## Reproducibility

- `--seed` controls sampling for `build_dataset.py` (default `42`).
- Tranco's "latest" permalink rolls daily; pin a specific list ID in
  `benign_source.py::TRANCO_URL` if you need byte-stable benign data.
- OTX results vary as new pulses are published. The script de-duplicates by
  `(indicator_type, indicator)`.
