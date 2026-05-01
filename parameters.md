# Phishing Dataset — Feature Parameters

This document specifies the feature schema used to build the phishing dataset.
Features are derived from indicators (URL / domain / hostname / IPv4) and are
selected based on commonly cited phishing-detection literature. Network-dependent
features (WHOIS age, DNS TTL, page content) are intentionally excluded from the
default pipeline to keep extraction deterministic and offline; hooks are noted
where they could be added.

## References

- Mohammad, R. M., Thabtah, F., & McCluskey, L. (2014). *Predicting phishing
  websites based on self-structuring neural network.* Neural Computing and
  Applications, 25(2), 443–458.
- Sahingoz, O. K., Buber, E., Demir, O., & Diri, B. (2019). *Machine learning
  based phishing detection from URLs.* Expert Systems with Applications, 117,
  345–357.
- Marchal, S., Saari, K., Singh, N., & Asokan, N. (2016). *Know Your Phish:
  Novel Techniques for Detecting Phishing Sites and their Targets.* ICDCS.
- Verma, R., & Dyer, K. (2015). *On the Character of Phishing URLs: Accurate
  and Robust Statistical Learning Classifiers.* CODASPY.
- Le, A., Markopoulou, A., & Faloutsos, M. (2011). *PhishDef: URL names say it
  all.* IEEE INFOCOM.

## Indicator-level columns

| column           | type   | description                                                      |
|------------------|--------|------------------------------------------------------------------|
| `indicator`      | str    | Raw indicator value (URL / domain / hostname / IPv4).            |
| `indicator_type` | str    | One of `URL`, `domain`, `hostname`, `IPv4`.                      |
| `source`         | str    | `OTX` or `tranco`.                                               |
| `pulse_id`       | str?   | OTX pulse id (phishing rows only).                               |
| `label`          | int    | `1` = phishing, `0` = benign.                                    |

Non-URL indicators are normalised to a URL form (`http://<indicator>/`) so a
single feature extractor can be applied uniformly. `indicator_type` is retained
to allow stratified splits or per-type evaluation.

## Lexical URL features (Sahingoz 2019; Verma 2015; Le 2011)

| feature                  | description                                                |
|--------------------------|------------------------------------------------------------|
| `url_length`             | Total character length of the URL.                         |
| `hostname_length`        | Length of the hostname component.                          |
| `path_length`            | Length of the path.                                        |
| `query_length`           | Length of the query string.                                |
| `num_dots`               | Count of `.` in the URL.                                   |
| `num_hyphens`            | Count of `-`.                                              |
| `num_at`                 | Count of `@` (Mohammad 2014: presence of `@` is a flag).   |
| `num_question`           | Count of `?`.                                              |
| `num_equals`             | Count of `=`.                                              |
| `num_underscore`         | Count of `_`.                                              |
| `num_ampersand`          | Count of `&`.                                              |
| `num_tilde`              | Count of `~`.                                              |
| `num_percent`            | Count of `%` (URL-encoding indicator).                     |
| `num_slash`              | Count of `/`.                                              |
| `num_digits`             | Count of digit characters.                                 |
| `digit_letter_ratio`     | `num_digits / max(num_letters, 1)`.                        |
| `num_subdomains`         | Number of subdomain labels (excluding eTLD+1).             |
| `longest_token_length`   | Longest token after splitting on `/._-?=&`.                |
| `avg_token_length`       | Mean token length over the same split.                     |
| `hostname_entropy`       | Shannon entropy of the hostname (bot/DGA signal).          |

## Host-based features (Mohammad 2014; Marchal 2016)

| feature              | description                                                    |
|----------------------|----------------------------------------------------------------|
| `has_https`          | Scheme is `https`.                                             |
| `has_port`           | Explicit non-default port present.                             |
| `has_ip_in_hostname` | Hostname is an IPv4/IPv6 literal (Mohammad 2014).              |
| `has_punycode`       | Any label starts with `xn--` (IDN homograph signal).           |
| `has_at_symbol`      | `@` present anywhere in URL (auth confusion).                  |
| `has_double_slash_in_path` | `//` appears in the path beyond the scheme separator.    |
| `tld`                | Effective TLD (e.g. `com`, `co.uk`).                           |
| `tld_length`         | Length of the eTLD.                                            |
| `is_suspicious_tld`  | TLD in curated list of phishing-prone TLDs.                    |

## Content / brand features (Marchal 2016; Mohammad 2014)

| feature                    | description                                                 |
|----------------------------|-------------------------------------------------------------|
| `num_suspicious_keywords`  | Count of {login, secure, account, update, verify, banking, confirm, signin, password, ebay, paypal, amazon, apple, microsoft, bank} substrings (case-insensitive) anywhere in URL. |
| `brand_in_subdomain`       | Any of the above brand tokens occurs in a subdomain label.  |
| `brand_in_path`            | Any brand token occurs in path.                             |

## Optional / future features (network-dependent — disabled by default)

- `domain_age_days` — WHOIS `creation_date` delta.
- `dns_ttl`, `num_a_records`, `num_mx_records`.
- `cert_issuer`, `cert_age_days`.
- `page_form_count`, `page_external_link_ratio`, `page_title_brand_match`.

These are intentionally omitted from the default 10K build because they require
live lookups and are non-reproducible. Add them in a second-pass enrichment
step if needed.

## Suspicious-TLD list

Sourced by aggregating reports from Spamhaus, Interisle Consulting (Phishing
Landscape), and the APWG Phishing Activity Trends Report. The list is encoded
in `src/features.py::SUSPICIOUS_TLDS` and can be edited there.

## Label strategy

- **Phishing (label = 1):** OTX pulses returned by the search query
  `q=phishing` (and tag-based filtering on `phishing`, `phish`, `credential`),
  filtered to indicator types `URL`, `domain`, `hostname`, `IPv4`.
- **Benign (label = 0):** Top entries of the Tranco research list
  (`https://tranco-list.eu/`). Tranco aggregates Alexa / Umbrella / Majestic
  / Cloudflare Radar over a rolling 30-day window and is the standard
  research-grade benign source.
- **Deduplication:** benign rows whose registrable domain (eTLD+1) appears in
  the phishing set are dropped to avoid label leakage.
- **Target:** 10,000 rows total, balanced 50/50 by default
  (`--target 10000 --benign-ratio 0.5`).
