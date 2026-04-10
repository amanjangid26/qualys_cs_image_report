# Qualys Container Security - Image SNOW Vulnerability Report

Enterprise CLI tool that fetches container image records from the Qualys CSAPI SNOW endpoint, enriches each QID with vulnerability title, CVE IDs, and patch status, classifies each QID as **Base** or **Application/Child** layer, and produces a unified CSV + JSON report.

[![Version](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange)](LICENSE)

---

## Features

| Feature | Description |
|---------|-------------|
| **Single SNOW endpoint + per-image vuln API** | SNOW gets images+layers+vulns+software+containers; vuln API enriches with title, CVEs, patch status |
| **Flexible QQL filter** | Pass ANY Qualys QQL via `-f` or `--raw-filter` — all special characters URL-encoded automatically |
| **QID Layer Classification** | 3 conditions: `isBaseLayer` = true → **Base** / false → **Application/Child** / null → **null** |
| **Parent Base Image SHA** | Shows the base image SHA from the `baseImage` field |
| **Vuln Title, CVE IDs, Patch Available** | Enriched from per-image vuln API call |
| **Layer Created By** | Shows the exact Docker instruction that created each layer |
| **Limit 250 per page** | Hardcoded for maximum throughput |
| **Idempotent** | Checkpoint per phase, re-run resumes, `--force` for fresh |
| **Rate-limit aware** | Reads `X-RateLimit-Remaining`, honours `Retry-After` on 429 |
| **Atomic writes** | Temp file → rename, no corrupt files on crash |
| **Streaming / constant memory** | ~10 MB regardless of image count |
| **Duplicate detection** | Stops pagination when API returns repeated data — tested up to 50,000 images |
| **Vuln cache** | Per-image vuln details cached to `vuln_cache/` for resume |

---

## Prerequisites

**Python 3.8+** and **curl**. No pip packages required.

```bash
# Ubuntu / Debian
sudo apt-get install -y python3 curl

# macOS
brew install python3 curl
```

---

## Quick Start

```bash
git clone https://github.com/<your-org>/qualys_image_snow_report.git
cd qualys_image_snow_report

export QUALYS_USERNAME="myuser"
export QUALYS_PASSWORD="mypass"

python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com
```

---

## Usage

```bash
# Basic — last 1 day
python3 qualys_image_snow_report.py -g https://gateway.qg2.apps.qualys.com

# Last 30 days
python3 qualys_image_snow_report.py -g ... -d 30

# Custom QQL filter (appended to default)
python3 qualys_image_snow_report.py -g ... -f "vulnerabilities.severity:5"

# Full raw QQL (overrides -d and -f)
python3 qualys_image_snow_report.py -g ... \
    --raw-filter "imagesInUse:\`[now-30d ... now]\` and operatingSystem:Ubuntu"

# Dry run / Force / Quiet
python3 qualys_image_snow_report.py -g ... --dry-run
python3 qualys_image_snow_report.py -g ... --force
python3 qualys_image_snow_report.py -g ... -q --force
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--username` | Qualys username | `$QUALYS_USERNAME` |
| `-p`, `--password` | Qualys password | `$QUALYS_PASSWORD` |
| `-g`, `--gateway` | Qualys gateway URL | US-2 |
| `-d`, `--days` | Lookback days | 1 |
| `-f`, `--filter` | Extra QQL appended with AND | — |
| `--raw-filter` | Complete raw QQL (overrides -d/-f) | — |
| `-l`, `--limit` | Records per page | 250 |
| `-o`, `--output-dir` | Output directory | `./qualys_snow_output` |
| `--force` | Start fresh | false |
| `-r`, `--retries` | Max retries | 3 |
| `--cps` | Max API calls/sec | 2 |
| `-C`, `--curl-extra` | Extra curl args | — |
| `-v`, `--verbose` | Debug output | false |
| `-q`, `--quiet` | Suppress console | false |
| `--dry-run` | Preview, no API calls | false |

---

## Output

```
qualys_snow_output/
├── qualys_image_snow_report.csv     ← Main report (open in Excel)
├── qualys_image_snow_report.json    ← Structured JSON
├── run_summary.json                 ← Machine-readable stats
├── report_YYYYMMDD_HHMMSS.log      ← Execution log
├── pages/                           ← Raw SNOW API responses (resume)
└── vuln_cache/                      ← Per-image vuln details (resume)
```

### CSV Columns (30)

| # | Column | Source | Description |
|---|--------|--------|-------------|
| 1 | `Image_ID` | SNOW | Short 12-char image ID |
| 2 | `Image_SHA` | SNOW | Full SHA256 |
| 3 | `Operating_System` | SNOW | e.g. Alpine Linux 3.16.2 |
| 4 | `Architecture` | SNOW | arm64, amd64 |
| 5 | `Image_Created` | SNOW | Creation timestamp |
| 6 | `Image_Last_Scanned` | SNOW | Last scan timestamp |
| 7 | `Image_Scan_Types` | SNOW | SCA, STATIC, DYNAMIC |
| 8 | `Image_Source` | SNOW | GENERAL, CONTINUOUS_ASSESSMENT |
| 9 | `Registry` | SNOW | e.g. docker.io |
| 10 | `Repository` | SNOW | e.g. library/nginx |
| 11 | `Image_Tag` | SNOW | e.g. v1.2.3 |
| 12 | `Risk_Score` | SNOW | TruRisk score |
| 13 | `Parent_Base_Image` | SNOW | SHA of the parent base image (from `baseImage` field) |
| 14 | `Associated_Container_Count` | SNOW | Running containers using this image |
| 15 | `Total_Vulnerabilities_On_Image` | SNOW | Vuln count |
| 16 | `Vuln_QID` | SNOW | Qualys vulnerability ID |
| 17 | `Vuln_Title` | Vuln API | Full vulnerability title |
| 18 | `Vuln_QDS_Score` | SNOW | QDS score (0-100) |
| 19 | `Vuln_QDS_Severity` | SNOW | CRITICAL/HIGH/MEDIUM/LOW |
| 20 | `Vuln_Scan_Type` | SNOW | SCA/STATIC/DYNAMIC |
| 21 | `Vuln_CVE_IDs` | Vuln API | Comma-separated CVE IDs |
| 22 | `Vuln_Patch_Available` | Vuln API | true / false |
| 23 | `QID_Layer_Type` | SNOW | **Base** / **Application/Child** / **null** |
| 24 | `QID_Layer_SHA` | SNOW | Full 64-char layer SHA |
| 25 | `QID_Layer_Created_By` | SNOW | Docker instruction that created the layer |
| 26 | `Vuln_Affected_Software_Count` | SNOW | Packages affected by this QID |
| 27 | `Software_Name` | SNOW | Package name |
| 28 | `Software_Installed_Version` | SNOW | Installed version |
| 29 | `Software_Fix_Version` | SNOW | Fix version |
| 30 | `Software_Package_Path` | SNOW | JAR/package path |

### QID Layer Classification

| `isBaseLayer` | `QID_Layer_Type` | Meaning |
|---------------|------------------|---------|
| `true` | **Base** | QID from parent/base image layer |
| `false` | **Application/Child** | QID from application Dockerfile layer |
| `null` | **null** | Qualys could not determine |

---

## How It Works

**Phase 0** — POST `/auth` → JWT token (4 hours)

**Phase 1** — GET `/images/snow` paginated (250/page). Duplicate detection stops infinite loops.

**Phase 2** — GET `/images/<SHA>/vuln?type=ALL&applyException=true` per unique image SHA. Gets title, CVE IDs, patchAvailable. Cached to `vuln_cache/`.

**Phase 3** — Stream pages → merge SNOW + vuln data → CSV + JSON (constant ~10 MB memory).

**Phase 4** — Print summary + `run_summary.json`.

### Idempotency

- **Same config re-run** → resumes from checkpoint
- **Config changed** → auto-resets, starts fresh
- **`--force`** → clears everything
- **Ctrl+C** → saves state, resume on next run

---

## Supported Gateways

| Region | URL |
|--------|-----|
| US-1 | `https://gateway.qg1.apps.qualys.com` |
| US-2 | `https://gateway.qg2.apps.qualys.com` |
| US-3 | `https://gateway.qg3.apps.qualys.com` |
| US-4 | `https://gateway.qg4.apps.qualys.com` |
| EU-1 | `https://gateway.qg1.apps.qualys.eu` |
| EU-2 | `https://gateway.qg2.apps.qualys.eu` |
| Canada | `https://gateway.qg1.apps.qualys.ca` |
| India | `https://gateway.qg1.apps.qualys.in` |
| Australia | `https://gateway.qg1.apps.qualys.com.au` |
| UAE | `https://gateway.qg1.apps.qualys.ae` |
| UK | `https://gateway.qg1.apps.qualys.co.uk` |
| KSA | `https://gateway.qg1.apps.qualysksa.com` |
| US Gov | `https://gateway.gov1.qualys.us` |

---

## QQL Reference

Full list of supported QQL tokens:
https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm

---

## CI/CD

### GitHub Actions

```yaml
- name: Generate Qualys Report
  env:
    QUALYS_USERNAME: ${{ secrets.QUALYS_USERNAME }}
    QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
  run: |
    python3 qualys_image_snow_report.py \
        -g "${{ secrets.QUALYS_GATEWAY }}" \
        -d 1 -o ./report -q --force
- uses: actions/upload-artifact@v4
  with:
    name: qualys-snow-report
    path: ./report/
```

### Docker

```bash
docker run --rm \
    -e QUALYS_USERNAME="$USER" \
    -e QUALYS_PASSWORD="$PASS" \
    -v $(pwd)/output:/app/qualys_snow_output \
    qualys-snow-reporter -g "https://gateway.qg2.apps.qualys.com" -d 30
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `HTTP 401` | Invalid credentials |
| `HTTP 403` | No CSAPI permissions |
| `HTTP 404` | Wrong gateway URL |
| `HTTP 429` | Handled automatically |
| Blank Vuln_Title/CVE/Patch columns | Vuln API returned no data for these QIDs (normal for some images) |
| `0 images returned` | Check QQL filter — use `--dry-run` |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
