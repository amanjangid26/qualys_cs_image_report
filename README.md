# Qualys Container Security - Image Vulnerability Report

Enterprise CLI tool that fetches container image records from the Qualys CSAPI SNOW endpoint, classifies each QID vulnerability as originating from the **Base Image** or **Application/Child** layer, and produces a unified CSV + JSON report.

[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange)](LICENSE)

---

## Features

| Feature | Description |
|---------|-------------|
| **Single API endpoint** | Uses only `/images/snow` — one call gets images, layers, vulns, software, and container counts |
| **Flexible QQL filter** | Pass any Qualys QQL expression via CLI — auto URL-encoded |
| **QID Layer Classification** | 3-tier detection: Qualys `isBaseLayer` → heuristic fallback → unclassified |
| **CSV + JSON output** | Fully denormalized CSV (open in Excel and filter) + structured JSON |
| **Base Image detection** | Reports whether Qualys has detected a base image for each image |
| **Container blast radius** | Associated running container count per image |
| **Idempotent** | Checkpoint after each phase. Re-run to resume, not restart. `--force` for fresh |
| **Rate-limit aware** | Reads `X-RateLimit-Remaining`, throttles proactively, honours `Retry-After` on 429 |
| **Exponential backoff + jitter** | Retries transient failures (5xx, timeouts) without thundering herd |
| **Atomic writes** | All files written to temp first, then renamed. No corrupt files on crash |
| **Lock file** | Prevents concurrent runs against the same output directory |
| **Signal handling** | `Ctrl+C` saves state and exits cleanly. Re-run to resume |
| **Streaming / constant memory** | Reads page files one at a time — ~10 MB regardless of image count |

---

## Prerequisites

**Python 3.8+** and **curl**.  No pip packages required.

```bash
# Ubuntu / Debian
sudo apt-get install -y python3 curl

# RHEL / Amazon Linux
sudo yum install -y python3 curl

# macOS
brew install python3 curl
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/<your-org>/qualys_image_snow_report.git
cd qualys_image_snow_report

# 2. Set credentials
export QUALYS_USERNAME="myuser"
export QUALYS_PASSWORD="mypass"

# 3. Run
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com
```

Reports land in `./qualys_snow_output/`.

---

## Getting Your Credentials

1. Log in to the **Qualys Platform**
2. Your Qualys **username** and **password** are the same ones you use to log in
3. Set them as environment variables (recommended) or pass via `-u` and `-p` flags

> **Never commit credentials to git.** Use environment variables, Vault, or a secrets manager.

---

## Usage

### Basic

```bash
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com
```

### Custom lookback and page size

```bash
# Last 30 days, 250 images per page (max throughput)
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com \
    -d 30 -l 250
```

### Custom QQL filter (appended to default)

```bash
# Only images with severity 5 vulns
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com \
    -f "vulnerabilities.severity:5"

# Only Ubuntu images
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com \
    -f "operatingSystem:Ubuntu"

# Specific registry
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com \
    -f "repo.registry:\`docker.io\`"
```

### Raw QQL filter (complete override)

When you use `--raw-filter`, it **replaces** the entire default filter.  Write any valid QQL — the script URL-encodes it automatically.

```bash
# Full QQL from the Qualys UI search bar
python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com \
    --raw-filter "imagesInUse:\`[now-30d ... now]\` and vulnerabilities.severity:5"
```

### Other options

```bash
# Dry run — preview config and URLs, no API calls
python3 qualys_image_snow_report.py -g ... --dry-run

# Force fresh run (ignore checkpoint)
python3 qualys_image_snow_report.py -g ... --force

# Quiet mode (cron / CI)
python3 qualys_image_snow_report.py -g ... -q --force

# Via proxy
python3 qualys_image_snow_report.py -g ... \
    -C "--proxy http://proxy.corp.com:8080"
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--username` | Qualys username | `$QUALYS_USERNAME` |
| `-p`, `--password` | Qualys password | `$QUALYS_PASSWORD` |
| `-g`, `--gateway` | Qualys gateway URL | `$QUALYS_GATEWAY` or US-2 |
| `-d`, `--days` | Image lookback days (for default filter) | 1 |
| `-f`, `--filter` | Extra QQL appended with AND | — |
| `--raw-filter` | Complete raw QQL (overrides -d and -f) | — |
| `-l`, `--limit` | Results per API page | 50 |
| `-o`, `--output-dir` | Output directory | `./qualys_snow_output` |
| `--force` | Ignore checkpoint, start fresh | false |
| `-r`, `--retries` | Max retries per API call | 3 |
| `--cps` | Max API calls per second | 2 |
| `-C`, `--curl-extra` | Extra curl args (e.g. `--proxy`) | — |
| `-v`, `--verbose` | Debug output | false |
| `-q`, `--quiet` | Suppress console output | false |
| `--dry-run` | Preview config, no API calls | false |

All flags can also be set via environment variables with `QUALYS_` prefix.

---

## Output

```
qualys_snow_output/
├── qualys_image_snow_report.csv     ← Main report (open in Excel)
├── qualys_image_snow_report.json    ← Structured JSON
├── run_summary.json                 ← Machine-readable execution stats
├── report_YYYYMMDD_HHMMSS.log      ← Execution log
└── pages/                           ← Raw API responses (for resume)
```

### CSV Columns (26)

| # | Column | Description |
|---|--------|-------------|
| 1 | `Image_ID` | Short 12-char image ID |
| 2 | `Image_SHA` | Full SHA256 |
| 3 | `Operating_System` | e.g. Alpine Linux 3.16.2, Debian Linux 12.13 |
| 4 | `Architecture` | arm64, amd64 |
| 5 | `Image_Created` | Creation timestamp (ISO 8601) |
| 6 | `Image_Last_Scanned` | Last Qualys scan timestamp |
| 7 | `Image_Scan_Types` | SCA, STATIC, DYNAMIC |
| 8 | `Image_Source` | GENERAL, CONTINUOUS_ASSESSMENT |
| 9 | `Registry` | e.g. docker.io, mcr.microsoft.com |
| 10 | `Repository` | e.g. library/nginx |
| 11 | `Image_Tag` | e.g. v1.2.3, latest |
| 12 | `Risk_Score` | Qualys TruRisk score |
| 13 | `Base_Image_Detected` | Yes/No — whether Qualys detected a base image |
| 14 | `Associated_Container_Count` | Running containers using this image |
| 15 | `Total_Vulnerabilities_On_Image` | Vuln count on the image |
| 16 | `Vuln_QID` | Qualys vulnerability ID |
| 17 | `Vuln_QDS_Score` | QDS score (0–100) |
| 18 | `Vuln_QDS_Severity` | CRITICAL / HIGH / MEDIUM / LOW |
| 19 | `Vuln_Scan_Type` | How this vuln was found (SCA/STATIC/DYNAMIC) |
| 20 | `QID_Layer_Type` | **Base / Application/Child / heuristic / etc.** |
| 21 | `QID_Layer_SHA` | Full 64-char SHA of the layer this QID came from |
| 22 | `Vuln_Affected_Software_Count` | # of packages affected by this QID |
| 23 | `Software_Name` | Affected package name |
| 24 | `Software_Installed_Version` | Currently installed version |
| 25 | `Software_Fix_Version` | Remediation version |
| 26 | `Software_Package_Path` | JAR/package path in the image |

### QID Layer Classification

The `QID_Layer_Type` column evaluates 3 conditions from the Qualys API's `isBaseLayer` field:

| `isBaseLayer` value | `QID_Layer_Type` | Meaning |
|---------------------|------------------|---------|
| `true` | **Base** | Qualys confirmed this QID comes from the base/parent image layer |
| `false` | **Application/Child** | Qualys confirmed this QID comes from an application Dockerfile layer |
| `null` | **null** | Qualys could not determine — base image detection not available for this image |

Edge cases:

| Condition | `QID_Layer_Type` |
|-----------|------------------|
| `layerSha` not found in `layers[]` | `Layer Not Found` |
| QID has no `layerSha` field | *(empty)* |

### Row Logic

| Row type | Driven by | Vuln cols | Software cols |
|----------|-----------|-----------|---------------|
| **Vulnerability** | Each QID × affected software | Filled | Filled |
| **QID-only** | QID with no software detail | Filled | Blank |
| **Bare image** | Image with no vulnerabilities | Blank | Blank |

Multi-registry images get **separate rows per registry** — no pipe-delimited values.

---

## How It Works

### Phase 0: Authentication
POST `/auth` with username + password → JWT token (valid 4 hours).  Credentials URL-encoded to handle special characters.

### Phase 1: Fetch images
GET `/images/snow` with offset-based pagination.  Each page saved to `pages/snow_NNNN.json` for crash recovery.  Continues until the API returns fewer records than the limit — no upper bound on image count.

### Phase 2: Report generation
Streams through page files one at a time (constant ~10 MB memory).  Cross-references each QID's `layerSha` against the image's `layers[]` to classify Base vs Application.  Writes CSV + JSON atomically.

### Phase 3: Summary
Prints execution stats and writes `run_summary.json`.

### Idempotency

Each phase writes a checkpoint file.  On re-run:
- **Same config** → resumes from last checkpoint
- **Config changed** → starts fresh automatically
- **`--force`** → clears checkpoint, starts fresh
- **`Ctrl+C` mid-run** → saves state, resume on next run

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

## CI/CD

### Cron

```bash
0 2 * * * QUALYS_USERNAME="$(cat /etc/qualys/user)" \
          QUALYS_PASSWORD="$(cat /etc/qualys/pass)" \
    python3 /opt/qualys_image_snow_report.py \
    -g "https://gateway.qg2.apps.qualys.com" \
    -d 1 -o /data/qualys/$(date +\%Y\%m\%d) -q --force
```

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

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY qualys_image_snow_report.py /app/
WORKDIR /app
ENTRYPOINT ["python3", "qualys_image_snow_report.py"]
```

```bash
docker run --rm \
    -e QUALYS_USERNAME="$USER" \
    -e QUALYS_PASSWORD="$PASS" \
    -v $(pwd)/output:/app/qualys_snow_output \
    qualys-snow-reporter \
    -g "https://gateway.qg2.apps.qualys.com" -d 30
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `HTTP 401` | Credentials invalid — check username/password |
| `HTTP 403` | User lacks CSAPI permissions |
| `HTTP 404` | Wrong gateway URL — check your region |
| `HTTP 429` | Handled automatically. Reduce `--cps` if persistent |
| `Another instance running` | Wait, or use `--force` |
| `0 images returned` | Check your QQL filter — use `--dry-run` to preview |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
