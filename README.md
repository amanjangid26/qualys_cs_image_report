# Qualys CS - Image SNOW Vulnerability Report

Enterprise CLI tool for generating container image vulnerability reports from the Qualys CSAPI SNOW endpoint.

Fetches all images, enriches each QID with vulnerability title, CVE IDs, and patch availability via multi-threaded API calls, classifies each QID as Base or Application/Child layer, and produces CSV + JSON reports.

## Prerequisites

- Python 3.8+
- curl

No pip packages required.

## Quick Start

```bash
export QUALYS_USERNAME="myuser"
export QUALYS_PASSWORD="mypass"

python3 qualys_image_snow_report.py \
    -g https://gateway.qg2.apps.qualys.com
```

## Usage

```bash
# Last 30 days
python3 qualys_image_snow_report.py -g https://gateway.qg2.apps.qualys.com -d 30

# Custom QQL filter (appended to default imagesInUse filter)
python3 qualys_image_snow_report.py -g ... -f "vulnerabilities.severity:5"
python3 qualys_image_snow_report.py -g ... -f "operatingSystem:Ubuntu"
python3 qualys_image_snow_report.py -g ... -f "repo.registry:\`docker.io\`"

# Full raw QQL (overrides -d and -f entirely)
python3 qualys_image_snow_report.py -g ... \
    --raw-filter "imagesInUse:\`[now-30d ... now]\` and vulnerabilities.severity:5"

# Dry run (preview URLs, no API calls)
python3 qualys_image_snow_report.py -g ... --dry-run

# Fresh run (ignore cached data)
python3 qualys_image_snow_report.py -g ... --force

# Quiet mode (cron/CI)
python3 qualys_image_snow_report.py -g ... -q --force
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--username` | Qualys username | `$QUALYS_USERNAME` |
| `-p`, `--password` | Qualys password | `$QUALYS_PASSWORD` |
| `-g`, `--gateway` | Gateway URL | US-2 |
| `-d`, `--days` | Lookback days | 1 |
| `-f`, `--filter` | Extra QQL (appended with AND) | — |
| `--raw-filter` | Complete raw QQL (overrides -d/-f) | — |
| `-l`, `--limit` | Records per page | 250 |
| `--threads` | Threads for vuln enrichment | 5 |
| `-o`, `--output-dir` | Output directory | `./qualys_snow_output` |
| `--force` | Ignore checkpoint, start fresh | false |
| `-r`, `--retries` | Max retries per call | 3 |
| `--cps` | Max API calls/sec | 2 |
| `-C`, `--curl-extra` | Extra curl args | — |
| `-v`, `--verbose` | Debug output | false |
| `-q`, `--quiet` | Suppress console | false |
| `--dry-run` | Preview, no API calls | false |

## API Endpoints

| # | Endpoint | Purpose |
|---|----------|---------|
| 1 | `POST /auth` | JWT authentication |
| 2 | `GET /images/snow?filter=<QQL>&limit=250` | All images (paginated) |
| 3 | `GET /images/<SHA>/vuln?type=ALL&applyException=true` | Vuln details per image (multi-threaded) |

## Output

```
qualys_snow_output/
├── qualys_image_snow_report.csv    # Main report
├── qualys_image_snow_report.json   # Structured JSON
├── run_summary.json                # Execution stats
├── report_YYYYMMDD_HHMMSS.log     # Log file
├── pages/                          # SNOW API cache (resume)
└── vuln_cache/                     # Vuln API cache (resume)
```

## CSV Columns (27)

| # | Column | Description |
|---|--------|-------------|
| 1 | `Image_ID` | 12-char image ID |
| 2 | `Image_SHA` | Full SHA256 |
| 3 | `Operating_System` | OS name |
| 4 | `Architecture` | arm64, amd64 |
| 5 | `Image_Created` | Creation date |
| 6 | `Image_Last_Scanned` | Last scan date |
| 7 | `Image_Scan_Types` | SCA, STATIC, DYNAMIC |
| 8 | `Image_Source` | GENERAL, CONTINUOUS_ASSESSMENT |
| 9 | `Registry` | Container registry |
| 10 | `Repository` | Image repository |
| 11 | `Image_Tag` | Image tag |
| 12 | `Risk_Score` | TruRisk score |
| 13 | `Parent_Base_Image` | Base image SHA (from `baseImage` field) |
| 14 | `Associated_Container_Count` | Running containers |
| 15 | `Total_Vulnerabilities_On_Image` | Vuln count |
| 16 | `Vuln_QID` | Qualys QID |
| 17 | `Vuln_Title` | Vulnerability title |
| 18 | `Vuln_QDS_Score` | QDS score |
| 19 | `Vuln_QDS_Severity` | CRITICAL/HIGH/MEDIUM/LOW |
| 20 | `Vuln_Scan_Type` | Detection method |
| 21 | `Vuln_CVE_IDs` | CVE IDs (comma-separated) |
| 22 | `Vuln_Patch_Available` | true/false |
| 23 | `QID_Layer_Type` | Base / Application/Child / null |
| 24 | `QID_Layer_SHA` | Full layer SHA |
| 25 | `Docker_Layer_Instruction` | Docker instruction that created the layer |
| 26 | `Affected_Packages` | Clubbed: `pkg1 (v1 -> v2) \| pkg2 (v3 -> v4)` |
| 27 | `Affected_Package_Paths` | Package paths (pipe-separated) |

## QID Layer Classification

| `isBaseLayer` | Column Value | Meaning |
|---------------|-------------|---------|
| `true` | Base | QID from base/parent image |
| `false` | Application/Child | QID from application layer |
| `null` | null | Qualys could not determine |

## How It Works

1. **Phase 0** — `POST /auth` → JWT token
2. **Phase 1** — `GET /images/snow` paginated (250/page, duplicate detection)
3. **Phase 2** — `GET /images/<SHA>/vuln` per image (multi-threaded, cached)
4. **Phase 3** — Generate CSV + JSON (streaming, ~10 MB memory)

Each phase checkpointed. Re-run resumes. `--force` resets. `Ctrl+C` saves state.

## Supported Gateways

US-1 `qg1.apps.qualys.com` · US-2 `qg2.apps.qualys.com` · US-3 `qg3.apps.qualys.com` · US-4 `qg4.apps.qualys.com` · EU-1 `qg1.apps.qualys.eu` · EU-2 `qg2.apps.qualys.eu` · CA `qg1.apps.qualys.ca` · IN `qg1.apps.qualys.in` · AU `qg1.apps.qualys.com.au` · UAE `qg1.apps.qualys.ae` · UK `qg1.apps.qualys.co.uk` · KSA `qg1.apps.qualysksa.com` · GOV `gov1.qualys.us`

## QQL Reference

https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm

## License

Apache 2.0
