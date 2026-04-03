#!/usr/bin/env python3
"""
=============================================================================
Qualys Container Security — Image SNOW Vulnerability Report
Version: 2.0.0
Author:  Qualys CS Engineering
License: Apache 2.0
=============================================================================

Enterprise CLI tool that fetches container-image records from the Qualys
CSAPI SNOW endpoint, classifies each QID vulnerability as originating from
the Base image or Application/Child layer, includes associated container
counts, and produces a unified CSV + JSON report.

─── SINGLE API ENDPOINT ────────────────────────────────────────────────────

    GET /csapi/v1.3/images/snow?filter=<QQL>&limit=N

    The filter accepts any valid Qualys QQL expression.  The script
    URL-encodes it automatically — you write the QQL in plain text.

─── HOW IT WORKS ───────────────────────────────────────────────────────────

    Phase 0 — AUTHENTICATION
        POST /auth with username + password → JWT token (valid 4 hours).
        Credentials URL-encoded to handle special chars in passwords.

    Phase 1 — FETCH ALL IMAGES
        Offset-based pagination.  Each page saved to pages/snow_NNNN.json
        for crash recovery.  Loops until API returns fewer records than
        the limit — no upper bound on image count.

    Phase 2 — REPORT GENERATION  (streaming, constant memory ~10 MB)
        Reads page files one at a time.  For each image → for each QID →
        for each affected software package → one CSV row.

        QID LAYER CLASSIFICATION:
            Each QID has a layerSha[].  We match it against the image's
            layers[] array and check the "isBaseLayer" field:

                isBaseLayer = true  →  "Base"
                isBaseLayer = false →  "Application/Child"
                isBaseLayer = null  →  "null"

    Phase 3 — RUN SUMMARY
        Writes run_summary.json with machine-readable execution stats.

─── FEATURES ───────────────────────────────────────────────────────────────

    • Flexible QQL filter — pass ANY Qualys QQL via -f (auto URL-encoded)
    • Idempotent — checkpoint per phase, re-run resumes, --force resets
    • Atomic writes — temp file → rename, zero corrupt files on crash
    • Lock file — prevents concurrent runs on the same output directory
    • Signal handling — Ctrl+C saves state and exits cleanly
    • Rate-limit aware — reads X-RateLimit-Remaining, honours Retry-After
    • Exponential backoff + jitter on transient failures (5xx, timeouts)
    • Streaming page iterator — constant ~10 MB memory regardless of scale
    • No pip packages — Python 3.8+ standard library + curl only

─── PREREQUISITES ──────────────────────────────────────────────────────────

    Python 3.8+
    curl

    # Ubuntu / Debian
    sudo apt-get install -y python3 curl

    # RHEL / Amazon Linux
    sudo yum install -y python3 curl

    # macOS
    brew install python3 curl

=============================================================================
"""

# =============================================================================
# IMPORTS — Python standard library only, no pip packages required
# =============================================================================
import argparse
import atexit
import csv
import hashlib
import json
import logging
import os
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote as url_encode

VERSION = "2.0.0"

# =============================================================================
# DEFAULTS
# =============================================================================
DEFAULT_GATEWAY         = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION     = "v1.3"
DEFAULT_PAGE_LIMIT      = 50
DEFAULT_LOOKBACK_DAYS   = 1
DEFAULT_MAX_RETRIES     = 3
DEFAULT_CONNECT_TIMEOUT = 15
DEFAULT_REQUEST_TIMEOUT = 90
DEFAULT_CALLS_PER_SEC   = 2

# =============================================================================
# SUPPORTED QUALYS GATEWAYS
# =============================================================================
GATEWAYS = {
    "US-1": "https://gateway.qg1.apps.qualys.com",
    "US-2": "https://gateway.qg2.apps.qualys.com",
    "US-3": "https://gateway.qg3.apps.qualys.com",
    "US-4": "https://gateway.qg4.apps.qualys.com",
    "EU-1": "https://gateway.qg1.apps.qualys.eu",
    "EU-2": "https://gateway.qg2.apps.qualys.eu",
    "CA":   "https://gateway.qg1.apps.qualys.ca",
    "IN":   "https://gateway.qg1.apps.qualys.in",
    "AU":   "https://gateway.qg1.apps.qualys.com.au",
    "UAE":  "https://gateway.qg1.apps.qualys.ae",
    "UK":   "https://gateway.qg1.apps.qualys.co.uk",
    "KSA":  "https://gateway.qg1.apps.qualysksa.com",
    "GOV":  "https://gateway.gov1.qualys.us",
}

# =============================================================================
# SIGNAL HANDLING — graceful shutdown on Ctrl+C or SIGTERM
# =============================================================================
_shutdown_requested = False

def _handle_shutdown(signal_number, _frame):
    global _shutdown_requested
    sig_name = signal.Signals(signal_number).name
    print(f"\n[!] {sig_name} received — saving progress and exiting...",
          file=sys.stderr)
    _shutdown_requested = True

signal.signal(signal.SIGINT,  _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)

def _check_shutdown():
    """Call periodically.  Raises SystemExit(130) if Ctrl+C was pressed."""
    if _shutdown_requested:
        raise SystemExit(130)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def safe_str(value):
    """Convert None or literal 'None' to empty string."""
    if value is None or value == "None":
        return ""
    return str(value)


def epoch_ms_to_iso(epoch_milliseconds):
    """Convert Qualys epoch-milliseconds to ISO 8601 string.
    Returns empty string for null, '0', or invalid values."""
    if not epoch_milliseconds or str(epoch_milliseconds) == "0":
        return ""
    try:
        seconds = int(epoch_milliseconds) / 1000
        return datetime.fromtimestamp(
            seconds, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_milliseconds)


def write_json_atomically(file_path, data):
    """Write JSON via temp file → atomic rename.  No corrupt files on crash."""
    directory = os.path.dirname(file_path)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, file_path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def remove_file_silently(file_path):
    """Remove a file, ignoring errors if it doesn't exist."""
    try:
        os.remove(file_path)
    except OSError:
        pass


def format_duration(total_seconds):
    """Format seconds into human-readable duration string."""
    total_seconds = int(total_seconds)
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        return f"{total_seconds // 60}m{total_seconds % 60}s"
    return f"{total_seconds // 3600}h{(total_seconds % 3600) // 60}m"


def get_qds_severity(score):
    """Map Qualys QDS score to severity label."""
    if score is None:
        return ""
    score = int(score)
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def generate_config_fingerprint(args):
    """Hash of config params — checkpoint auto-resets when config changes."""
    config = f"{args.gateway}|{args.days}|{args.limit}|{args.filter or ''}"
    return hashlib.sha256(config.encode()).hexdigest()[:16]


def encode_qql_filter(qql_filter_text):
    """URL-encode a raw QQL filter string for use in the API URL.

    The user writes plain QQL like:
        imagesInUse:`[now-30d ... now]`
        vulnerabilities.severity:5 and operatingSystem:Ubuntu
        repo.registry:`registry-1.docker.io`

    This function encodes ALL special characters for safe HTTP transport:
        :  →  %3A       `  →  %60       [  →  %5B
        ]  →  %5D       space → %20     '  →  %27
        &  →  %26       =  →  %3D       +  →  %2B
        #  →  %23       @  →  %40       !  →  %21
        $  →  %24       /  →  %2F       etc.

    Uses safe='' which encodes EVERYTHING — no character passes through
    unencoded.  This guarantees the QQL string is safe in a URL query
    parameter regardless of what special characters the user includes.
    """
    return url_encode(qql_filter_text, safe='')

# =============================================================================
# LOGGING
# =============================================================================
def setup_logging(output_directory, verbose_mode, quiet_mode):
    """Configure dual logging: file (DEBUG) + console (INFO or DEBUG)."""
    logger = logging.getLogger("qualys_snow")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_filename)

    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

    if not quiet_mode:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(
            logging.DEBUG if verbose_mode else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

    return logger, log_file_path

# =============================================================================
# LOCK FILE — prevent concurrent runs against the same output directory
# =============================================================================
def acquire_lock(output_directory, force_mode):
    lock_path = os.path.join(output_directory, ".lock")
    if os.path.exists(lock_path):
        try:
            existing_pid = int(open(lock_path).read().strip())
            os.kill(existing_pid, 0)      # check if process is alive
            if not force_mode:
                print(f"ERROR: Another instance running (PID {existing_pid}). "
                      f"Use --force to override.", file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass      # stale lock from a crashed process — safe to overwrite
    open(lock_path, "w").write(str(os.getpid()))
    atexit.register(lambda: remove_file_silently(lock_path))

# =============================================================================
# CHECKPOINT — idempotent execution, resume on re-run
# =============================================================================
class CheckpointManager:
    """Tracks completed phases.  Config change auto-resets checkpoint."""

    def __init__(self, output_directory, config_fingerprint):
        self.file_path = os.path.join(output_directory, ".checkpoint.json")
        self.fingerprint = config_fingerprint
        self.state = {}
        if os.path.exists(self.file_path):
            try:
                self.state = json.load(open(self.file_path))
                if self.state.get("fingerprint") != config_fingerprint:
                    self.state = {}      # config changed → reset
            except (json.JSONDecodeError, KeyError):
                self.state = {}

    def is_done(self, phase_name):
        return self.state.get(phase_name) is True

    def mark_done(self, phase_name):
        self.state[phase_name] = True
        self.state["fingerprint"] = self.fingerprint
        write_json_atomically(self.file_path, self.state)

    def clear(self):
        remove_file_silently(self.file_path)
        self.state = {}

# =============================================================================
# JWT AUTHENTICATION — POST /auth (username + password → token)
# =============================================================================
def generate_jwt_token(gateway_url, username, password,
                       connect_timeout, logger):
    """Authenticate to Qualys and return a JWT token.

    POST https://<gateway>/auth
    Content-Type: application/x-www-form-urlencoded
    Body: username=<encoded>&password=<encoded>&token=true

    Credentials are URL-encoded to handle special characters:
        "P@ss&word#1" → "P%40ss%26word%231"
    """
    auth_url = f"{gateway_url.rstrip('/')}/auth"
    logger.info(f"  Authenticating as '{username}'...")

    encoded_user = url_encode(username, safe='')
    encoded_pass = url_encode(password, safe='')

    cmd = [
        "curl", "-s", "-w", "\n%{http_code}",
        "--connect-timeout", str(connect_timeout),
        "--max-time", "30",
        "-X", "POST", auth_url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", f"username={encoded_user}"
              f"&password={encoded_pass}&token=true",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")
        http_code = int(lines[-1]) if lines[-1].isdigit() else 0
        response_body = "\n".join(lines[:-1]).strip()
    except Exception as error:
        logger.error(f"  Authentication failed: {error}")
        sys.exit(1)

    if http_code in (200, 201) and response_body:
        token = response_body.strip()
        if token.startswith("eyJ"):
            logger.info(
                f"  Token obtained: {token[:15]}...{token[-6:]}"
                f"  (valid ~4 hours)")
            return token
        else:
            logger.error(
                f"  Unexpected auth response: {response_body[:100]}")
            sys.exit(1)
    elif http_code == 401:
        logger.error("  Authentication failed: invalid username or password.")
    elif http_code == 0:
        logger.error(
            f"  Connection failed.  Check gateway URL: {gateway_url}")
    else:
        logger.error(f"  Authentication failed: HTTP {http_code}")
        if response_body:
            logger.error(f"  Response: {response_body[:200]}")
    sys.exit(1)

# =============================================================================
# RATE LIMITER — thread-safe, reads Qualys rate-limit headers
# =============================================================================
class RateLimiter:
    def __init__(self, max_calls_per_second, logger):
        self.min_interval = 1.0 / max_calls_per_second
        self.logger = logger
        self.lock = threading.Lock()
        self.last_call_time = 0.0
        self.global_pause_until = 0.0
        self.total_throttle_events = 0

    def acquire(self):
        """Block until it's safe to make the next API call."""
        while True:
            _check_shutdown()
            with self.lock:
                now = time.time()
                if now < self.global_pause_until:
                    wait = self.global_pause_until - now
                    self.lock.release()
                    time.sleep(wait)
                    self.lock.acquire()
                    continue
                elapsed = now - self.last_call_time
                if elapsed < self.min_interval:
                    wait = self.min_interval - elapsed
                    self.lock.release()
                    time.sleep(wait)
                    self.lock.acquire()
                    continue
                self.last_call_time = time.time()
                return

    def read_rate_limit_headers(self, header_file_path):
        """Parse Qualys rate-limit headers and throttle if needed."""
        if not os.path.exists(header_file_path):
            return
        remaining = window = None
        try:
            for line in open(header_file_path):
                lower = line.lower().strip()
                if lower.startswith("x-ratelimit-remaining:"):
                    remaining = int(line.split(":", 1)[1].strip())
                elif lower.startswith("x-ratelimit-window-sec:"):
                    window = int(line.split(":", 1)[1].strip())
        except Exception:
            return
        with self.lock:
            if remaining is not None and remaining <= 0:
                pause = (window or 60) + 5
                self.global_pause_until = time.time() + pause
                self.logger.warning(
                    f"  Rate limit exhausted — pausing {pause}s")
                self.total_throttle_events += 1
            elif remaining is not None and remaining <= 20:
                self.min_interval = max(self.min_interval, 1.0)

    def handle_http_429(self, header_file_path):
        """Handle HTTP 429 Too Many Requests."""
        retry_after = None
        if os.path.exists(header_file_path):
            try:
                for line in open(header_file_path):
                    if line.lower().strip().startswith("retry-after:"):
                        retry_after = int(line.split(":", 1)[1].strip())
            except Exception:
                pass
        pause = retry_after or 35
        with self.lock:
            self.global_pause_until = time.time() + pause
            self.logger.warning(f"  HTTP 429 — pausing {pause}s")
            self.total_throttle_events += 1

# =============================================================================
# API CLIENT — curl-based, retries with backoff, rate-limit aware
# =============================================================================
class QualysApiClient:
    def __init__(self, gateway_url, access_token, max_retries,
                 connect_timeout, request_timeout, extra_curl_args,
                 rate_limiter, logger):
        self.gateway = gateway_url.rstrip("/")
        self.token = access_token
        self.max_retries = max_retries
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.extra_curl_args = extra_curl_args
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.total_api_calls = 0
        self.total_retries = 0
        self.total_errors = 0

    def make_request(self, url, output_file_path, keep_headers=False):
        """Execute a GET request.  Returns HTTP status code or 0 on failure."""
        for attempt in range(self.max_retries + 1):
            _check_shutdown()

            if attempt > 0:
                delay = random.uniform(1, min(15, 2 ** attempt))
                self.logger.debug(
                    f"  Retry {attempt}/{self.max_retries} "
                    f"in {delay:.0f}s...")
                time.sleep(delay)
                self.total_retries += 1

            self.rate_limiter.acquire()

            header_file = output_file_path + ".hdr"
            curl_cmd = [
                "curl", "-s",
                "-o", output_file_path,
                "-D", header_file,
                "-w", "%{http_code}",
                "--connect-timeout", str(self.connect_timeout),
                "--max-time", str(self.request_timeout),
                "-X", "GET", url,
                "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.token}",
            ]
            if self.extra_curl_args:
                curl_cmd.extend(self.extra_curl_args.split())

            try:
                result = subprocess.run(
                    curl_cmd, capture_output=True, text=True)
                http_code = int(result.stdout.strip()) \
                    if result.stdout.strip().isdigit() else 0
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self.total_api_calls += 1
                self.total_errors += 1
                continue

            self.total_api_calls += 1
            self.rate_limiter.read_rate_limit_headers(header_file)

            if http_code in (200, 204):
                if not keep_headers:
                    remove_file_silently(header_file)
                return http_code

            if http_code == 401:
                self.logger.error(
                    "HTTP 401 — token expired or invalid.  Re-run to "
                    "re-authenticate.")
                sys.exit(1)
            if http_code == 403:
                self.logger.error(
                    "HTTP 403 — insufficient permissions for this API.")
                sys.exit(1)
            if http_code == 404:
                self.logger.error(f"HTTP 404 — endpoint not found: {url}")
                sys.exit(1)
            if http_code == 429:
                self.rate_limiter.handle_http_429(header_file)
            else:
                self.logger.debug(f"  HTTP {http_code}")

            remove_file_silently(header_file)

        self.total_errors += 1
        return 0

    def fetch_all_snow_pages(self, base_url, pages_directory,
                             page_limit, label="snow"):
        """Paginate through the SNOW endpoint via offset.

        Each page saved to pages/snow_NNNN.json for crash recovery.
        Continues until API returns fewer records than the limit.
        No upper bound on total images.
        """
        all_records = []
        page_number = 1
        offset = 0

        while True:
            _check_shutdown()

            separator = "&" if "?" in base_url else "?"
            url = f"{base_url}{separator}offset={offset}"
            page_file = os.path.join(
                pages_directory, f"{label}_{page_number:04d}.json")

            # ── Resume from cached page ──
            if os.path.exists(page_file):
                try:
                    cached_data = json.load(open(page_file)).get("data", [])
                    if isinstance(cached_data, list) and cached_data:
                        all_records.extend(cached_data)
                        self.logger.info(
                            f"  page {page_number}: {len(cached_data)} images "
                            f"(cached, total: {len(all_records)})")
                        if len(cached_data) < page_limit:
                            break      # last page
                        offset += page_limit
                        page_number += 1
                        continue
                except (json.JSONDecodeError, KeyError):
                    pass      # corrupted cache — re-fetch

            # ── Fetch from API ──
            self.logger.info(
                f"  Fetching page {page_number} (offset={offset})...")
            code = self.make_request(url, page_file)

            if code != 200:
                self.logger.error(
                    f"  Failed page {page_number} (HTTP {code})")
                break

            try:
                page_data = json.load(open(page_file)).get("data", [])
            except (json.JSONDecodeError, KeyError):
                self.logger.error(
                    f"  Failed to parse page {page_number}")
                break

            if not isinstance(page_data, list):
                break

            all_records.extend(page_data)
            self.logger.info(
                f"  page {page_number}: {len(page_data)} images "
                f"(total: {len(all_records)})")

            if len(page_data) < page_limit:
                break      # last page

            offset += page_limit
            page_number += 1

        self.logger.info(
            f"  Fetched {len(all_records)} images across "
            f"{page_number} page(s)")
        return all_records

# =============================================================================
# STREAMING PAGE ITERATOR — constant memory, reads one page at a time
# =============================================================================
def iterate_images_from_pages(pages_directory, label):
    """Yield images one at a time from saved page files.
    Each page loaded → yielded → garbage collected.
    Memory stays at ~10 MB regardless of total image count."""
    page = 1
    while True:
        page_file = os.path.join(
            pages_directory, f"{label}_{page:04d}.json")
        if not os.path.exists(page_file):
            break
        try:
            page_data = json.load(open(page_file)).get("data", [])
            if not isinstance(page_data, list) or not page_data:
                break
            yield from page_data
            page += 1
        except (json.JSONDecodeError, KeyError):
            break


def count_images_from_pages(pages_directory, label):
    """Count total images across page files without loading all into memory."""
    total = 0
    page = 1
    while True:
        page_file = os.path.join(
            pages_directory, f"{label}_{page:04d}.json")
        if not os.path.exists(page_file):
            break
        try:
            page_data = json.load(open(page_file)).get("data", [])
            if not isinstance(page_data, list) or not page_data:
                break
            total += len(page_data)
            page += 1
        except (json.JSONDecodeError, KeyError):
            break
    return total

# =============================================================================
# QID LAYER CLASSIFICATION
#
# Each QID has a "layerSha" field.  We match it against the image's
# "layers" section and read the "isBaseLayer" field on that layer.
#
# 3 conditions only:
#   isBaseLayer = true  →  "Base"
#   isBaseLayer = false →  "Application/Child"
#   isBaseLayer = null  →  "null"
# =============================================================================

def build_layer_sha_map(image):
    """Build lookup dict:  full_sha → isBaseLayer value.

    isBaseLayer values from Qualys API:
        True  — Qualys confirmed this is a base image layer
        False — Qualys confirmed this is an application layer
        None  — Qualys could not determine
    """
    sha_map = {}
    for layer in (image.get("layers") or []):
        sha = layer.get("sha")
        if sha:
            sha_map[sha] = layer.get("isBaseLayer")
    return sha_map


def classify_qid_layer(vuln_layer_shas, layer_sha_map):
    """Classify which layer a QID belongs to.

    Cross-references the QID's layerSha against the image layers[].
    Reads the isBaseLayer field — 3 conditions only:

        isBaseLayer = true  →  "Base"
        isBaseLayer = false →  "Application/Child"
        isBaseLayer = null  →  "null"

    Edge cases:
        layerSha not in layers[]  →  "Layer Not Found"
        QID has no layerSha       →  ""

    Returns: (label, full_sha_string)
    """
    if not vuln_layer_shas:
        return "", ""

    for sha in vuln_layer_shas:
        if sha in layer_sha_map:
            is_base_layer = layer_sha_map[sha]

            if is_base_layer is True:
                return "Base", sha
            elif is_base_layer is False:
                return "Application/Child", sha
            else:
                return "null", sha

    # layerSha exists but doesn't match any known layer
    return "Layer Not Found", (
        vuln_layer_shas[0] if vuln_layer_shas else "")


def extract_repositories(image):
    """Extract registry/repository/tag from image.
    Falls back to repoDigests for registry if missing from repo."""
    repo_entries = image.get("repo") or []
    digest_entries = image.get("repoDigests") or []

    registry_fallback = {
        d["repository"]: d["registry"]
        for d in digest_entries
        if d.get("registry") and d.get("repository")
    }

    result = []
    for repo in repo_entries:
        registry = repo.get("registry") or ""
        repository = safe_str(repo.get("repository"))
        if not registry and repository:
            registry = registry_fallback.get(repository, "")
        result.append({
            "registry":   safe_str(registry),
            "repository": repository,
            "tag":        safe_str(repo.get("tag")),
        })

    return result if result else [
        {"registry": "", "repository": "", "tag": ""}]

# =============================================================================
# CSV + JSON REPORT — 26 columns
#
# Row logic:
#   Image has vulns → 1 row per (repo × QID × affected software)
#   QID with no software → 1 row with empty software cols
#   Image with no vulns → 1 bare row
#   Multi-registry images → separate rows per registry (clean filtering)
# =============================================================================

CSV_HEADERS = [
    # ── Image columns (15) ──
    "Image_ID",
    "Image_SHA",
    "Operating_System",
    "Architecture",
    "Image_Created",
    "Image_Last_Scanned",
    "Image_Scan_Types",
    "Image_Source",
    "Registry",
    "Repository",
    "Image_Tag",
    "Risk_Score",
    "Base_Image_Detected",
    "Associated_Container_Count",
    "Total_Vulnerabilities_On_Image",

    # ── Vulnerability columns (7) ──
    "Vuln_QID",
    "Vuln_QDS_Score",
    "Vuln_QDS_Severity",
    "Vuln_Scan_Type",
    "QID_Layer_Type",
    "QID_Layer_SHA",
    "Vuln_Affected_Software_Count",

    # ── Software columns (4) ──
    "Software_Name",
    "Software_Installed_Version",
    "Software_Fix_Version",
    "Software_Package_Path",
]

EMPTY_VULN_COLS = [""] * 7
EMPTY_SW_COLS = [""] * 4


def generate_csv_report(pages_directory, label, csv_path, logger):
    """Generate CSV report by streaming through page files.
    Memory usage: ~10 MB constant regardless of image count."""
    temp_path = csv_path + ".tmp"
    total_rows = 0
    total_images = 0
    total_vulns = 0

    with open(temp_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_HEADERS)

        for image in iterate_images_from_pages(pages_directory, label):
            total_images += 1
            _check_shutdown()

            sha = image.get("sha", "")
            vulnerabilities = image.get("vulnerabilities") or []
            repositories = extract_repositories(image)
            layer_map = build_layer_sha_map(image)
            container_count = image.get("associatedContainersCount", 0)

            # Base Image field from API response
            base_image_raw = image.get("baseImage")
            base_image_detected = (
                "Yes" if base_image_raw is not None
                and base_image_raw != "" else "No")

            # Image-level columns (shared across repos)
            image_base_cols = [
                safe_str(image.get("imageId")),
                sha,
                safe_str(image.get("operatingSystem")),
                safe_str(image.get("architecture")),
                epoch_ms_to_iso(image.get("created")),
                epoch_ms_to_iso(image.get("lastScanned")),
                " | ".join(
                    safe_str(s) for s in (image.get("scanTypes") or [])),
                " | ".join(
                    safe_str(s) for s in (image.get("source") or [])),
            ]

            for repo in repositories:
                image_cols = image_base_cols + [
                    repo["registry"],
                    repo["repository"],
                    repo["tag"],
                    safe_str(image.get("riskScore")),
                    base_image_detected,
                    str(container_count),
                    str(len(vulnerabilities)),
                ]

                if vulnerabilities:
                    for vuln in vulnerabilities:
                        total_vulns += 1
                        qds_score = vuln.get("qdsScore")
                        layer_type, layer_sha = classify_qid_layer(
                            vuln.get("layerSha") or [], layer_map)
                        software_list = vuln.get("software") or []

                        vuln_cols = [
                            safe_str(vuln.get("qid")),
                            safe_str(qds_score)
                            if qds_score is not None else "",
                            get_qds_severity(qds_score),
                            " | ".join(
                                safe_str(s)
                                for s in (vuln.get("scanType") or [])),
                            layer_type,
                            layer_sha,
                            str(len(software_list)),
                        ]

                        if software_list:
                            for sw in software_list:
                                sw_cols = [
                                    safe_str(sw.get("name")),
                                    safe_str(sw.get("version")),
                                    safe_str(sw.get("fixVersion")),
                                    safe_str(sw.get("packagePath")),
                                ]
                                writer.writerow(
                                    image_cols + vuln_cols + sw_cols)
                                total_rows += 1
                        else:
                            writer.writerow(
                                image_cols + vuln_cols + EMPTY_SW_COLS)
                            total_rows += 1
                else:
                    writer.writerow(
                        image_cols + EMPTY_VULN_COLS + EMPTY_SW_COLS)
                    total_rows += 1

    os.replace(temp_path, csv_path)
    logger.info(
        f"  CSV: {csv_path}  "
        f"({total_rows:,} rows × {len(CSV_HEADERS)} cols)")
    return total_rows, total_images, total_vulns


def generate_json_report(pages_directory, label, json_path, logger):
    """Generate JSON report by streaming through page files."""
    temp_path = json_path + ".tmp"
    total_images = 0
    total_vulns = 0

    with open(temp_path, "w", encoding="utf-8") as f:
        f.write('{\n')
        f.write(
            f'  "generatedAt": '
            f'"{datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}"'
            f',\n')
        f.write('  "images": [\n')

        first = True
        for image in iterate_images_from_pages(pages_directory, label):
            total_images += 1
            _check_shutdown()

            layer_map = build_layer_sha_map(image)
            vulnerabilities = image.get("vulnerabilities") or []
            container_count = image.get("associatedContainersCount", 0)
            base_image_raw = image.get("baseImage")

            qds_scores = [
                v.get("qdsScore") for v in vulnerabilities
                if v.get("qdsScore") is not None
            ]
            max_qds = max(qds_scores) if qds_scores else None

            json_vulns = []
            for vuln in vulnerabilities:
                total_vulns += 1
                qds = vuln.get("qdsScore")
                layer_type, layer_sha = classify_qid_layer(
                    vuln.get("layerSha") or [], layer_map)

                json_vulns.append({
                    "qid": vuln.get("qid"),
                    "qdsScore": qds,
                    "qdsSeverity": get_qds_severity(qds),
                    "scanType": vuln.get("scanType") or [],
                    "qidLayerType": layer_type,
                    "qidLayerSha": layer_sha,
                    "affectedSoftware": [
                        {
                            "name": safe_str(sw.get("name")),
                            "version": safe_str(sw.get("version")),
                            "fixVersion": safe_str(sw.get("fixVersion")),
                            "packagePath": safe_str(sw.get("packagePath")),
                        }
                        for sw in (vuln.get("software") or [])
                    ],
                })

            record = {
                "imageId": safe_str(image.get("imageId")),
                "sha": image.get("sha", ""),
                "operatingSystem": safe_str(
                    image.get("operatingSystem")),
                "architecture": safe_str(image.get("architecture")),
                "riskScore": image.get("riskScore"),
                "baseImageDetected": (
                    base_image_raw is not None
                    and base_image_raw != ""),
                "baseImage": safe_str(base_image_raw),
                "maxQdsScore": max_qds,
                "maxQdsSeverity": get_qds_severity(max_qds),
                "associatedContainerCount": container_count,
                "totalVulnerabilities": len(vulnerabilities),
                "repositories": extract_repositories(image),
                "vulnerabilities": json_vulns,
            }

            if not first:
                f.write(',\n')
            f.write('    ' + json.dumps(record, default=str))
            first = False

        f.write('\n  ],\n')
        f.write(f'  "totalImages": {total_images},\n')
        f.write(f'  "totalVulnerabilities": {total_vulns}\n')
        f.write('}\n')

    os.replace(temp_path, json_path)
    logger.info(f"  JSON: {json_path}")
    return total_images, total_vulns

# =============================================================================
# RUN SUMMARY — printed to console + log, and saved as run_summary.json
# =============================================================================
def print_summary(pages_directory, label, total_rows, total_vulns,
                  elapsed, api_client, rate_limiter, logger):
    """Print execution summary and QID layer classification stats."""
    total_images = count_images_from_pages(pages_directory, label)
    total_containers = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    layer_type_counts = {}

    for image in iterate_images_from_pages(pages_directory, label):
        total_containers += image.get("associatedContainersCount", 0)
        layer_map = build_layer_sha_map(image)
        for vuln in (image.get("vulnerabilities") or []):
            sev = get_qds_severity(vuln.get("qdsScore"))
            if sev in severity_counts:
                severity_counts[sev] += 1
            layer_type, _ = classify_qid_layer(
                vuln.get("layerSha") or [], layer_map)
            if layer_type:
                layer_type_counts[layer_type] = \
                    layer_type_counts.get(layer_type, 0) + 1

    logger.info(f"\n{'=' * 64}")
    logger.info(
        f"  QUALYS IMAGE SNOW — VULNERABILITY REPORT SUMMARY")
    logger.info(f"{'=' * 64}")
    logger.info(
        f"  Generated        : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"  Duration         : {format_duration(elapsed)}")
    logger.info(
        f"  API Calls        : {api_client.total_api_calls}  "
        f"(retries: {api_client.total_retries}, "
        f"errors: {api_client.total_errors})")
    logger.info(f"  Images           : {total_images}")
    logger.info(f"  Vulnerabilities  : {total_vulns}")
    logger.info(f"  CSV Rows         : {total_rows:,}")
    logger.info(f"  Containers at Risk: {total_containers}")
    logger.info(f"{'-' * 64}")
    logger.info(f"  CRITICAL (QDS≥70)  : {severity_counts['CRITICAL']}")
    logger.info(f"  HIGH     (QDS≥40)  : {severity_counts['HIGH']}")
    logger.info(f"  MEDIUM   (QDS≥25)  : {severity_counts['MEDIUM']}")
    logger.info(f"  LOW      (QDS<25)  : {severity_counts['LOW']}")
    logger.info(f"{'-' * 64}")
    logger.info(f"  QID Layer Classification:")
    for label_name in sorted(
            layer_type_counts, key=layer_type_counts.get, reverse=True):
        logger.info(
            f"    {label_name:<30} : {layer_type_counts[label_name]}")
    logger.info(f"{'=' * 64}")

# =============================================================================
# CLI — command-line argument parsing
# =============================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="qualys_image_snow_report",
        description=(
            f"Qualys CS Image SNOW Vulnerability Report v{VERSION}\n\n"
            f"Fetches container images from the Qualys SNOW API, classifies\n"
            f"each QID as Base or Application/Child layer, and produces a\n"
            f"unified CSV + JSON report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
─── AUTHENTICATION ─────────────────────────────────────────────────────

  Set via environment variables (recommended) or CLI flags:

    export QUALYS_USERNAME="myuser"
    export QUALYS_PASSWORD="mypass"

─── EXAMPLES ───────────────────────────────────────────────────────────

  # Basic — last 1 day, 50 images per page
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com

  # Last 30 days, 250 per page (max throughput)
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com -d 30 -l 250

  # Custom QQL filter — only Ubuntu images with severity 5 vulns
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      -f "imagesInUse:`[now-30d ... now]` and vulnerabilities.severity:5"

  # Custom QQL — specific registry
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      -f "imagesInUse:`[now-7d ... now]` and repo.registry:`docker.io`"

  # Override the entire filter (no default prepended)
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      --raw-filter "imagesInUse:`[now-1d ... now]` and operatingSystem:Alpine"

  # Dry run — preview URLs, no API calls
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com --dry-run

  # Force fresh run (ignore checkpoint)
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com --force

  # Quiet mode for cron / CI
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com -q --force

  # Via corporate proxy
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      -C "--proxy http://proxy.corp.com:8080"

─── SUPPORTED GATEWAYS ─────────────────────────────────────────────────

  US-1: https://gateway.qg1.apps.qualys.com
  US-2: https://gateway.qg2.apps.qualys.com
  US-3: https://gateway.qg3.apps.qualys.com
  US-4: https://gateway.qg4.apps.qualys.com
  EU-1: https://gateway.qg1.apps.qualys.eu
  EU-2: https://gateway.qg2.apps.qualys.eu
  CA:   https://gateway.qg1.apps.qualys.ca
  IN:   https://gateway.qg1.apps.qualys.in
  AU:   https://gateway.qg1.apps.qualys.com.au
  UAE:  https://gateway.qg1.apps.qualys.ae
  UK:   https://gateway.qg1.apps.qualys.co.uk
  KSA:  https://gateway.qg1.apps.qualysksa.com
  GOV:  https://gateway.gov1.qualys.us
""",
    )

    env = os.environ.get

    # ── Authentication ──
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-u", "--username",
        default=env("QUALYS_USERNAME", ""),
        help="Qualys username  (default: $QUALYS_USERNAME)")
    auth_group.add_argument(
        "-p", "--password",
        default=env("QUALYS_PASSWORD", ""),
        help="Qualys password  (default: $QUALYS_PASSWORD)")

    # ── Connection ──
    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument(
        "-g", "--gateway",
        default=env("QUALYS_GATEWAY", DEFAULT_GATEWAY),
        help=f"Qualys gateway URL  (default: {DEFAULT_GATEWAY})")

    # ── Query / Filter ──
    query_group = parser.add_argument_group("query")
    query_group.add_argument(
        "-d", "--days", type=int,
        default=int(env("QUALYS_DAYS", DEFAULT_LOOKBACK_DAYS)),
        help=(f"Image lookback days for default filter "
              f"(default: {DEFAULT_LOOKBACK_DAYS}).  "
              f"Ignored when --raw-filter is used."))
    query_group.add_argument(
        "-f", "--filter",
        default=env("QUALYS_FILTER", ""),
        help=("Extra QQL appended to the default imagesInUse filter "
              "with AND.  Example: -f \"vulnerabilities.severity:5\""))
    query_group.add_argument(
        "--raw-filter",
        default=env("QUALYS_RAW_FILTER", ""),
        help=("Complete raw QQL filter — overrides -d and -f entirely.  "
              "Passed as-is (URL-encoded automatically).  "
              "Example: --raw-filter "
              "\"imagesInUse:`[now-30d ... now]` and "
              "operatingSystem:Ubuntu\""))
    query_group.add_argument(
        "-l", "--limit", type=int,
        default=int(env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)),
        help=f"Results per API page  (default: {DEFAULT_PAGE_LIMIT})")

    # ── Output ──
    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "-o", "--output-dir",
        default=env("QUALYS_OUTPUT_DIR", "./qualys_snow_output"),
        help="Output directory  (default: ./qualys_snow_output)")

    # ── Behavior ──
    beh_group = parser.add_argument_group("behavior")
    beh_group.add_argument(
        "--force", action="store_true",
        help="Ignore checkpoint, start fresh")
    beh_group.add_argument(
        "-r", "--retries", type=int,
        default=int(env("QUALYS_RETRIES", DEFAULT_MAX_RETRIES)),
        help=f"Max retries per API call  (default: {DEFAULT_MAX_RETRIES})")
    beh_group.add_argument(
        "--cps", type=int,
        default=int(env("QUALYS_CPS", DEFAULT_CALLS_PER_SEC)),
        help=f"Max API calls/sec  (default: {DEFAULT_CALLS_PER_SEC})")
    beh_group.add_argument(
        "-C", "--curl-extra",
        default=env("QUALYS_CURL_EXTRA", ""),
        help="Extra curl args  (e.g. \"--proxy http://...\")")
    beh_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Debug-level console output")
    beh_group.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress console output (log file still written)")
    beh_group.add_argument(
        "--dry-run", action="store_true",
        help="Preview config and URLs, no API calls")

    return parser.parse_args()

# =============================================================================
# MAIN
# =============================================================================
def main():
    args = parse_arguments()
    start_time = time.time()

    # ── Validate credentials ──
    if not args.username or not args.password:
        print(
            "ERROR: Qualys credentials required.\n"
            "  Set environment variables:\n"
            "    export QUALYS_USERNAME=\"myuser\"\n"
            "    export QUALYS_PASSWORD=\"mypass\"\n"
            "  Or use CLI flags:  -u myuser -p mypass",
            file=sys.stderr)
        sys.exit(1)

    if not args.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS.", file=sys.stderr)
        sys.exit(1)

    # ── Build QQL filter ──
    if args.raw_filter:
        # User provided the complete QQL — use it as-is
        qql_plain = args.raw_filter
    else:
        # Build default filter from -d (days) and optional -f (extra QQL)
        qql_plain = f"imagesInUse:`[now-{args.days}d ... now]`"
        if args.filter:
            qql_plain += f" and {args.filter}"

    qql_encoded = encode_qql_filter(qql_plain)

    # ── Directory setup ──
    output_dir = args.output_dir
    pages_dir = os.path.join(output_dir, "pages")
    os.makedirs(pages_dir, exist_ok=True)

    logger, log_file = setup_logging(
        output_dir, args.verbose, args.quiet)
    acquire_lock(output_dir, args.force)

    base_api_url = (
        f"{args.gateway.rstrip('/')}/csapi/{DEFAULT_API_VERSION}")
    snow_url = (
        f"{base_api_url}/images/snow"
        f"?filter={qql_encoded}&limit={args.limit}")

    # ── Print config ──
    logger.info(f"Qualys Image SNOW Report v{VERSION}")
    logger.info(f"  Gateway    : {args.gateway}")
    logger.info(f"  Username   : {args.username}")
    logger.info(f"  QQL Filter : {qql_plain}")
    logger.info(f"  Limit/page : {args.limit}")
    logger.info(f"  Rate limit : {args.cps} calls/sec, "
                f"{args.retries} retries")
    logger.info(f"  Output     : {output_dir}")
    logger.info(f"  Log        : {log_file}")

    if args.dry_run:
        logger.info(f"\n  ** DRY RUN — no API calls **")
        logger.info(f"  Auth URL : {args.gateway.rstrip('/')}/auth")
        logger.info(f"  SNOW URL : {snow_url}")
        logger.info(f"  QQL (raw): {qql_plain}")
        logger.info(f"  QQL (enc): {qql_encoded}")
        return

    # ── Checkpoint ──
    checkpoint = CheckpointManager(
        output_dir, generate_config_fingerprint(args))
    if checkpoint.is_done("complete") and not args.force:
        logger.info(
            "\nPrevious run already complete.  "
            "Use --force for a fresh run.")
        return
    if args.force:
        checkpoint.clear()

    # ══════════════════════════════════════════════════════════════════
    # PHASE 0: Authentication
    # ══════════════════════════════════════════════════════════════════
    logger.info(f"\n[Phase 0] Authentication")
    jwt_token = generate_jwt_token(
        args.gateway, args.username, args.password,
        DEFAULT_CONNECT_TIMEOUT, logger)

    rate_limiter = RateLimiter(args.cps, logger)
    api_client = QualysApiClient(
        gateway_url=args.gateway,
        access_token=jwt_token,
        max_retries=args.retries,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        request_timeout=DEFAULT_REQUEST_TIMEOUT,
        extra_curl_args=args.curl_extra,
        rate_limiter=rate_limiter,
        logger=logger,
    )

    # ══════════════════════════════════════════════════════════════════
    # PHASE 1: Fetch all SNOW images
    # ══════════════════════════════════════════════════════════════════
    if checkpoint.is_done("fetch"):
        logger.info(f"\n[Phase 1] Fetch SNOW images — cached")
        image_count = count_images_from_pages(pages_dir, "snow")
        logger.info(f"  {image_count} images from cache")
    else:
        logger.info(f"\n[Phase 1] Fetching SNOW images...")
        records = api_client.fetch_all_snow_pages(
            snow_url, pages_dir, args.limit)
        image_count = len(records)
        checkpoint.mark_done("fetch")

    if image_count == 0:
        logger.warning(
            "  WARNING: 0 images returned.  "
            "Check your QQL filter and gateway URL.")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2: Generate reports (CSV + JSON)
    # ══════════════════════════════════════════════════════════════════
    if checkpoint.is_done("reports"):
        logger.info(f"\n[Phase 2] Reports — cached")
        csv_rows = total_vulns = 0
    else:
        logger.info(f"\n[Phase 2] Generating reports...")
        csv_rows, _, total_vulns = generate_csv_report(
            pages_dir, "snow",
            os.path.join(output_dir, "qualys_image_snow_report.csv"),
            logger)
        generate_json_report(
            pages_dir, "snow",
            os.path.join(output_dir, "qualys_image_snow_report.json"),
            logger)
        checkpoint.mark_done("reports")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 3: Summary
    # ══════════════════════════════════════════════════════════════════
    elapsed = time.time() - start_time
    print_summary(
        pages_dir, "snow", csv_rows, total_vulns,
        elapsed, api_client, rate_limiter, logger)

    # Machine-readable summary
    write_json_atomically(
        os.path.join(output_dir, "run_summary.json"),
        {
            "version": VERSION,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "gateway": args.gateway,
            "qql_filter": qql_plain,
            "lookback_days": args.days,
            "total_images": image_count,
            "total_vulnerabilities": total_vulns,
            "csv_rows": csv_rows,
            "csv_columns": len(CSV_HEADERS),
            "duration": format_duration(elapsed),
            "api_calls": api_client.total_api_calls,
            "retries": api_client.total_retries,
            "errors": api_client.total_errors,
            "throttles": rate_limiter.total_throttle_events,
        })
    checkpoint.mark_done("complete")
    logger.info(f"\n  All reports saved to: {output_dir}/")


if __name__ == "__main__":
    main()
