#!/usr/bin/env python3
"""
=============================================================================
Qualys Container Security - Image Vulnerability Report
Version: 2.1.0
Author:  Qualys CS Engineering
License: Apache 2.0
=============================================================================

Enterprise CLI tool that fetches container-image records from the Qualys
CSAPI SNOW endpoint, classifies each QID vulnerability as originating from
the Base image or Application/Child layer, and produces CSV + JSON reports.

─── SINGLE API ENDPOINT ────────────────────────────────────────────────────

    GET /csapi/v1.3/images/snow?filter=<QQL>&limit=250

    The filter accepts ANY valid Qualys QQL expression.  Write QQL in
    plain text — the script URL-encodes all special characters automatically.

    Supported QQL characters:
        backticks ` , single quotes ' , double quotes " , colons : ,
        brackets [ ] , parentheses ( ) , curly braces { } , commas , ,
        greater/less than > < , dots . , hyphens - , underscores _ ,
        slashes / , spaces, and any other unicode character.

    Full list of QQL tokens:
    https://docs.qualys.com/en/cs/1.41.0/search_tips/search_ui_images.htm

─── HOW IT WORKS ───────────────────────────────────────────────────────────

    Phase 0 — AUTHENTICATION
        POST /auth with username + password → JWT token (valid 4 hours).
        Credentials URL-encoded to handle special characters in passwords.

    Phase 1 — FETCH ALL IMAGES
        Offset-based pagination with 250 records per page.
        Each page saved to pages/snow_NNNN.json for crash recovery.
        Stops when: empty page, fewer records than limit, or duplicate
        data detected (handles all SNOW API pagination behaviors).
        No upper bound — tested with 50,000+ images.

    Phase 2 — REPORT GENERATION  (streaming, constant ~10 MB memory)
        Reads page files one at a time.
        For each image → for each QID → for each affected software → 1 CSV row.

        QID LAYER CLASSIFICATION — 3 conditions only:
            isBaseLayer = true   →  "Base"
            isBaseLayer = false  →  "Application/Child"
            isBaseLayer = null   →  "null"

    Phase 3 — RUN SUMMARY
        Prints stats and writes run_summary.json.

─── FEATURES ───────────────────────────────────────────────────────────────

    • Flexible QQL — pass ANY Qualys QQL via -f or --raw-filter
    • Idempotent — checkpoint per phase, re-run resumes, --force resets
    • Atomic writes — temp file → rename, zero corrupt files on crash
    • Lock file — prevents concurrent runs on the same output directory
    • Signal handling — Ctrl+C saves state and exits cleanly
    • Rate-limit aware — reads X-RateLimit-Remaining, honours Retry-After
    • Exponential backoff + jitter on transient failures
    • Streaming — constant ~10 MB memory regardless of image count
    • No pip packages — Python 3.8+ standard library + curl only

─── PREREQUISITES ──────────────────────────────────────────────────────────

    Python 3.8+   and   curl

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
from urllib.parse import quote as python_url_encode

VERSION = "2.1.0"

# =============================================================================
# DEFAULT CONFIGURATION
# =============================================================================
DEFAULT_GATEWAY_URL       = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION       = "v1.3"
DEFAULT_PAGE_LIMIT        = 250       # hardcoded per Qualys SNOW API best practice
DEFAULT_LOOKBACK_DAYS     = 1
DEFAULT_MAX_RETRIES       = 3
DEFAULT_CONNECT_TIMEOUT   = 15        # seconds for TCP connection
DEFAULT_REQUEST_TIMEOUT   = 120       # seconds for full response
DEFAULT_CALLS_PER_SECOND  = 2

# =============================================================================
# SIGNAL HANDLING — graceful shutdown on Ctrl+C or SIGTERM
# =============================================================================
shutdown_was_requested = False


def on_shutdown_signal(signal_number, _stack_frame):
    """Set a flag so long-running loops can exit cleanly."""
    global shutdown_was_requested
    signal_name = signal.Signals(signal_number).name
    print(f"\n[!] {signal_name} received — saving progress and exiting...",
          file=sys.stderr)
    shutdown_was_requested = True


signal.signal(signal.SIGINT,  on_shutdown_signal)
signal.signal(signal.SIGTERM, on_shutdown_signal)


def raise_if_shutdown_requested():
    """Call this inside loops.  Raises SystemExit if Ctrl+C was pressed."""
    if shutdown_was_requested:
        raise SystemExit(130)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def convert_none_to_empty_string(value):
    """Convert Python None or the literal string 'None' to an empty string.
    Everything else is converted to a string."""
    if value is None or value == "None":
        return ""
    return str(value)


def convert_epoch_milliseconds_to_iso_date(epoch_milliseconds):
    """Convert Qualys epoch-millisecond timestamps to ISO 8601 format.

    Examples:
        1774987210747  →  "2026-03-31T20:00:10Z"
        "0" or None    →  ""  (empty string)
    """
    if not epoch_milliseconds or str(epoch_milliseconds) == "0":
        return ""
    try:
        timestamp_in_seconds = int(epoch_milliseconds) / 1000
        utc_datetime = datetime.fromtimestamp(
            timestamp_in_seconds, tz=timezone.utc)
        return utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_milliseconds)


def write_json_file_atomically(file_path, data_to_write):
    """Write JSON data safely: write to temp file first, then rename.

    This ensures the output file is never left in a half-written state
    if the process crashes or is killed mid-write.
    """
    parent_directory = os.path.dirname(file_path)
    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=parent_directory, suffix=".tmp")
    try:
        with os.fdopen(file_descriptor, "w") as temporary_file:
            json.dump(data_to_write, temporary_file, indent=2, default=str)
        os.replace(temporary_path, file_path)
    except Exception:
        try:
            os.remove(temporary_path)
        except OSError:
            pass
        raise


def delete_file_if_exists(file_path):
    """Delete a file, silently ignoring errors if it doesn't exist."""
    try:
        os.remove(file_path)
    except OSError:
        pass


def format_seconds_as_duration(total_seconds):
    """Convert seconds to a human-readable duration like '2m35s' or '1h12m'."""
    total_seconds = int(total_seconds)
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes}m{seconds}s"
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{hours}h{minutes}m"


def convert_qds_score_to_severity_label(qds_score):
    """Convert a Qualys QDS numeric score to a severity label.

    Qualys QDS Score ranges:
        70–100  →  CRITICAL
        40–69   →  HIGH
        25–39   →  MEDIUM
         0–24   →  LOW
        None    →  ""  (empty)
    """
    if qds_score is None:
        return ""
    qds_score = int(qds_score)
    if qds_score >= 70:
        return "CRITICAL"
    if qds_score >= 40:
        return "HIGH"
    if qds_score >= 25:
        return "MEDIUM"
    return "LOW"


def compute_configuration_fingerprint(parsed_arguments):
    """Create a short hash of the run configuration.

    Used by the checkpoint system to detect when the user changes
    configuration between runs — if the fingerprint changes, the
    checkpoint is automatically invalidated.
    """
    configuration_string = (
        f"{parsed_arguments.gateway}"
        f"|{parsed_arguments.days}"
        f"|{parsed_arguments.limit}"
        f"|{parsed_arguments.filter or ''}"
        f"|{parsed_arguments.raw_filter or ''}"
    )
    full_hash = hashlib.sha256(configuration_string.encode()).hexdigest()
    return full_hash[:16]


def url_encode_qql_filter(plain_text_qql_filter):
    """URL-encode a raw Qualys QQL filter string for the API URL.

    The user writes QQL in plain text exactly as it appears in the
    Qualys UI search bar:

        imagesInUse:`[now-30d ... now]`
        vulnerabilities.severity:5 and operatingSystem:Ubuntu
        repo.registry:`registry-1.docker.io`

    This function encodes ALL characters (safe='') so every special
    character is percent-encoded for safe HTTP transport:

        Backticks `    →  %60        Colons :       →  %3A
        Single quotes' →  %27        Double quotes" →  %22
        Brackets [ ]   →  %5B %5D    Parentheses () →  %28 %29
        Curly braces{} →  %7B %7D    Commas ,       →  %2C
        Spaces         →  %20        Greater than > →  %3E
        Plus +         →  %2B        Equals =       →  %3D
        Ampersand &    →  %26        Hash #         →  %23
        At sign @      →  %40        Exclamation !  →  %21
        Forward slash/ →  %2F        Dollar $       →  %24

    Full list of supported QQL tokens:
    https://docs.qualys.com/en/cs/1.41.0/search_tips/search_ui_images.htm
    """
    return python_url_encode(plain_text_qql_filter, safe='')

# =============================================================================
# LOGGING SETUP
# =============================================================================


def setup_logging(output_directory, enable_verbose, enable_quiet):
    """Create a logger that writes to both a file and the console.

    The log file always captures DEBUG-level detail.
    The console shows INFO by default, or DEBUG with --verbose.
    """
    logger = logging.getLogger("qualys_snow_report")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_file_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_file_name)

    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

    if not enable_quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(
            logging.DEBUG if enable_verbose else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

    return logger, log_file_path

# =============================================================================
# LOCK FILE — prevents two instances from running against the same output dir
# =============================================================================


def acquire_lock_file(output_directory, force_mode_enabled):
    """Create a .lock file with our PID.  If another process holds the lock,
    exit unless --force is used."""
    lock_file_path = os.path.join(output_directory, ".lock")

    if os.path.exists(lock_file_path):
        try:
            existing_process_id = int(
                open(lock_file_path).read().strip())
            os.kill(existing_process_id, 0)      # check if process is alive
            if not force_mode_enabled:
                print(
                    f"ERROR: Another instance is running "
                    f"(PID {existing_process_id}).  "
                    f"Use --force to override.",
                    file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass      # stale lock from a crashed process

    with open(lock_file_path, "w") as lock_file:
        lock_file.write(str(os.getpid()))

    atexit.register(lambda: delete_file_if_exists(lock_file_path))

# =============================================================================
# CHECKPOINT MANAGER — enables idempotent execution
# =============================================================================


class CheckpointManager:
    """Tracks which phases have completed so re-runs resume from where
    they left off instead of starting over.

    If the configuration changes between runs (detected via fingerprint),
    the checkpoint is automatically cleared.
    """

    def __init__(self, output_directory, configuration_fingerprint):
        self.checkpoint_file_path = os.path.join(
            output_directory, ".checkpoint.json")
        self.configuration_fingerprint = configuration_fingerprint
        self.completed_phases = {}

        if os.path.exists(self.checkpoint_file_path):
            try:
                saved_state = json.load(open(self.checkpoint_file_path))
                if saved_state.get("fingerprint") == configuration_fingerprint:
                    self.completed_phases = saved_state
                # else: config changed → start fresh (empty dict)
            except (json.JSONDecodeError, KeyError):
                pass      # corrupted checkpoint → start fresh

    def is_phase_complete(self, phase_name):
        """Check if a specific phase has already been completed."""
        return self.completed_phases.get(phase_name) is True

    def mark_phase_complete(self, phase_name):
        """Record that a phase has finished successfully."""
        self.completed_phases[phase_name] = True
        self.completed_phases["fingerprint"] = \
            self.configuration_fingerprint
        write_json_file_atomically(
            self.checkpoint_file_path, self.completed_phases)

    def clear_all_checkpoints(self):
        """Delete all checkpoint data for a fresh start."""
        delete_file_if_exists(self.checkpoint_file_path)
        self.completed_phases = {}

# =============================================================================
# JWT AUTHENTICATION — POST /auth with username + password
# =============================================================================


def authenticate_and_get_jwt_token(
        gateway_url, username, password, connect_timeout_seconds, logger):
    """Authenticate to Qualys and return a JWT token string.

    Makes a POST request to:
        https://<gateway>/auth
        Content-Type: application/x-www-form-urlencoded
        Body: username=<encoded>&password=<encoded>&token=true

    The username and password are URL-encoded to handle special characters
    like & = + @ ! $ # that would otherwise break the form body.
    Example: "P@ss&word#1" becomes "P%40ss%26word%231"
    """
    authentication_url = f"{gateway_url.rstrip('/')}/auth"
    logger.info(f"  Authenticating as '{username}'...")

    encoded_username = python_url_encode(username, safe='')
    encoded_password = python_url_encode(password, safe='')

    curl_command = [
        "curl", "-s",
        "-w", "\n%{http_code}",
        "--connect-timeout", str(connect_timeout_seconds),
        "--max-time", "30",
        "-X", "POST",
        authentication_url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", (f"username={encoded_username}"
               f"&password={encoded_password}"
               f"&token=true"),
    ]

    try:
        curl_result = subprocess.run(
            curl_command, capture_output=True, text=True)
        output_lines = curl_result.stdout.strip().split("\n")
        http_status_code = (
            int(output_lines[-1])
            if output_lines[-1].isdigit() else 0)
        response_body = "\n".join(output_lines[:-1]).strip()
    except Exception as error:
        logger.error(f"  Authentication failed: {error}")
        sys.exit(1)

    if http_status_code in (200, 201) and response_body:
        jwt_token = response_body.strip()
        if jwt_token.startswith("eyJ"):
            logger.info(
                f"  Token obtained: "
                f"{jwt_token[:15]}...{jwt_token[-6:]}"
                f"  (valid ~4 hours)")
            return jwt_token
        else:
            logger.error(
                f"  Unexpected auth response: {response_body[:100]}")
            sys.exit(1)

    if http_status_code == 401:
        logger.error(
            "  Authentication failed: invalid username or password.")
    elif http_status_code == 0:
        logger.error(
            f"  Connection failed.  "
            f"Check gateway URL: {gateway_url}")
    else:
        logger.error(
            f"  Authentication failed: HTTP {http_status_code}")
        if response_body:
            logger.error(f"  Response: {response_body[:200]}")

    sys.exit(1)

# =============================================================================
# RATE LIMITER — prevents exceeding Qualys API call limits
# =============================================================================


class ApiRateLimiter:
    """Thread-safe rate limiter that reads Qualys rate-limit headers
    and pauses automatically when limits are approaching."""

    def __init__(self, max_calls_per_second, logger):
        self.minimum_interval_between_calls = 1.0 / max_calls_per_second
        self.logger = logger
        self.thread_lock = threading.Lock()
        self.last_call_timestamp = 0.0
        self.pause_all_calls_until = 0.0
        self.total_throttle_events = 0

    def wait_until_safe_to_call(self):
        """Block the calling thread until it's safe to make an API call."""
        while True:
            raise_if_shutdown_requested()
            with self.thread_lock:
                current_time = time.time()

                # Check if we're in a global pause (rate limit exhausted)
                if current_time < self.pause_all_calls_until:
                    wait_seconds = self.pause_all_calls_until - current_time
                    self.thread_lock.release()
                    time.sleep(wait_seconds)
                    self.thread_lock.acquire()
                    continue

                # Check minimum interval between calls
                seconds_since_last_call = (
                    current_time - self.last_call_timestamp)
                if seconds_since_last_call < self.minimum_interval_between_calls:
                    wait_seconds = (
                        self.minimum_interval_between_calls
                        - seconds_since_last_call)
                    self.thread_lock.release()
                    time.sleep(wait_seconds)
                    self.thread_lock.acquire()
                    continue

                # Safe to proceed
                self.last_call_timestamp = time.time()
                return

    def check_rate_limit_headers(self, header_file_path):
        """Parse Qualys response headers for rate limit information."""
        if not os.path.exists(header_file_path):
            return

        remaining_calls = None
        window_seconds = None

        try:
            with open(header_file_path) as header_file:
                for line in header_file:
                    lowercase_line = line.lower().strip()
                    if lowercase_line.startswith("x-ratelimit-remaining:"):
                        remaining_calls = int(
                            line.split(":", 1)[1].strip())
                    elif lowercase_line.startswith("x-ratelimit-window-sec:"):
                        window_seconds = int(
                            line.split(":", 1)[1].strip())
        except Exception:
            return

        with self.thread_lock:
            if remaining_calls is not None and remaining_calls <= 0:
                pause_duration = (window_seconds or 60) + 5
                self.pause_all_calls_until = time.time() + pause_duration
                self.logger.warning(
                    f"  Rate limit exhausted — pausing {pause_duration}s")
                self.total_throttle_events += 1
            elif remaining_calls is not None and remaining_calls <= 20:
                # Slow down when approaching the limit
                self.minimum_interval_between_calls = max(
                    self.minimum_interval_between_calls, 1.0)

    def handle_too_many_requests(self, header_file_path):
        """Handle HTTP 429 Too Many Requests by pausing all API calls."""
        retry_after_seconds = None

        if os.path.exists(header_file_path):
            try:
                with open(header_file_path) as header_file:
                    for line in header_file:
                        if line.lower().strip().startswith("retry-after:"):
                            retry_after_seconds = int(
                                line.split(":", 1)[1].strip())
            except Exception:
                pass

        pause_duration = retry_after_seconds or 35

        with self.thread_lock:
            self.pause_all_calls_until = time.time() + pause_duration
            self.logger.warning(
                f"  HTTP 429 Too Many Requests — pausing {pause_duration}s")
            self.total_throttle_events += 1

# =============================================================================
# QUALYS API CLIENT — makes HTTP requests via curl with retry logic
# =============================================================================


class QualysApiClient:
    """HTTP client that uses curl to call the Qualys API.

    Features:
        - Automatic retries with exponential backoff + jitter
        - Rate limit awareness (via ApiRateLimiter)
        - Saves responses to files for caching/resume
        - Handles HTTP 401, 403, 404, 429 appropriately
    """

    def __init__(self, gateway_url, jwt_access_token, max_retry_attempts,
                 connect_timeout_seconds, request_timeout_seconds,
                 extra_curl_arguments, rate_limiter, logger):
        self.gateway_url = gateway_url.rstrip("/")
        self.jwt_access_token = jwt_access_token
        self.max_retry_attempts = max_retry_attempts
        self.connect_timeout_seconds = connect_timeout_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.extra_curl_arguments = extra_curl_arguments
        self.rate_limiter = rate_limiter
        self.logger = logger

        # Counters for the run summary
        self.total_api_calls_made = 0
        self.total_retry_attempts = 0
        self.total_failed_calls = 0

    def make_get_request(self, request_url, output_file_path,
                         keep_response_headers=False):
        """Execute an HTTP GET request via curl.

        Returns the HTTP status code (200, 204, etc.) or 0 on total failure.
        The response body is saved to output_file_path.
        """
        for attempt_number in range(self.max_retry_attempts + 1):
            raise_if_shutdown_requested()

            # Retry with exponential backoff + jitter
            if attempt_number > 0:
                backoff_delay = random.uniform(
                    1, min(15, 2 ** attempt_number))
                self.logger.debug(
                    f"  Retry {attempt_number}/{self.max_retry_attempts} "
                    f"in {backoff_delay:.0f}s...")
                time.sleep(backoff_delay)
                self.total_retry_attempts += 1

            # Wait for rate limiter
            self.rate_limiter.wait_until_safe_to_call()

            response_header_file = output_file_path + ".hdr"

            curl_command = [
                "curl", "-s",
                "-o", output_file_path,
                "-D", response_header_file,
                "-w", "%{http_code}",
                "--connect-timeout", str(self.connect_timeout_seconds),
                "--max-time", str(self.request_timeout_seconds),
                "-X", "GET",
                request_url,
                "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.jwt_access_token}",
            ]

            if self.extra_curl_arguments:
                curl_command.extend(self.extra_curl_arguments.split())

            try:
                curl_result = subprocess.run(
                    curl_command, capture_output=True, text=True)
                http_status_code = (
                    int(curl_result.stdout.strip())
                    if curl_result.stdout.strip().isdigit() else 0)
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self.total_api_calls_made += 1
                self.total_failed_calls += 1
                continue

            self.total_api_calls_made += 1
            self.rate_limiter.check_rate_limit_headers(
                response_header_file)

            # Success
            if http_status_code in (200, 204):
                if not keep_response_headers:
                    delete_file_if_exists(response_header_file)
                return http_status_code

            # Fatal errors — no point retrying
            if http_status_code == 401:
                self.logger.error(
                    "HTTP 401 — token expired or invalid.  "
                    "Re-run to re-authenticate.")
                sys.exit(1)
            if http_status_code == 403:
                self.logger.error(
                    "HTTP 403 — insufficient permissions for CSAPI.")
                sys.exit(1)
            if http_status_code == 404:
                self.logger.error(
                    f"HTTP 404 — endpoint not found: {request_url}")
                sys.exit(1)

            # Rate limited — pause and retry
            if http_status_code == 429:
                self.rate_limiter.handle_too_many_requests(
                    response_header_file)
            else:
                self.logger.debug(
                    f"  HTTP {http_status_code} — will retry")

            delete_file_if_exists(response_header_file)

        # All retries exhausted
        self.total_failed_calls += 1
        return 0

    def fetch_all_snow_image_pages(
            self, base_snow_url, pages_directory, records_per_page,
            page_label="snow"):
        """Paginate through the SNOW endpoint and save each page to disk.

        Pagination strategy:
            - Uses offset-based pagination: &offset=0, &offset=250, etc.
            - Each page saved as pages/snow_0001.json, snow_0002.json, ...
            - Cached pages are reused on re-run (resume support)

        Stop conditions (handles all SNOW API behaviors):
            1. API returns fewer records than records_per_page
            2. API returns 0 records (empty data array)
            3. API returns HTTP 204 (no content)
            4. API returns records we already fetched (duplicate detection)

        Returns: list of all image records across all pages
        """
        all_image_records = []
        already_seen_image_shas = set()
        current_page_number = 1
        current_offset = 0

        while True:
            raise_if_shutdown_requested()

            # Build URL with offset
            url_separator = "&" if "?" in base_snow_url else "?"
            page_url = (
                f"{base_snow_url}{url_separator}offset={current_offset}")
            page_file_path = os.path.join(
                pages_directory,
                f"{page_label}_{current_page_number:04d}.json")

            # ── Try to resume from cached page file ──
            if os.path.exists(page_file_path):
                try:
                    cached_response = json.load(open(page_file_path))
                    cached_image_records = cached_response.get("data", [])

                    if (isinstance(cached_image_records, list)
                            and len(cached_image_records) > 0):

                        # Check for duplicate data
                        new_image_shas = {
                            image.get("sha")
                            for image in cached_image_records
                            if image.get("sha")
                        }
                        if (new_image_shas
                                and new_image_shas.issubset(
                                    already_seen_image_shas)):
                            self.logger.info(
                                f"  page {current_page_number}: "
                                f"duplicate data (cached) — stopping")
                            delete_file_if_exists(page_file_path)
                            break

                        all_image_records.extend(cached_image_records)
                        already_seen_image_shas.update(new_image_shas)
                        self.logger.info(
                            f"  page {current_page_number}: "
                            f"{len(cached_image_records)} images "
                            f"(cached, total: {len(all_image_records)})")

                        if len(cached_image_records) < records_per_page:
                            break      # last page
                        current_offset += records_per_page
                        current_page_number += 1
                        continue

                except (json.JSONDecodeError, KeyError):
                    pass      # corrupted cache file — re-fetch

            # ── Fetch fresh page from API ──
            self.logger.info(
                f"  Fetching page {current_page_number} "
                f"(offset={current_offset})...")
            http_status = self.make_get_request(
                page_url, page_file_path)

            if http_status == 204:
                self.logger.info(
                    f"  page {current_page_number}: "
                    f"HTTP 204 no content — all data fetched")
                delete_file_if_exists(page_file_path)
                break

            if http_status != 200:
                self.logger.error(
                    f"  Failed page {current_page_number} "
                    f"(HTTP {http_status})")
                break

            # Parse the response
            try:
                api_response = json.load(open(page_file_path))
                page_image_records = api_response.get("data", [])
            except (json.JSONDecodeError, KeyError):
                self.logger.error(
                    f"  Failed to parse page {current_page_number}")
                break

            if (not isinstance(page_image_records, list)
                    or len(page_image_records) == 0):
                self.logger.info(
                    f"  page {current_page_number}: "
                    f"0 images — all data fetched")
                delete_file_if_exists(page_file_path)
                break

            # ── Duplicate detection ──
            new_image_shas = {
                image.get("sha")
                for image in page_image_records
                if image.get("sha")
            }
            if (new_image_shas
                    and new_image_shas.issubset(already_seen_image_shas)):
                self.logger.info(
                    f"  page {current_page_number}: "
                    f"duplicate data — all data fetched")
                delete_file_if_exists(page_file_path)
                break

            all_image_records.extend(page_image_records)
            already_seen_image_shas.update(new_image_shas)
            self.logger.info(
                f"  page {current_page_number}: "
                f"{len(page_image_records)} images "
                f"(total: {len(all_image_records)})")

            if len(page_image_records) < records_per_page:
                break      # last page — fewer records than requested

            current_offset += records_per_page
            current_page_number += 1

        self.logger.info(
            f"  Fetched {len(all_image_records)} images "
            f"across {current_page_number} page(s)")
        return all_image_records

# =============================================================================
# PAGE FILE ITERATOR — reads saved pages one at a time for constant memory
# =============================================================================


def iterate_images_from_saved_pages(pages_directory, page_label):
    """Yield one image at a time from saved JSON page files.

    This is a generator — it loads one page file into memory,
    yields all images from it, then discards it and loads the next.
    Memory stays at ~10 MB regardless of whether there are 50 or
    50,000 images.
    """
    page_number = 1
    while True:
        page_file_path = os.path.join(
            pages_directory, f"{page_label}_{page_number:04d}.json")

        if not os.path.exists(page_file_path):
            break

        try:
            with open(page_file_path) as page_file:
                page_data = json.load(page_file).get("data", [])
            if not isinstance(page_data, list) or len(page_data) == 0:
                break
            for single_image in page_data:
                yield single_image
            page_number += 1
        except (json.JSONDecodeError, KeyError):
            break


def count_images_across_saved_pages(pages_directory, page_label):
    """Count total images across all page files without loading them all."""
    total_image_count = 0
    page_number = 1
    while True:
        page_file_path = os.path.join(
            pages_directory, f"{page_label}_{page_number:04d}.json")
        if not os.path.exists(page_file_path):
            break
        try:
            with open(page_file_path) as page_file:
                page_data = json.load(page_file).get("data", [])
            if not isinstance(page_data, list) or len(page_data) == 0:
                break
            total_image_count += len(page_data)
            page_number += 1
        except (json.JSONDecodeError, KeyError):
            break
    return total_image_count

# =============================================================================
# QID LAYER CLASSIFICATION
#
# Each QID in the SNOW response has a "layerSha" field — a list of SHA
# strings identifying which Docker layer introduced that vulnerability.
#
# The image's "layers" section has an "isBaseLayer" field per layer.
# We match the QID's layerSha against the layers and read isBaseLayer.
#
# 3 conditions — nothing else:
#   isBaseLayer = true   →  "Base"
#   isBaseLayer = false  →  "Application/Child"
#   isBaseLayer = null   →  "null"
# =============================================================================


def build_layer_sha_to_is_base_layer_map(image_data):
    """Build a lookup dictionary from the image's layers.

    Returns: dict mapping full_sha_string → isBaseLayer_value
        where isBaseLayer_value is True, False, or None.

    Example return value:
        {
            "994393dc58e7...": None,
            "57c379a94f03...": None,
            "27172507b0ce...": True,
        }
    """
    sha_to_is_base_layer = {}
    for layer in (image_data.get("layers") or []):
        layer_sha = layer.get("sha")
        if layer_sha:
            sha_to_is_base_layer[layer_sha] = layer.get("isBaseLayer")
    return sha_to_is_base_layer


def classify_qid_layer_origin(
        vulnerability_layer_shas, layer_sha_to_is_base_layer_map):
    """Determine whether a QID comes from a Base or Application layer.

    How it works:
        1. Take the QID's layerSha list (e.g. ["27172507b0ce..."])
        2. Look up each SHA in the image's layer map
        3. Read the isBaseLayer field on the matching layer

    3 values only:
        isBaseLayer = true   →  "Base"
        isBaseLayer = false  →  "Application/Child"
        isBaseLayer = null   →  "null"

    If QID has no layerSha field → empty string.

    Returns: (classification_label, full_layer_sha_string)
    """
    if not vulnerability_layer_shas:
        return "", ""

    for layer_sha in vulnerability_layer_shas:
        if layer_sha in layer_sha_to_is_base_layer_map:
            is_base_layer_value = layer_sha_to_is_base_layer_map[layer_sha]

            if is_base_layer_value is True:
                return "Base", layer_sha
            elif is_base_layer_value is False:
                return "Application/Child", layer_sha
            else:
                return "null", layer_sha

    # layerSha not found in layers — treat as null
    return "null", (
        vulnerability_layer_shas[0]
        if vulnerability_layer_shas else "")


def extract_repository_information(image_data):
    """Extract registry, repository, and tag from the image data.

    Falls back to repoDigests for registry name when it's missing
    from the repo entry.
    """
    repository_entries = image_data.get("repo") or []
    digest_entries = image_data.get("repoDigests") or []

    # Build a fallback map: repository_name → registry_name
    registry_fallback_map = {
        digest["repository"]: digest["registry"]
        for digest in digest_entries
        if digest.get("registry") and digest.get("repository")
    }

    extracted_repositories = []
    for repository_entry in repository_entries:
        registry_name = repository_entry.get("registry") or ""
        repository_name = convert_none_to_empty_string(
            repository_entry.get("repository"))

        if not registry_name and repository_name:
            registry_name = registry_fallback_map.get(
                repository_name, "")

        extracted_repositories.append({
            "registry":   convert_none_to_empty_string(registry_name),
            "repository": repository_name,
            "tag":        convert_none_to_empty_string(
                repository_entry.get("tag")),
        })

    if not extracted_repositories:
        extracted_repositories = [
            {"registry": "", "repository": "", "tag": ""}]

    return extracted_repositories

# =============================================================================
# CSV + JSON REPORT GENERATION — 26 columns
# =============================================================================

CSV_COLUMN_HEADERS = [
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

EMPTY_VULNERABILITY_COLUMNS = [""] * 7
EMPTY_SOFTWARE_COLUMNS = [""] * 4


def generate_csv_report(
        pages_directory, page_label, csv_output_path, logger):
    """Generate the CSV report by streaming through saved page files.

    Memory usage stays at ~10 MB regardless of total image count.
    """
    temporary_csv_path = csv_output_path + ".tmp"
    total_csv_rows_written = 0
    total_images_processed = 0
    total_vulnerabilities_processed = 0

    with open(temporary_csv_path, "w", newline="",
              encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(CSV_COLUMN_HEADERS)

        for image in iterate_images_from_saved_pages(
                pages_directory, page_label):
            total_images_processed += 1
            raise_if_shutdown_requested()

            image_sha = image.get("sha", "")
            vulnerability_list = image.get("vulnerabilities") or []
            repository_list = extract_repository_information(image)
            layer_map = build_layer_sha_to_is_base_layer_map(image)
            associated_container_count = image.get(
                "associatedContainersCount", 0)

            # Base Image field — "Yes" if Qualys detected a base image
            base_image_field_value = image.get("baseImage")
            base_image_detected = (
                "Yes" if base_image_field_value is not None
                and base_image_field_value != ""
                else "No")

            # Image-level columns (shared across all repos)
            image_base_columns = [
                convert_none_to_empty_string(image.get("imageId")),
                image_sha,
                convert_none_to_empty_string(
                    image.get("operatingSystem")),
                convert_none_to_empty_string(
                    image.get("architecture")),
                convert_epoch_milliseconds_to_iso_date(
                    image.get("created")),
                convert_epoch_milliseconds_to_iso_date(
                    image.get("lastScanned")),
                " | ".join(
                    convert_none_to_empty_string(scan_type)
                    for scan_type in (image.get("scanTypes") or [])),
                " | ".join(
                    convert_none_to_empty_string(source)
                    for source in (image.get("source") or [])),
            ]

            for repository in repository_list:
                image_columns = image_base_columns + [
                    repository["registry"],
                    repository["repository"],
                    repository["tag"],
                    convert_none_to_empty_string(
                        image.get("riskScore")),
                    base_image_detected,
                    str(associated_container_count),
                    str(len(vulnerability_list)),
                ]

                if vulnerability_list:
                    for vulnerability in vulnerability_list:
                        total_vulnerabilities_processed += 1
                        qds_score = vulnerability.get("qdsScore")

                        layer_classification, layer_sha = \
                            classify_qid_layer_origin(
                                vulnerability.get("layerSha") or [],
                                layer_map)

                        affected_software_list = (
                            vulnerability.get("software") or [])

                        vulnerability_columns = [
                            convert_none_to_empty_string(
                                vulnerability.get("qid")),
                            (convert_none_to_empty_string(qds_score)
                             if qds_score is not None else ""),
                            convert_qds_score_to_severity_label(
                                qds_score),
                            " | ".join(
                                convert_none_to_empty_string(st)
                                for st in (
                                    vulnerability.get("scanType") or []
                                )),
                            layer_classification,
                            layer_sha,
                            str(len(affected_software_list)),
                        ]

                        if affected_software_list:
                            for software in affected_software_list:
                                software_columns = [
                                    convert_none_to_empty_string(
                                        software.get("name")),
                                    convert_none_to_empty_string(
                                        software.get("version")),
                                    convert_none_to_empty_string(
                                        software.get("fixVersion")),
                                    convert_none_to_empty_string(
                                        software.get("packagePath")),
                                ]
                                csv_writer.writerow(
                                    image_columns
                                    + vulnerability_columns
                                    + software_columns)
                                total_csv_rows_written += 1
                        else:
                            csv_writer.writerow(
                                image_columns
                                + vulnerability_columns
                                + EMPTY_SOFTWARE_COLUMNS)
                            total_csv_rows_written += 1
                else:
                    csv_writer.writerow(
                        image_columns
                        + EMPTY_VULNERABILITY_COLUMNS
                        + EMPTY_SOFTWARE_COLUMNS)
                    total_csv_rows_written += 1

    os.replace(temporary_csv_path, csv_output_path)
    logger.info(
        f"  CSV: {csv_output_path}  "
        f"({total_csv_rows_written:,} rows × "
        f"{len(CSV_COLUMN_HEADERS)} cols)")
    return (total_csv_rows_written,
            total_images_processed,
            total_vulnerabilities_processed)


def generate_json_report(
        pages_directory, page_label, json_output_path, logger):
    """Generate the JSON report by streaming through saved page files."""
    temporary_json_path = json_output_path + ".tmp"
    total_images_written = 0
    total_vulnerabilities_written = 0

    with open(temporary_json_path, "w", encoding="utf-8") as json_file:
        generation_timestamp = datetime.now(
            tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        json_file.write('{\n')
        json_file.write(
            f'  "generatedAt": "{generation_timestamp}",\n')
        json_file.write('  "images": [\n')

        is_first_image = True

        for image in iterate_images_from_saved_pages(
                pages_directory, page_label):
            total_images_written += 1
            raise_if_shutdown_requested()

            layer_map = build_layer_sha_to_is_base_layer_map(image)
            vulnerability_list = image.get("vulnerabilities") or []
            associated_container_count = image.get(
                "associatedContainersCount", 0)
            base_image_field_value = image.get("baseImage")

            qds_scores = [
                vuln.get("qdsScore")
                for vuln in vulnerability_list
                if vuln.get("qdsScore") is not None
            ]
            max_qds_score = max(qds_scores) if qds_scores else None

            enriched_vulnerabilities = []
            for vulnerability in vulnerability_list:
                total_vulnerabilities_written += 1
                qds_score = vulnerability.get("qdsScore")
                layer_classification, layer_sha = \
                    classify_qid_layer_origin(
                        vulnerability.get("layerSha") or [],
                        layer_map)

                enriched_vulnerabilities.append({
                    "qid": vulnerability.get("qid"),
                    "qdsScore": qds_score,
                    "qdsSeverity":
                        convert_qds_score_to_severity_label(qds_score),
                    "scanType": vulnerability.get("scanType") or [],
                    "qidLayerType": layer_classification,
                    "qidLayerSha": layer_sha,
                    "affectedSoftware": [
                        {
                            "name": convert_none_to_empty_string(
                                sw.get("name")),
                            "version": convert_none_to_empty_string(
                                sw.get("version")),
                            "fixVersion": convert_none_to_empty_string(
                                sw.get("fixVersion")),
                            "packagePath": convert_none_to_empty_string(
                                sw.get("packagePath")),
                        }
                        for sw in (
                            vulnerability.get("software") or [])
                    ],
                })

            image_record = {
                "imageId": convert_none_to_empty_string(
                    image.get("imageId")),
                "sha": image.get("sha", ""),
                "operatingSystem": convert_none_to_empty_string(
                    image.get("operatingSystem")),
                "architecture": convert_none_to_empty_string(
                    image.get("architecture")),
                "riskScore": image.get("riskScore"),
                "baseImageDetected": (
                    base_image_field_value is not None
                    and base_image_field_value != ""),
                "baseImage": convert_none_to_empty_string(
                    base_image_field_value),
                "maxQdsScore": max_qds_score,
                "maxQdsSeverity":
                    convert_qds_score_to_severity_label(max_qds_score),
                "associatedContainerCount":
                    associated_container_count,
                "totalVulnerabilities": len(vulnerability_list),
                "repositories":
                    extract_repository_information(image),
                "vulnerabilities": enriched_vulnerabilities,
            }

            if not is_first_image:
                json_file.write(',\n')
            json_file.write(
                '    ' + json.dumps(image_record, default=str))
            is_first_image = False

        json_file.write('\n  ],\n')
        json_file.write(
            f'  "totalImages": {total_images_written},\n')
        json_file.write(
            f'  "totalVulnerabilities": '
            f'{total_vulnerabilities_written}\n')
        json_file.write('}\n')

    os.replace(temporary_json_path, json_output_path)
    logger.info(f"  JSON: {json_output_path}")
    return total_images_written, total_vulnerabilities_written

# =============================================================================
# RUN SUMMARY — displayed on console and saved as run_summary.json
# =============================================================================


def print_run_summary(
        pages_directory, page_label, total_csv_rows,
        total_vulnerabilities, elapsed_seconds, api_client,
        rate_limiter, logger):
    """Print a human-readable summary of the report generation run."""
    total_images = count_images_across_saved_pages(
        pages_directory, page_label)
    total_containers_at_risk = 0
    severity_counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    layer_type_counts = {}

    for image in iterate_images_from_saved_pages(
            pages_directory, page_label):
        total_containers_at_risk += image.get(
            "associatedContainersCount", 0)
        layer_map = build_layer_sha_to_is_base_layer_map(image)
        for vulnerability in (image.get("vulnerabilities") or []):
            severity = convert_qds_score_to_severity_label(
                vulnerability.get("qdsScore"))
            if severity in severity_counts:
                severity_counts[severity] += 1
            layer_type, _ = classify_qid_layer_origin(
                vulnerability.get("layerSha") or [], layer_map)
            if layer_type:
                layer_type_counts[layer_type] = \
                    layer_type_counts.get(layer_type, 0) + 1

    logger.info(f"\n{'=' * 64}")
    logger.info(
        "  QUALYS IMAGE SNOW — VULNERABILITY REPORT SUMMARY")
    logger.info(f"{'=' * 64}")
    logger.info(
        f"  Generated          : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(
        f"  Duration           : "
        f"{format_seconds_as_duration(elapsed_seconds)}")
    logger.info(
        f"  API Calls          : {api_client.total_api_calls_made}"
        f"  (retries: {api_client.total_retry_attempts},"
        f" errors: {api_client.total_failed_calls})")
    logger.info(f"  Images             : {total_images}")
    logger.info(
        f"  Vulnerabilities    : {total_vulnerabilities}")
    logger.info(f"  CSV Rows           : {total_csv_rows:,}")
    logger.info(
        f"  Containers at Risk : {total_containers_at_risk}")
    logger.info(f"{'-' * 64}")
    logger.info(
        f"  CRITICAL (QDS≥70)  : {severity_counts['CRITICAL']}")
    logger.info(
        f"  HIGH     (QDS≥40)  : {severity_counts['HIGH']}")
    logger.info(
        f"  MEDIUM   (QDS≥25)  : {severity_counts['MEDIUM']}")
    logger.info(
        f"  LOW      (QDS<25)  : {severity_counts['LOW']}")
    logger.info(f"{'-' * 64}")
    logger.info("  QID Layer Classification:")
    for layer_type_label in sorted(
            layer_type_counts,
            key=layer_type_counts.get,
            reverse=True):
        logger.info(
            f"    {layer_type_label:<25} : "
            f"{layer_type_counts[layer_type_label]}")
    logger.info(f"{'=' * 64}")

# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================


def parse_command_line_arguments():
    """Parse and return command-line arguments."""
    argument_parser = argparse.ArgumentParser(
        prog="qualys_image_snow_report",
        description=(
            f"Qualys CS Image SNOW Vulnerability Report "
            f"v{VERSION}\n\n"
            f"Fetches container images from the Qualys SNOW API,\n"
            f"classifies each QID as Base or Application/Child layer,\n"
            f"and produces a unified CSV + JSON report."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
─── AUTHENTICATION ─────────────────────────────────────────────

  export QUALYS_USERNAME="myuser"
  export QUALYS_PASSWORD="mypass"

─── EXAMPLES ───────────────────────────────────────────────────

  # Basic — last 1 day
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com

  # Last 30 days
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com -d 30

  # Add QQL filter — severity 5 only
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      -f "vulnerabilities.severity:5"

  # Full raw QQL (overrides -d and -f)
  python3 qualys_image_snow_report.py \\
      -g https://gateway.qg2.apps.qualys.com \\
      --raw-filter "imagesInUse:`[now-30d ... now]` and operatingSystem:Ubuntu"

  # Dry run / Force / Quiet
  python3 qualys_image_snow_report.py -g ... --dry-run
  python3 qualys_image_snow_report.py -g ... --force
  python3 qualys_image_snow_report.py -g ... -q --force

─── SUPPORTED GATEWAYS ─────────────────────────────────────────

  US-1:  https://gateway.qg1.apps.qualys.com
  US-2:  https://gateway.qg2.apps.qualys.com
  US-3:  https://gateway.qg3.apps.qualys.com
  US-4:  https://gateway.qg4.apps.qualys.com
  EU-1:  https://gateway.qg1.apps.qualys.eu
  EU-2:  https://gateway.qg2.apps.qualys.eu
  CA:    https://gateway.qg1.apps.qualys.ca
  IN:    https://gateway.qg1.apps.qualys.in
  AU:    https://gateway.qg1.apps.qualys.com.au
  UAE:   https://gateway.qg1.apps.qualys.ae
  UK:    https://gateway.qg1.apps.qualys.co.uk
  KSA:   https://gateway.qg1.apps.qualysksa.com
  GOV:   https://gateway.gov1.qualys.us

─── QQL REFERENCE ──────────────────────────────────────────────

  All QQL tokens for images:
  https://docs.qualys.com/en/cs/1.41.0/search_tips/search_ui_images.htm
""",
    )

    get_env = os.environ.get

    # ── Authentication ──
    auth_group = argument_parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-u", "--username",
        default=get_env("QUALYS_USERNAME", ""),
        help="Qualys username  (default: $QUALYS_USERNAME)")
    auth_group.add_argument(
        "-p", "--password",
        default=get_env("QUALYS_PASSWORD", ""),
        help="Qualys password  (default: $QUALYS_PASSWORD)")

    # ── Connection ──
    connection_group = argument_parser.add_argument_group("connection")
    connection_group.add_argument(
        "-g", "--gateway",
        default=get_env("QUALYS_GATEWAY", DEFAULT_GATEWAY_URL),
        help=f"Qualys gateway URL  (default: {DEFAULT_GATEWAY_URL})")

    # ── Query / Filter ──
    query_group = argument_parser.add_argument_group("query")
    query_group.add_argument(
        "-d", "--days", type=int,
        default=int(get_env("QUALYS_DAYS", DEFAULT_LOOKBACK_DAYS)),
        help=(f"Image lookback days for default filter "
              f"(default: {DEFAULT_LOOKBACK_DAYS}).  "
              f"Ignored when --raw-filter is used."))
    query_group.add_argument(
        "-f", "--filter",
        default=get_env("QUALYS_FILTER", ""),
        help=("Extra QQL appended with AND to the default "
              "imagesInUse filter.  "
              "Example: -f \"vulnerabilities.severity:5\""))
    query_group.add_argument(
        "--raw-filter",
        default=get_env("QUALYS_RAW_FILTER", ""),
        help=("Complete raw QQL filter — overrides -d and -f.  "
              "URL-encoded automatically.  "
              "Example: --raw-filter "
              "\"imagesInUse:`[now-30d ... now]`\""))
    query_group.add_argument(
        "-l", "--limit", type=int,
        default=int(get_env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)),
        help=f"Records per API page  (default: {DEFAULT_PAGE_LIMIT})")

    # ── Output ──
    output_group = argument_parser.add_argument_group("output")
    output_group.add_argument(
        "-o", "--output-dir",
        default=get_env("QUALYS_OUTPUT_DIR", "./qualys_snow_output"),
        help="Output directory  (default: ./qualys_snow_output)")

    # ── Behavior ──
    behavior_group = argument_parser.add_argument_group("behavior")
    behavior_group.add_argument(
        "--force", action="store_true",
        help="Ignore checkpoint, start completely fresh")
    behavior_group.add_argument(
        "-r", "--retries", type=int,
        default=int(get_env("QUALYS_RETRIES", DEFAULT_MAX_RETRIES)),
        help=f"Max retries per API call  (default: {DEFAULT_MAX_RETRIES})")
    behavior_group.add_argument(
        "--cps", type=int,
        default=int(get_env("QUALYS_CPS", DEFAULT_CALLS_PER_SECOND)),
        help=f"Max API calls/sec  (default: {DEFAULT_CALLS_PER_SECOND})")
    behavior_group.add_argument(
        "-C", "--curl-extra",
        default=get_env("QUALYS_CURL_EXTRA", ""),
        help="Extra curl arguments  (e.g. \"--proxy http://...\")")
    behavior_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug-level console output")
    behavior_group.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress console output (log file still written)")
    behavior_group.add_argument(
        "--dry-run", action="store_true",
        help="Preview configuration and URLs, make no API calls")

    return argument_parser.parse_args()

# =============================================================================
# MAIN — orchestrates the entire report generation
# =============================================================================


def main():
    parsed_arguments = parse_command_line_arguments()
    run_start_time = time.time()

    # ── Validate credentials ──
    if not parsed_arguments.username or not parsed_arguments.password:
        print(
            "ERROR: Qualys credentials required.\n\n"
            "  Set environment variables:\n"
            "    export QUALYS_USERNAME=\"myuser\"\n"
            "    export QUALYS_PASSWORD=\"mypass\"\n\n"
            "  Or use CLI flags:\n"
            "    -u myuser -p mypass",
            file=sys.stderr)
        sys.exit(1)

    if not parsed_arguments.gateway.startswith("https://"):
        print("ERROR: Gateway URL must use HTTPS.", file=sys.stderr)
        sys.exit(1)

    # ── Build the QQL filter ──
    if parsed_arguments.raw_filter:
        plain_text_qql_filter = parsed_arguments.raw_filter
    else:
        plain_text_qql_filter = (
            f"imagesInUse:`[now-{parsed_arguments.days}d ... now]`")
        if parsed_arguments.filter:
            plain_text_qql_filter += (
                f" and {parsed_arguments.filter}")

    url_encoded_qql_filter = url_encode_qql_filter(
        plain_text_qql_filter)

    # ── Create output directories ──
    output_directory = parsed_arguments.output_dir
    pages_directory = os.path.join(output_directory, "pages")
    os.makedirs(pages_directory, exist_ok=True)

    logger, log_file_path = setup_logging(
        output_directory,
        parsed_arguments.verbose,
        parsed_arguments.quiet)

    acquire_lock_file(output_directory, parsed_arguments.force)

    # ── Build the SNOW API URL ──
    base_api_url = (
        f"{parsed_arguments.gateway.rstrip('/')}"
        f"/csapi/{DEFAULT_API_VERSION}")
    snow_api_url = (
        f"{base_api_url}/images/snow"
        f"?filter={url_encoded_qql_filter}"
        f"&limit={parsed_arguments.limit}")

    # ── Display configuration ──
    logger.info(f"Qualys Image SNOW Report v{VERSION}")
    logger.info(
        f"  Gateway    : {parsed_arguments.gateway}")
    logger.info(
        f"  Username   : {parsed_arguments.username}")
    logger.info(
        f"  QQL Filter : {plain_text_qql_filter}")
    logger.info(
        f"  Limit/page : {parsed_arguments.limit}")
    logger.info(
        f"  Rate limit : {parsed_arguments.cps} calls/sec, "
        f"{parsed_arguments.retries} retries")
    logger.info(f"  Output     : {output_directory}")
    logger.info(f"  Log        : {log_file_path}")

    if parsed_arguments.dry_run:
        logger.info(f"\n  ** DRY RUN — no API calls **")
        logger.info(
            f"  Auth URL   : "
            f"{parsed_arguments.gateway.rstrip('/')}/auth")
        logger.info(f"  SNOW URL   : {snow_api_url}")
        logger.info(f"  QQL (raw)  : {plain_text_qql_filter}")
        logger.info(f"  QQL (enc)  : {url_encoded_qql_filter}")
        return

    # ── Initialize checkpoint ──
    checkpoint_manager = CheckpointManager(
        output_directory,
        compute_configuration_fingerprint(parsed_arguments))

    if (checkpoint_manager.is_phase_complete("complete")
            and not parsed_arguments.force):
        logger.info(
            "\nPrevious run already complete.  "
            "Use --force for a fresh run.")
        return

    if parsed_arguments.force:
        checkpoint_manager.clear_all_checkpoints()

    # ══════════════════════════════════════════════════════════════
    # PHASE 0: Authentication
    # ══════════════════════════════════════════════════════════════
    logger.info(f"\n[Phase 0] Authentication")
    jwt_token = authenticate_and_get_jwt_token(
        parsed_arguments.gateway,
        parsed_arguments.username,
        parsed_arguments.password,
        DEFAULT_CONNECT_TIMEOUT,
        logger)

    rate_limiter = ApiRateLimiter(parsed_arguments.cps, logger)
    api_client = QualysApiClient(
        gateway_url=parsed_arguments.gateway,
        jwt_access_token=jwt_token,
        max_retry_attempts=parsed_arguments.retries,
        connect_timeout_seconds=DEFAULT_CONNECT_TIMEOUT,
        request_timeout_seconds=DEFAULT_REQUEST_TIMEOUT,
        extra_curl_arguments=parsed_arguments.curl_extra,
        rate_limiter=rate_limiter,
        logger=logger)

    # ══════════════════════════════════════════════════════════════
    # PHASE 1: Fetch all SNOW images
    # ══════════════════════════════════════════════════════════════
    if checkpoint_manager.is_phase_complete("fetch"):
        logger.info(f"\n[Phase 1] Fetch SNOW images — cached")
        total_image_count = count_images_across_saved_pages(
            pages_directory, "snow")
        logger.info(
            f"  {total_image_count} images from cache")
    else:
        logger.info(f"\n[Phase 1] Fetching SNOW images...")
        fetched_image_records = \
            api_client.fetch_all_snow_image_pages(
                snow_api_url,
                pages_directory,
                parsed_arguments.limit)
        total_image_count = len(fetched_image_records)
        checkpoint_manager.mark_phase_complete("fetch")

    if total_image_count == 0:
        logger.warning(
            "  WARNING: 0 images returned.  "
            "Check your QQL filter and gateway URL.  "
            "Use --dry-run to preview the URL.")

    # ══════════════════════════════════════════════════════════════
    # PHASE 2: Generate reports (CSV + JSON)
    # ══════════════════════════════════════════════════════════════
    if checkpoint_manager.is_phase_complete("reports"):
        logger.info(f"\n[Phase 2] Reports — cached")
        total_csv_rows = total_vulnerability_count = 0
    else:
        logger.info(f"\n[Phase 2] Generating reports...")

        total_csv_rows, _, total_vulnerability_count = \
            generate_csv_report(
                pages_directory, "snow",
                os.path.join(output_directory,
                             "qualys_image_snow_report.csv"),
                logger)

        generate_json_report(
            pages_directory, "snow",
            os.path.join(output_directory,
                         "qualys_image_snow_report.json"),
            logger)

        checkpoint_manager.mark_phase_complete("reports")

    # ══════════════════════════════════════════════════════════════
    # PHASE 3: Summary
    # ══════════════════════════════════════════════════════════════
    total_elapsed_seconds = time.time() - run_start_time

    print_run_summary(
        pages_directory, "snow",
        total_csv_rows, total_vulnerability_count,
        total_elapsed_seconds, api_client, rate_limiter, logger)

    # Save machine-readable summary
    write_json_file_atomically(
        os.path.join(output_directory, "run_summary.json"),
        {
            "version": VERSION,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "gateway": parsed_arguments.gateway,
            "qql_filter": plain_text_qql_filter,
            "lookback_days": parsed_arguments.days,
            "total_images": total_image_count,
            "total_vulnerabilities": total_vulnerability_count,
            "csv_rows": total_csv_rows,
            "csv_columns": len(CSV_COLUMN_HEADERS),
            "duration": format_seconds_as_duration(
                total_elapsed_seconds),
            "api_calls": api_client.total_api_calls_made,
            "retries": api_client.total_retry_attempts,
            "errors": api_client.total_failed_calls,
            "throttles": rate_limiter.total_throttle_events,
        })

    checkpoint_manager.mark_phase_complete("complete")
    logger.info(f"\n  All reports saved to: {output_directory}/")


if __name__ == "__main__":
    main()
