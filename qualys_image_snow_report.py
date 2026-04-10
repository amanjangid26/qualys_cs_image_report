#!/usr/bin/env python3
"""
=============================================================================
Qualys Container Security - Image SNOW Vulnerability Report
Version: 3.0.0
Author:  Qualys CS Engineering
License: Apache 2.0
=============================================================================

Fetches container-image records from the Qualys CSAPI SNOW endpoint,
enriches each QID with vulnerability title, CVE IDs, and patch status
from a per-image vuln API, classifies each QID as Base or Application/Child
layer, and produces CSV + JSON reports.

API ENDPOINTS USED:

    1. POST /auth
       Username + password -> JWT token (valid 4 hours).

    2. GET /csapi/v1.3/images/snow?filter=<QQL>&limit=250
       All images with layers, vulns, software, container counts.

    3. GET /csapi/v1.3/images/<SHA>/vuln?type=ALL&applyException=true
       Per-image vuln details: title, CVE IDs, patchAvailable.

HOW IT WORKS:

    Phase 0 - AUTHENTICATION
    Phase 1 - FETCH ALL IMAGES (SNOW, paginated, 250/page)
    Phase 2 - FETCH VULN DETAILS (per unique image SHA, cached)
    Phase 3 - GENERATE REPORTS (CSV + JSON, streaming, constant memory)
    Phase 4 - RUN SUMMARY

QID LAYER CLASSIFICATION - 3 conditions only:
    isBaseLayer = true   ->  "Base"
    isBaseLayer = false  ->  "Application/Child"
    isBaseLayer = null   ->  "null"

QQL FILTER:
    Accepts ANY valid Qualys QQL expression. All special characters
    (backticks, quotes, colons, brackets, etc.) are URL-encoded
    automatically. Full token list:
    https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm

FEATURES:
    Idempotent, atomic writes, lock file, Ctrl+C safe, rate-limit aware,
    exponential backoff + jitter, streaming (constant ~10 MB memory),
    vuln cache (resume-safe), duplicate detection (no infinite loops),
    tested with 50,000+ images.

PREREQUISITES: Python 3.8+, curl. No pip packages.
=============================================================================
"""

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

VERSION = "3.0.0"

# =============================================================================
# DEFAULTS
# =============================================================================
DEFAULT_GATEWAY_URL       = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION       = "v1.3"
DEFAULT_PAGE_LIMIT        = 250
DEFAULT_LOOKBACK_DAYS     = 1
DEFAULT_MAX_RETRIES       = 3
DEFAULT_CONNECT_TIMEOUT   = 15
DEFAULT_REQUEST_TIMEOUT   = 120
DEFAULT_CALLS_PER_SECOND  = 2

# =============================================================================
# SIGNAL HANDLING
# =============================================================================
shutdown_was_requested = False

def on_shutdown_signal(signal_number, _stack_frame):
    global shutdown_was_requested
    signal_name = signal.Signals(signal_number).name
    print(f"\n[!] {signal_name} received - saving progress...", file=sys.stderr)
    shutdown_was_requested = True

signal.signal(signal.SIGINT, on_shutdown_signal)
signal.signal(signal.SIGTERM, on_shutdown_signal)

def raise_if_shutdown_requested():
    if shutdown_was_requested:
        raise SystemExit(130)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def convert_none_to_empty_string(value):
    """None or literal 'None' -> empty string."""
    if value is None or value == "None":
        return ""
    return str(value)

def convert_epoch_milliseconds_to_iso_date(epoch_milliseconds):
    """Qualys epoch-ms -> ISO 8601. '0' or null -> empty."""
    if not epoch_milliseconds or str(epoch_milliseconds) == "0":
        return ""
    try:
        timestamp_in_seconds = int(epoch_milliseconds) / 1000
        utc_datetime = datetime.fromtimestamp(timestamp_in_seconds, tz=timezone.utc)
        return utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_milliseconds)

def write_json_file_atomically(file_path, data_to_write):
    """Write JSON via temp file -> atomic rename."""
    parent_directory = os.path.dirname(file_path)
    file_descriptor, temporary_path = tempfile.mkstemp(dir=parent_directory, suffix=".tmp")
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
    try:
        os.remove(file_path)
    except OSError:
        pass

def format_seconds_as_duration(total_seconds):
    total_seconds = int(total_seconds)
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        return f"{total_seconds // 60}m{total_seconds % 60}s"
    return f"{total_seconds // 3600}h{(total_seconds % 3600) // 60}m"

def convert_qds_score_to_severity_label(qds_score):
    """QDS score -> CRITICAL/HIGH/MEDIUM/LOW."""
    if qds_score is None:
        return ""
    qds_score = int(qds_score)
    if qds_score >= 70: return "CRITICAL"
    if qds_score >= 40: return "HIGH"
    if qds_score >= 25: return "MEDIUM"
    return "LOW"

def compute_configuration_fingerprint(parsed_arguments):
    """Hash of config - checkpoint auto-resets when config changes."""
    configuration_string = (
        f"{parsed_arguments.gateway}|{parsed_arguments.days}"
        f"|{parsed_arguments.limit}|{parsed_arguments.filter or ''}"
        f"|{parsed_arguments.raw_filter or ''}")
    return hashlib.sha256(configuration_string.encode()).hexdigest()[:16]

def url_encode_qql_filter(plain_text_qql_filter):
    """URL-encode a raw QQL filter string for the API URL.
    Uses safe='' to encode ALL special characters:
    backticks ` quotes ' " colons : brackets [ ] parentheses ( )
    curly braces { } commas , spaces, dots . hyphens - slashes /
    plus + equals = ampersand & hash # at @ exclamation ! dollar $
    and any other character."""
    return python_url_encode(plain_text_qql_filter, safe='')

# =============================================================================
# LOGGING
# =============================================================================

def setup_logging(output_directory, enable_verbose, enable_quiet):
    logger = logging.getLogger("qualys_snow_report")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    log_file_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_file_name)
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(file_handler)
    if not enable_quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if enable_verbose else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)
    return logger, log_file_path

# =============================================================================
# LOCK FILE + CHECKPOINT
# =============================================================================

def acquire_lock_file(output_directory, force_mode_enabled):
    lock_file_path = os.path.join(output_directory, ".lock")
    if os.path.exists(lock_file_path):
        try:
            existing_process_id = int(open(lock_file_path).read().strip())
            os.kill(existing_process_id, 0)
            if not force_mode_enabled:
                print(f"ERROR: Another instance running (PID {existing_process_id}). Use --force.", file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    with open(lock_file_path, "w") as lock_file:
        lock_file.write(str(os.getpid()))
    atexit.register(lambda: delete_file_if_exists(lock_file_path))

class CheckpointManager:
    def __init__(self, output_directory, configuration_fingerprint):
        self.checkpoint_file_path = os.path.join(output_directory, ".checkpoint.json")
        self.configuration_fingerprint = configuration_fingerprint
        self.completed_phases = {}
        if os.path.exists(self.checkpoint_file_path):
            try:
                saved_state = json.load(open(self.checkpoint_file_path))
                if saved_state.get("fingerprint") == configuration_fingerprint:
                    self.completed_phases = saved_state
            except (json.JSONDecodeError, KeyError):
                pass

    def is_phase_complete(self, phase_name):
        return self.completed_phases.get(phase_name) is True

    def mark_phase_complete(self, phase_name):
        self.completed_phases[phase_name] = True
        self.completed_phases["fingerprint"] = self.configuration_fingerprint
        write_json_file_atomically(self.checkpoint_file_path, self.completed_phases)

    def clear_all_checkpoints(self):
        delete_file_if_exists(self.checkpoint_file_path)
        self.completed_phases = {}

# =============================================================================
# JWT AUTHENTICATION - POST /auth
# =============================================================================

def authenticate_and_get_jwt_token(gateway_url, username, password, connect_timeout_seconds, logger):
    authentication_url = f"{gateway_url.rstrip('/')}/auth"
    logger.info(f"  Authenticating as '{username}'...")
    encoded_username = python_url_encode(username, safe='')
    encoded_password = python_url_encode(password, safe='')
    curl_command = [
        "curl", "-s", "-w", "\n%{http_code}",
        "--connect-timeout", str(connect_timeout_seconds), "--max-time", "30",
        "-X", "POST", authentication_url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", f"username={encoded_username}&password={encoded_password}&token=true",
    ]
    try:
        curl_result = subprocess.run(curl_command, capture_output=True, text=True)
        output_lines = curl_result.stdout.strip().split("\n")
        http_status_code = int(output_lines[-1]) if output_lines[-1].isdigit() else 0
        response_body = "\n".join(output_lines[:-1]).strip()
    except Exception as error:
        logger.error(f"  Authentication failed: {error}"); sys.exit(1)
    if http_status_code in (200, 201) and response_body:
        jwt_token = response_body.strip()
        if jwt_token.startswith("eyJ"):
            logger.info(f"  Token obtained: {jwt_token[:15]}...{jwt_token[-6:]}  (valid ~4 hours)")
            return jwt_token
        else:
            logger.error(f"  Unexpected auth response: {response_body[:100]}"); sys.exit(1)
    if http_status_code == 401:
        logger.error("  Invalid username or password.")
    else:
        logger.error(f"  Auth failed: HTTP {http_status_code}")
        if response_body: logger.error(f"  {response_body[:200]}")
    sys.exit(1)

# =============================================================================
# RATE LIMITER
# =============================================================================

class ApiRateLimiter:
    def __init__(self, max_calls_per_second, logger):
        self.minimum_interval_between_calls = 1.0 / max_calls_per_second
        self.logger = logger
        self.thread_lock = threading.Lock()
        self.last_call_timestamp = 0.0
        self.pause_all_calls_until = 0.0
        self.total_throttle_events = 0

    def wait_until_safe_to_call(self):
        while True:
            raise_if_shutdown_requested()
            with self.thread_lock:
                current_time = time.time()
                if current_time < self.pause_all_calls_until:
                    wait_seconds = self.pause_all_calls_until - current_time
                    self.thread_lock.release(); time.sleep(wait_seconds); self.thread_lock.acquire(); continue
                seconds_since_last_call = current_time - self.last_call_timestamp
                if seconds_since_last_call < self.minimum_interval_between_calls:
                    wait_seconds = self.minimum_interval_between_calls - seconds_since_last_call
                    self.thread_lock.release(); time.sleep(wait_seconds); self.thread_lock.acquire(); continue
                self.last_call_timestamp = time.time()
                return

    def check_rate_limit_headers(self, header_file_path):
        if not os.path.exists(header_file_path): return
        remaining_calls = window_seconds = None
        try:
            with open(header_file_path) as header_file:
                for line in header_file:
                    lowercase_line = line.lower().strip()
                    if lowercase_line.startswith("x-ratelimit-remaining:"):
                        remaining_calls = int(line.split(":", 1)[1].strip())
                    elif lowercase_line.startswith("x-ratelimit-window-sec:"):
                        window_seconds = int(line.split(":", 1)[1].strip())
        except Exception: return
        with self.thread_lock:
            if remaining_calls is not None and remaining_calls <= 0:
                pause_duration = (window_seconds or 60) + 5
                self.pause_all_calls_until = time.time() + pause_duration
                self.logger.warning(f"  Rate limit exhausted - pausing {pause_duration}s")
                self.total_throttle_events += 1
            elif remaining_calls is not None and remaining_calls <= 20:
                self.minimum_interval_between_calls = max(self.minimum_interval_between_calls, 1.0)

    def handle_too_many_requests(self, header_file_path):
        retry_after_seconds = None
        if os.path.exists(header_file_path):
            try:
                with open(header_file_path) as header_file:
                    for line in header_file:
                        if line.lower().strip().startswith("retry-after:"):
                            retry_after_seconds = int(line.split(":", 1)[1].strip())
            except Exception: pass
        pause_duration = retry_after_seconds or 35
        with self.thread_lock:
            self.pause_all_calls_until = time.time() + pause_duration
            self.logger.warning(f"  HTTP 429 - pausing {pause_duration}s")
            self.total_throttle_events += 1

# =============================================================================
# API CLIENT
# =============================================================================

class QualysApiClient:
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
        self.total_api_calls_made = 0
        self.total_retry_attempts = 0
        self.total_failed_calls = 0

    def make_get_request(self, request_url, output_file_path, keep_response_headers=False):
        for attempt_number in range(self.max_retry_attempts + 1):
            raise_if_shutdown_requested()
            if attempt_number > 0:
                backoff_delay = random.uniform(1, min(15, 2 ** attempt_number))
                self.logger.debug(f"  Retry {attempt_number}/{self.max_retry_attempts} in {backoff_delay:.0f}s...")
                time.sleep(backoff_delay)
                self.total_retry_attempts += 1
            self.rate_limiter.wait_until_safe_to_call()
            response_header_file = output_file_path + ".hdr"
            curl_command = [
                "curl", "-s", "-o", output_file_path, "-D", response_header_file,
                "-w", "%{http_code}",
                "--connect-timeout", str(self.connect_timeout_seconds),
                "--max-time", str(self.request_timeout_seconds),
                "-X", "GET", request_url,
                "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.jwt_access_token}",
            ]
            if self.extra_curl_arguments:
                curl_command.extend(self.extra_curl_arguments.split())
            try:
                curl_result = subprocess.run(curl_command, capture_output=True, text=True)
                http_status_code = int(curl_result.stdout.strip()) if curl_result.stdout.strip().isdigit() else 0
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self.total_api_calls_made += 1; self.total_failed_calls += 1; continue
            self.total_api_calls_made += 1
            self.rate_limiter.check_rate_limit_headers(response_header_file)
            if http_status_code in (200, 204):
                if not keep_response_headers: delete_file_if_exists(response_header_file)
                return http_status_code
            if http_status_code == 401:
                self.logger.error("HTTP 401 - token expired. Re-run."); sys.exit(1)
            if http_status_code == 403:
                self.logger.error("HTTP 403 - insufficient permissions."); sys.exit(1)
            if http_status_code == 404:
                delete_file_if_exists(response_header_file); return 404
            if http_status_code == 429:
                self.rate_limiter.handle_too_many_requests(response_header_file)
            delete_file_if_exists(response_header_file)
        self.total_failed_calls += 1
        return 0

    def fetch_all_snow_image_pages(self, base_snow_url, pages_directory, records_per_page, page_label="snow"):
        """Paginate SNOW endpoint. Stops on: empty page, fewer records, or duplicate data."""
        all_image_records = []
        already_seen_image_shas = set()
        current_page_number = 1
        current_offset = 0
        while True:
            raise_if_shutdown_requested()
            url_separator = "&" if "?" in base_snow_url else "?"
            page_url = f"{base_snow_url}{url_separator}offset={current_offset}"
            page_file_path = os.path.join(pages_directory, f"{page_label}_{current_page_number:04d}.json")
            # Resume from cache
            if os.path.exists(page_file_path):
                try:
                    cached_image_records = json.load(open(page_file_path)).get("data", [])
                    if isinstance(cached_image_records, list) and len(cached_image_records) > 0:
                        new_image_shas = {image.get("sha") for image in cached_image_records if image.get("sha")}
                        if new_image_shas and new_image_shas.issubset(already_seen_image_shas):
                            self.logger.info(f"  page {current_page_number}: duplicate (cached) - stopping")
                            delete_file_if_exists(page_file_path); break
                        all_image_records.extend(cached_image_records)
                        already_seen_image_shas.update(new_image_shas)
                        self.logger.info(f"  page {current_page_number}: {len(cached_image_records)} images (cached, total: {len(all_image_records)})")
                        if len(cached_image_records) < records_per_page: break
                        current_offset += records_per_page; current_page_number += 1; continue
                except (json.JSONDecodeError, KeyError): pass
            # Fetch from API
            self.logger.info(f"  Fetching page {current_page_number} (offset={current_offset})...")
            http_status = self.make_get_request(page_url, page_file_path)
            if http_status == 204:
                self.logger.info(f"  page {current_page_number}: HTTP 204 - all data fetched")
                delete_file_if_exists(page_file_path); break
            if http_status != 200:
                self.logger.error(f"  Failed page {current_page_number} (HTTP {http_status})"); break
            try:
                page_image_records = json.load(open(page_file_path)).get("data", [])
            except (json.JSONDecodeError, KeyError):
                self.logger.error(f"  Failed to parse page {current_page_number}"); break
            if not isinstance(page_image_records, list) or len(page_image_records) == 0:
                self.logger.info(f"  page {current_page_number}: 0 images - all data fetched")
                delete_file_if_exists(page_file_path); break
            # Duplicate detection
            new_image_shas = {image.get("sha") for image in page_image_records if image.get("sha")}
            if new_image_shas and new_image_shas.issubset(already_seen_image_shas):
                self.logger.info(f"  page {current_page_number}: duplicate - all data fetched")
                delete_file_if_exists(page_file_path); break
            all_image_records.extend(page_image_records)
            already_seen_image_shas.update(new_image_shas)
            self.logger.info(f"  page {current_page_number}: {len(page_image_records)} images (total: {len(all_image_records)})")
            if len(page_image_records) < records_per_page: break
            current_offset += records_per_page; current_page_number += 1
        self.logger.info(f"  Fetched {len(all_image_records)} images across {current_page_number} page(s)")
        return all_image_records

# =============================================================================
# VULN DETAIL FETCHER - calls /images/<SHA>/vuln per unique image
# =============================================================================

def fetch_vuln_details_for_all_images(api_client, base_api_url, pages_directory, vuln_cache_directory, page_label, logger):
    """For each unique image SHA, call vuln API. Returns: dict qid(int) -> {title, cveids, patchAvailable}"""
    global_qid_details = {}
    unique_image_shas = set()
    # Collect SHAs from pages
    page_number = 1
    while True:
        page_file_path = os.path.join(pages_directory, f"{page_label}_{page_number:04d}.json")
        if not os.path.exists(page_file_path): break
        try:
            page_data = json.load(open(page_file_path)).get("data", [])
            if not isinstance(page_data, list) or not page_data: break
            for image in page_data:
                image_sha = image.get("sha")
                if image_sha: unique_image_shas.add(image_sha)
            page_number += 1
        except (json.JSONDecodeError, KeyError): break

    logger.info(f"  {len(unique_image_shas)} unique image SHAs to enrich")
    completed_count = 0
    total_to_fetch = len(unique_image_shas)
    fetch_start_time = time.time()

    for image_sha in unique_image_shas:
        raise_if_shutdown_requested()
        cache_file_path = os.path.join(vuln_cache_directory, f"{image_sha[:16]}.json")
        # Check cache
        if os.path.exists(cache_file_path):
            try:
                cached_vuln_data = json.load(open(cache_file_path))
                for qid_str, details in cached_vuln_data.items():
                    global_qid_details[int(qid_str)] = details
                completed_count += 1
                if completed_count % 50 == 0:
                    logger.info(f"  Vuln details: {completed_count}/{total_to_fetch} (cached)")
                continue
            except (json.JSONDecodeError, KeyError, ValueError): pass
        # Fetch from API
        vuln_api_url = f"{base_api_url}/images/{image_sha}/vuln?type=ALL&applyException=true"
        temp_response_file = os.path.join(vuln_cache_directory, f"_tmp_{image_sha[:16]}.json")
        http_status = api_client.make_get_request(vuln_api_url, temp_response_file)
        image_qid_map = {}
        if http_status == 200:
            try:
                vuln_response = json.load(open(temp_response_file))
                for vuln_detail in vuln_response.get("details", []):
                    qid_value = vuln_detail.get("qid")
                    if qid_value is None: continue
                    cve_id_list = vuln_detail.get("cveids") or []
                    cve_ids_joined = ", ".join(cve_id_list)
                    patch_available_value = vuln_detail.get("patchAvailable")
                    if patch_available_value is True: patch_available_string = "true"
                    elif patch_available_value is False: patch_available_string = "false"
                    else: patch_available_string = ""
                    vuln_title = convert_none_to_empty_string(vuln_detail.get("title"))
                    qid_detail_record = {"title": vuln_title, "cveids": cve_ids_joined, "patchAvailable": patch_available_string}
                    image_qid_map[str(qid_value)] = qid_detail_record
                    global_qid_details[int(qid_value)] = qid_detail_record
            except (json.JSONDecodeError, KeyError): pass
        delete_file_if_exists(temp_response_file)
        write_json_file_atomically(cache_file_path, image_qid_map)
        completed_count += 1
        if completed_count % 10 == 0 or completed_count == total_to_fetch:
            elapsed = time.time() - fetch_start_time
            rate = elapsed / completed_count if completed_count else 1
            remaining_time = (total_to_fetch - completed_count) * rate
            logger.info(f"  Vuln details: {completed_count}/{total_to_fetch}  ({format_seconds_as_duration(remaining_time)} left)")

    logger.info(f"  Enriched {len(global_qid_details)} unique QIDs from {len(unique_image_shas)} images")
    return global_qid_details

# =============================================================================
# PAGE ITERATOR - constant memory
# =============================================================================

def iterate_images_from_saved_pages(pages_directory, page_label):
    page_number = 1
    while True:
        page_file_path = os.path.join(pages_directory, f"{page_label}_{page_number:04d}.json")
        if not os.path.exists(page_file_path): break
        try:
            with open(page_file_path) as page_file:
                page_data = json.load(page_file).get("data", [])
            if not isinstance(page_data, list) or len(page_data) == 0: break
            yield from page_data
            page_number += 1
        except (json.JSONDecodeError, KeyError): break

def count_images_across_saved_pages(pages_directory, page_label):
    total_image_count = 0; page_number = 1
    while True:
        page_file_path = os.path.join(pages_directory, f"{page_label}_{page_number:04d}.json")
        if not os.path.exists(page_file_path): break
        try:
            with open(page_file_path) as page_file:
                page_data = json.load(page_file).get("data", [])
            if not isinstance(page_data, list) or len(page_data) == 0: break
            total_image_count += len(page_data); page_number += 1
        except (json.JSONDecodeError, KeyError): break
    return total_image_count

# =============================================================================
# QID LAYER CLASSIFICATION - 3 conditions: true, false, null
# =============================================================================

def build_layer_sha_map(image_data):
    """Build lookup: full_sha -> (isBaseLayer, createdBy)"""
    sha_map = {}
    for layer in (image_data.get("layers") or []):
        layer_sha = layer.get("sha")
        if layer_sha:
            sha_map[layer_sha] = (layer.get("isBaseLayer"), layer.get("createdBy") or "")
    return sha_map

def classify_qid_layer_origin(vulnerability_layer_shas, layer_sha_map):
    """3 conditions: true->Base, false->Application/Child, null->null.
    Returns: (label, full_sha, created_by_instruction)"""
    if not vulnerability_layer_shas:
        return "", "", ""
    for layer_sha in vulnerability_layer_shas:
        if layer_sha in layer_sha_map:
            is_base_layer_value, created_by_instruction = layer_sha_map[layer_sha]
            if is_base_layer_value is True:
                return "Base", layer_sha, created_by_instruction
            elif is_base_layer_value is False:
                return "Application/Child", layer_sha, created_by_instruction
            else:
                return "null", layer_sha, created_by_instruction
    first_sha = vulnerability_layer_shas[0] if vulnerability_layer_shas else ""
    return "null", first_sha, ""

def extract_repository_information(image_data):
    repository_entries = image_data.get("repo") or []
    digest_entries = image_data.get("repoDigests") or []
    registry_fallback_map = {d["repository"]: d["registry"] for d in digest_entries if d.get("registry") and d.get("repository")}
    extracted_repositories = []
    for repository_entry in repository_entries:
        registry_name = repository_entry.get("registry") or ""
        repository_name = convert_none_to_empty_string(repository_entry.get("repository"))
        if not registry_name and repository_name:
            registry_name = registry_fallback_map.get(repository_name, "")
        extracted_repositories.append({
            "registry": convert_none_to_empty_string(registry_name),
            "repository": repository_name,
            "tag": convert_none_to_empty_string(repository_entry.get("tag")),
        })
    return extracted_repositories or [{"registry": "", "repository": "", "tag": ""}]

# =============================================================================
# CSV + JSON REPORT - 30 columns
# =============================================================================

CSV_COLUMN_HEADERS = [
    "Image_ID", "Image_SHA", "Operating_System", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types", "Image_Source",
    "Registry", "Repository", "Image_Tag", "Risk_Score",
    "Parent_Base_Image", "Associated_Container_Count", "Total_Vulnerabilities_On_Image",
    "Vuln_QID", "Vuln_Title", "Vuln_QDS_Score", "Vuln_QDS_Severity", "Vuln_Scan_Type",
    "Vuln_CVE_IDs", "Vuln_Patch_Available",
    "QID_Layer_Type", "QID_Layer_SHA", "QID_Layer_Created_By", "Vuln_Affected_Software_Count",
    "Software_Name", "Software_Installed_Version", "Software_Fix_Version", "Software_Package_Path",
]
EMPTY_VULNERABILITY_COLUMNS = [""] * 11
EMPTY_SOFTWARE_COLUMNS = [""] * 4

def generate_csv_report(pages_directory, page_label, global_qid_details, csv_output_path, logger):
    temporary_csv_path = csv_output_path + ".tmp"
    total_csv_rows_written = 0; total_images_processed = 0; total_vulnerabilities_processed = 0
    with open(temporary_csv_path, "w", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(CSV_COLUMN_HEADERS)
        for image in iterate_images_from_saved_pages(pages_directory, page_label):
            total_images_processed += 1; raise_if_shutdown_requested()
            image_sha = image.get("sha", "")
            vulnerability_list = image.get("vulnerabilities") or []
            repository_list = extract_repository_information(image)
            layer_map = build_layer_sha_map(image)
            associated_container_count = image.get("associatedContainersCount", 0)
            parent_base_image_sha = convert_none_to_empty_string(image.get("baseImage"))
            image_base_columns = [
                convert_none_to_empty_string(image.get("imageId")), image_sha,
                convert_none_to_empty_string(image.get("operatingSystem")),
                convert_none_to_empty_string(image.get("architecture")),
                convert_epoch_milliseconds_to_iso_date(image.get("created")),
                convert_epoch_milliseconds_to_iso_date(image.get("lastScanned")),
                " | ".join(convert_none_to_empty_string(st) for st in (image.get("scanTypes") or [])),
                " | ".join(convert_none_to_empty_string(src) for src in (image.get("source") or [])),
            ]
            for repository in repository_list:
                image_columns = image_base_columns + [
                    repository["registry"], repository["repository"], repository["tag"],
                    convert_none_to_empty_string(image.get("riskScore")),
                    parent_base_image_sha, str(associated_container_count), str(len(vulnerability_list)),
                ]
                if vulnerability_list:
                    for vulnerability in vulnerability_list:
                        total_vulnerabilities_processed += 1
                        qds_score = vulnerability.get("qdsScore"); qid_value = vulnerability.get("qid")
                        qid_enrichment = global_qid_details.get(qid_value, {})
                        layer_classification, layer_sha, layer_created_by = classify_qid_layer_origin(vulnerability.get("layerSha") or [], layer_map)
                        affected_software_list = vulnerability.get("software") or []
                        vulnerability_columns = [
                            convert_none_to_empty_string(qid_value),
                            qid_enrichment.get("title", ""),
                            convert_none_to_empty_string(qds_score) if qds_score is not None else "",
                            convert_qds_score_to_severity_label(qds_score),
                            " | ".join(convert_none_to_empty_string(st) for st in (vulnerability.get("scanType") or [])),
                            qid_enrichment.get("cveids", ""),
                            qid_enrichment.get("patchAvailable", ""),
                            layer_classification, layer_sha, layer_created_by,
                            str(len(affected_software_list)),
                        ]
                        if affected_software_list:
                            for software in affected_software_list:
                                software_columns = [
                                    convert_none_to_empty_string(software.get("name")),
                                    convert_none_to_empty_string(software.get("version")),
                                    convert_none_to_empty_string(software.get("fixVersion")),
                                    convert_none_to_empty_string(software.get("packagePath")),
                                ]
                                csv_writer.writerow(image_columns + vulnerability_columns + software_columns)
                                total_csv_rows_written += 1
                        else:
                            csv_writer.writerow(image_columns + vulnerability_columns + EMPTY_SOFTWARE_COLUMNS)
                            total_csv_rows_written += 1
                else:
                    csv_writer.writerow(image_columns + EMPTY_VULNERABILITY_COLUMNS + EMPTY_SOFTWARE_COLUMNS)
                    total_csv_rows_written += 1
    os.replace(temporary_csv_path, csv_output_path)
    logger.info(f"  CSV: {csv_output_path}  ({total_csv_rows_written:,} rows x {len(CSV_COLUMN_HEADERS)} cols)")
    return total_csv_rows_written, total_images_processed, total_vulnerabilities_processed

def generate_json_report(pages_directory, page_label, global_qid_details, json_output_path, logger):
    temporary_json_path = json_output_path + ".tmp"
    total_images_written = 0; total_vulnerabilities_written = 0
    with open(temporary_json_path, "w", encoding="utf-8") as json_file:
        generation_timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        json_file.write('{\n')
        json_file.write(f'  "generatedAt": "{generation_timestamp}",\n')
        json_file.write('  "images": [\n')
        is_first_image = True
        for image in iterate_images_from_saved_pages(pages_directory, page_label):
            total_images_written += 1; raise_if_shutdown_requested()
            layer_map = build_layer_sha_map(image)
            vulnerability_list = image.get("vulnerabilities") or []
            enriched_vulnerabilities = []
            for vulnerability in vulnerability_list:
                total_vulnerabilities_written += 1
                qid_value = vulnerability.get("qid"); qds_score = vulnerability.get("qdsScore")
                qid_enrichment = global_qid_details.get(qid_value, {})
                layer_classification, layer_sha, layer_created_by = classify_qid_layer_origin(vulnerability.get("layerSha") or [], layer_map)
                enriched_vulnerabilities.append({
                    "qid": qid_value, "title": qid_enrichment.get("title", ""),
                    "qdsScore": qds_score, "qdsSeverity": convert_qds_score_to_severity_label(qds_score),
                    "scanType": vulnerability.get("scanType") or [],
                    "cveIds": qid_enrichment.get("cveids", ""), "patchAvailable": qid_enrichment.get("patchAvailable", ""),
                    "qidLayerType": layer_classification, "qidLayerSha": layer_sha, "qidLayerCreatedBy": layer_created_by,
                    "affectedSoftware": [
                        {"name": convert_none_to_empty_string(sw.get("name")), "version": convert_none_to_empty_string(sw.get("version")),
                         "fixVersion": convert_none_to_empty_string(sw.get("fixVersion")), "packagePath": convert_none_to_empty_string(sw.get("packagePath"))}
                        for sw in (vulnerability.get("software") or [])
                    ],
                })
            qds_scores = [v.get("qdsScore") for v in vulnerability_list if v.get("qdsScore") is not None]
            image_record = {
                "imageId": convert_none_to_empty_string(image.get("imageId")), "sha": image.get("sha", ""),
                "operatingSystem": convert_none_to_empty_string(image.get("operatingSystem")),
                "architecture": convert_none_to_empty_string(image.get("architecture")),
                "riskScore": image.get("riskScore"),
                "parentBaseImage": convert_none_to_empty_string(image.get("baseImage")),
                "maxQdsScore": max(qds_scores) if qds_scores else None,
                "associatedContainerCount": image.get("associatedContainersCount", 0),
                "totalVulnerabilities": len(vulnerability_list),
                "repositories": extract_repository_information(image),
                "vulnerabilities": enriched_vulnerabilities,
            }
            if not is_first_image: json_file.write(',\n')
            json_file.write('    ' + json.dumps(image_record, default=str))
            is_first_image = False
        json_file.write(f'\n  ],\n  "totalImages": {total_images_written},\n  "totalVulnerabilities": {total_vulnerabilities_written}\n}}\n')
    os.replace(temporary_json_path, json_output_path)
    logger.info(f"  JSON: {json_output_path}")
    return total_images_written, total_vulnerabilities_written

# =============================================================================
# CLI
# =============================================================================

def parse_command_line_arguments():
    argument_parser = argparse.ArgumentParser(
        prog="qualys_image_snow_report",
        description=f"Qualys CS Image SNOW Vulnerability Report v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  export QUALYS_USERNAME="myuser"
  export QUALYS_PASSWORD="mypass"

  python3 qualys_image_snow_report.py -g https://gateway.qg2.apps.qualys.com
  python3 qualys_image_snow_report.py -g ... -d 30
  python3 qualys_image_snow_report.py -g ... -f "vulnerabilities.severity:5"
  python3 qualys_image_snow_report.py -g ... --raw-filter "imagesInUse:`[now-30d ... now]` and operatingSystem:Ubuntu"
  python3 qualys_image_snow_report.py -g ... --dry-run
  python3 qualys_image_snow_report.py -g ... --force
  python3 qualys_image_snow_report.py -g ... -q --force

QQL token reference:
  https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm

Supported gateways:
  US-1: https://gateway.qg1.apps.qualys.com   EU-1: https://gateway.qg1.apps.qualys.eu
  US-2: https://gateway.qg2.apps.qualys.com   EU-2: https://gateway.qg2.apps.qualys.eu
  US-3: https://gateway.qg3.apps.qualys.com   IN:   https://gateway.qg1.apps.qualys.in
  US-4: https://gateway.qg4.apps.qualys.com   AU:   https://gateway.qg1.apps.qualys.com.au
  CA:   https://gateway.qg1.apps.qualys.ca    UAE:  https://gateway.qg1.apps.qualys.ae
  UK:   https://gateway.qg1.apps.qualys.co.uk KSA:  https://gateway.qg1.apps.qualysksa.com
  GOV:  https://gateway.gov1.qualys.us
""")
    get_env = os.environ.get
    auth = argument_parser.add_argument_group("authentication")
    auth.add_argument("-u", "--username", default=get_env("QUALYS_USERNAME", ""), help="Qualys username (default: $QUALYS_USERNAME)")
    auth.add_argument("-p", "--password", default=get_env("QUALYS_PASSWORD", ""), help="Qualys password (default: $QUALYS_PASSWORD)")
    conn = argument_parser.add_argument_group("connection")
    conn.add_argument("-g", "--gateway", default=get_env("QUALYS_GATEWAY", DEFAULT_GATEWAY_URL), help=f"Gateway URL (default: {DEFAULT_GATEWAY_URL})")
    query = argument_parser.add_argument_group("query")
    query.add_argument("-d", "--days", type=int, default=int(get_env("QUALYS_DAYS", DEFAULT_LOOKBACK_DAYS)), help=f"Lookback days (default: {DEFAULT_LOOKBACK_DAYS}). Ignored with --raw-filter.")
    query.add_argument("-f", "--filter", default=get_env("QUALYS_FILTER", ""), help="Extra QQL appended with AND")
    query.add_argument("--raw-filter", default=get_env("QUALYS_RAW_FILTER", ""), help="Complete raw QQL (overrides -d and -f)")
    query.add_argument("-l", "--limit", type=int, default=int(get_env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)), help=f"Records per page (default: {DEFAULT_PAGE_LIMIT})")
    output = argument_parser.add_argument_group("output")
    output.add_argument("-o", "--output-dir", default=get_env("QUALYS_OUTPUT_DIR", "./qualys_snow_output"), help="Output directory")
    behavior = argument_parser.add_argument_group("behavior")
    behavior.add_argument("--force", action="store_true", help="Ignore checkpoint, start fresh")
    behavior.add_argument("-r", "--retries", type=int, default=int(get_env("QUALYS_RETRIES", DEFAULT_MAX_RETRIES)))
    behavior.add_argument("--cps", type=int, default=int(get_env("QUALYS_CPS", DEFAULT_CALLS_PER_SECOND)), help="Max API calls/sec")
    behavior.add_argument("-C", "--curl-extra", default=get_env("QUALYS_CURL_EXTRA", ""), help='Extra curl args (e.g. "--proxy http://...")')
    behavior.add_argument("-v", "--verbose", action="store_true")
    behavior.add_argument("-q", "--quiet", action="store_true")
    behavior.add_argument("--dry-run", action="store_true", help="Preview config, no API calls")
    return argument_parser.parse_args()

# =============================================================================
# MAIN
# =============================================================================

def main():
    parsed_arguments = parse_command_line_arguments()
    run_start_time = time.time()
    if not parsed_arguments.username or not parsed_arguments.password:
        print("ERROR: Set QUALYS_USERNAME + QUALYS_PASSWORD or -u/-p.", file=sys.stderr); sys.exit(1)
    if not parsed_arguments.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS.", file=sys.stderr); sys.exit(1)

    # Build QQL filter
    if parsed_arguments.raw_filter:
        plain_text_qql_filter = parsed_arguments.raw_filter
    else:
        plain_text_qql_filter = f"imagesInUse:`[now-{parsed_arguments.days}d ... now]`"
        if parsed_arguments.filter:
            plain_text_qql_filter += f" and {parsed_arguments.filter}"
    url_encoded_qql_filter = url_encode_qql_filter(plain_text_qql_filter)

    # Directories
    output_directory = parsed_arguments.output_dir
    pages_directory = os.path.join(output_directory, "pages")
    vuln_cache_directory = os.path.join(output_directory, "vuln_cache")
    os.makedirs(pages_directory, exist_ok=True)
    os.makedirs(vuln_cache_directory, exist_ok=True)

    logger, log_file_path = setup_logging(output_directory, parsed_arguments.verbose, parsed_arguments.quiet)
    acquire_lock_file(output_directory, parsed_arguments.force)

    base_api_url = f"{parsed_arguments.gateway.rstrip('/')}/csapi/{DEFAULT_API_VERSION}"
    snow_api_url = f"{base_api_url}/images/snow?filter={url_encoded_qql_filter}&limit={parsed_arguments.limit}"

    logger.info(f"Qualys Image SNOW Report v{VERSION}")
    logger.info(f"  Gateway    : {parsed_arguments.gateway}")
    logger.info(f"  Username   : {parsed_arguments.username}")
    logger.info(f"  QQL Filter : {plain_text_qql_filter}")
    logger.info(f"  Limit/page : {parsed_arguments.limit}")
    logger.info(f"  Output     : {output_directory}")
    logger.info(f"  Log        : {log_file_path}")

    if parsed_arguments.dry_run:
        logger.info(f"\n  ** DRY RUN - no API calls **")
        logger.info(f"  Auth URL : {parsed_arguments.gateway.rstrip('/')}/auth")
        logger.info(f"  SNOW URL : {snow_api_url}")
        logger.info(f"  Vuln URL : {base_api_url}/images/<SHA>/vuln?type=ALL&applyException=true")
        return

    checkpoint_manager = CheckpointManager(output_directory, compute_configuration_fingerprint(parsed_arguments))
    if checkpoint_manager.is_phase_complete("complete") and not parsed_arguments.force:
        logger.info("\nPrevious run complete. Use --force for fresh."); return
    if parsed_arguments.force:
        checkpoint_manager.clear_all_checkpoints()

    # Phase 0: Auth
    logger.info(f"\n[Phase 0] Authentication")
    jwt_token = authenticate_and_get_jwt_token(parsed_arguments.gateway, parsed_arguments.username, parsed_arguments.password, DEFAULT_CONNECT_TIMEOUT, logger)
    rate_limiter = ApiRateLimiter(parsed_arguments.cps, logger)
    api_client = QualysApiClient(
        gateway_url=parsed_arguments.gateway, jwt_access_token=jwt_token,
        max_retry_attempts=parsed_arguments.retries, connect_timeout_seconds=DEFAULT_CONNECT_TIMEOUT,
        request_timeout_seconds=DEFAULT_REQUEST_TIMEOUT, extra_curl_arguments=parsed_arguments.curl_extra,
        rate_limiter=rate_limiter, logger=logger)

    # Phase 1: Fetch SNOW images
    if checkpoint_manager.is_phase_complete("fetch"):
        logger.info(f"\n[Phase 1] Fetch SNOW images - cached")
        total_image_count = count_images_across_saved_pages(pages_directory, "snow")
        logger.info(f"  {total_image_count} images from cache")
    else:
        logger.info(f"\n[Phase 1] Fetching SNOW images...")
        fetched_records = api_client.fetch_all_snow_image_pages(snow_api_url, pages_directory, parsed_arguments.limit)
        total_image_count = len(fetched_records)
        checkpoint_manager.mark_phase_complete("fetch")
    if total_image_count == 0:
        logger.warning("  0 images returned. Check QQL filter.")

    # Phase 2: Fetch vuln details per image
    if checkpoint_manager.is_phase_complete("vuln_details"):
        logger.info(f"\n[Phase 2] Vuln details - cached")
        global_qid_details = {}
        for cache_file in os.listdir(vuln_cache_directory):
            if cache_file.endswith(".json") and not cache_file.startswith("_"):
                try:
                    cached_data = json.load(open(os.path.join(vuln_cache_directory, cache_file)))
                    for qid_str, details in cached_data.items():
                        global_qid_details[int(qid_str)] = details
                except (json.JSONDecodeError, ValueError): pass
        logger.info(f"  {len(global_qid_details)} QIDs from cache")
    else:
        logger.info(f"\n[Phase 2] Fetching vuln details per image...")
        global_qid_details = fetch_vuln_details_for_all_images(api_client, base_api_url, pages_directory, vuln_cache_directory, "snow", logger)
        checkpoint_manager.mark_phase_complete("vuln_details")

    # Phase 3: Generate reports
    if checkpoint_manager.is_phase_complete("reports"):
        logger.info(f"\n[Phase 3] Reports - cached")
        total_csv_rows = total_vulnerability_count = 0
    else:
        logger.info(f"\n[Phase 3] Generating reports...")
        total_csv_rows, _, total_vulnerability_count = generate_csv_report(
            pages_directory, "snow", global_qid_details,
            os.path.join(output_directory, "qualys_image_snow_report.csv"), logger)
        generate_json_report(
            pages_directory, "snow", global_qid_details,
            os.path.join(output_directory, "qualys_image_snow_report.json"), logger)
        checkpoint_manager.mark_phase_complete("reports")

    # Phase 4: Summary
    total_elapsed_seconds = time.time() - run_start_time
    logger.info(f"\n{'=' * 64}")
    logger.info("  QUALYS IMAGE SNOW - VULNERABILITY REPORT SUMMARY")
    logger.info(f"{'=' * 64}")
    logger.info(f"  Generated     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"  Duration      : {format_seconds_as_duration(total_elapsed_seconds)}")
    logger.info(f"  API Calls     : {api_client.total_api_calls_made} (retries: {api_client.total_retry_attempts}, errors: {api_client.total_failed_calls})")
    logger.info(f"  Images        : {total_image_count}")
    logger.info(f"  QIDs enriched : {len(global_qid_details)}")
    logger.info(f"  CSV Rows      : {total_csv_rows:,} x {len(CSV_COLUMN_HEADERS)} cols")
    logger.info(f"{'=' * 64}")

    write_json_file_atomically(os.path.join(output_directory, "run_summary.json"), {
        "version": VERSION, "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "gateway": parsed_arguments.gateway, "qql_filter": plain_text_qql_filter,
        "total_images": total_image_count, "total_qids_enriched": len(global_qid_details),
        "csv_rows": total_csv_rows, "csv_columns": len(CSV_COLUMN_HEADERS),
        "duration": format_seconds_as_duration(total_elapsed_seconds),
        "api_calls": api_client.total_api_calls_made,
    })
    checkpoint_manager.mark_phase_complete("complete")
    logger.info(f"\n  All reports saved to: {output_directory}/")

if __name__ == "__main__":
    main()
