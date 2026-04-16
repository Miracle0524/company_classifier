"""
Domain classification via Truelist verification.

1) Normalize & syntax gate (0 cost)
2) Truelist domain check (batch or inline)
"""

import argparse
import csv
import json
import logging
import os
import re
import random
import secrets
import socket
import threading
import time
import uuid
import io
import tldextract
import requests
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter

DOMAIN_LABEL_REGEX = re.compile(r"^[a-z0-9-]{1,63}$")
DOMAIN_TLD_REGEX = re.compile(r"^[a-z]{2,63}$")

TRUELIST_CONFIG: Dict[str, Any] = {
    "verify_url": "https://api.truelist.io/api/v1/verify_inline",
    "batch_url": "https://api.truelist.io/api/v1/batches",
    "email_addresses_url": "https://api.truelist.io/api/v1/email_addresses",
    "timeout": 12.0,
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjMyMDRlNzYyLTk3Y2YtNDQ5YS1iZjA2LWE2MjRmYWJlZjBhYiIsImV4cGlyZXNfYXQiOm51bGx9.c4uUaYBHpyEuCjRuks7f-nZRR7QZ-9SwCPSQ-La4QhU",
    "qps": 8.0,
    "timeout_max": 35.0,
    "retry_backoff_base": 0.6,
    "max_retries": 3,
    "rate_limit_fallback_sleep": 5.0,
    "use_batch": True,
    "batch_poll_interval": 5.0,
    "batch_timeout": 20 * 60.0,
    "batch_strategy": "fast",
    "details_default": {
        "truelist_domain_status": "unknown",
        "accept_all": False,
        "greylisted": False,
        "truelist_checked": False,
        "is_real_ok_domain": False,
        "truelist_reason": None,
    },
    "accepted_states": frozenset({"email_ok"}),
    "rejected_states": frozenset(
        {"accept_all", "failed_no_mailbox", "rejected", "invalid", "undeliverable", "no_mailbox", "bad", "reject", "is_role"}
    ),
    "temp_states": frozenset({"failed_greylisted", "greylisted", "timeout", "temp_error", "unknown", "error"}),
}

# Override token from env (matches email_finder, validate_leads)
_api_key = os.getenv("TRUELIST_API_KEY", "").strip()
if _api_key:
    TRUELIST_CONFIG["token"] = _api_key

TRUELIST_STATS: Optional["TruelistStats"] = None
TRUELIST_SESSION = requests.Session()
TRUELIST_SESSION.mount("https://", HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0))
TRUELIST_CACHE: Dict[str, Dict[str, Any]] = {}
TRUELIST_CACHE_LOCK = threading.Lock()


class TruelistRateLimited(RuntimeError):
    def __init__(self, retry_after_s: float) -> None:
        super().__init__(f"Truelist rate limited (retry_after={retry_after_s:.2f}s)")
        self.retry_after_s = retry_after_s


class GlobalRateLimiter:
    """
    Simple global QPS limiter with a shared cooldown window.
    """
    def __init__(self, qps: float) -> None:
        self._lock = threading.Lock()
        self._interval = 1.0 / max(0.001, float(qps))
        self._next_time = 0.0
        self._cooldown_until = 0.0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                wait = max(self._next_time - now, self._cooldown_until - now, 0.0)
                if wait <= 0.0:
                    base = max(self._next_time, now)
                    self._next_time = base + self._interval
                    return
            time.sleep(min(wait, 1.0))

    def cooldown(self, seconds: float) -> None:
        seconds = max(0.0, float(seconds))
        until = time.monotonic() + seconds
        with self._lock:
            if until > self._cooldown_until:
                self._cooldown_until = until


TRUELIST_RATE = GlobalRateLimiter(TRUELIST_CONFIG["qps"])


def _parse_retry_after_seconds(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    v = value.strip()
    try:
        return float(v)
    except Exception:
        return None


class TruelistStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.truelist_wait: List[float] = []
        self.truelist_exec: List[float] = []
        self.truelist_timeouts = 0
        self.truelist_calls = 0
        self.row_time: List[float] = []

    def record_truelist(self, wait_s: float, exec_s: float, timed_out: bool) -> None:
        with self._lock:
            self.truelist_wait.append(wait_s)
            self.truelist_exec.append(exec_s)
            self.truelist_calls += 1
            if timed_out:
                self.truelist_timeouts += 1

    def record_row_time(self, duration_s: float) -> None:
        with self._lock:
            self.row_time.append(duration_s)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "truelist_wait": list(self.truelist_wait),
                "truelist_exec": list(self.truelist_exec),
                "truelist_calls": self.truelist_calls,
                "truelist_timeouts": self.truelist_timeouts,
                "row_time": list(self.row_time),
            }


def normalize_url(url: str) -> str:
    """Normalize URL to include https:// protocol if missing."""
    if not url:
        return ""
    url = url.strip()
    if url.startswith(("http://", "https://")):
        return url
    if "." in url and not url.startswith("/"):
        return f"https://{url}"
    return url


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        domain = parsed.netloc or parsed.path
        if "/" in domain:
            domain = domain.split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.lower().strip() if domain else None
    except Exception:
        return None


def normalize_domain(raw_value: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Normalize a domain or URL into unicode + ASCII (punycode) forms with syntax checks."""
    if not raw_value:
        return None, None, "No domain provided"

    domain = extract_domain_from_url(raw_value) or raw_value
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain or "." not in domain:
        return None, None, "Invalid domain format"

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
        unicode_domain = ascii_domain.encode("ascii").decode("idna").lower()
    except Exception:
        return None, None, "Invalid IDNA domain"

    ext = tldextract.extract(ascii_domain)
    registered = ext.top_domain_under_public_suffix
    if registered:
        ascii_domain = registered
        unicode_domain = registered.encode("ascii").decode("idna").lower()

    if len(ascii_domain) > 253:
        return None, None, "Domain too long"

    labels = ascii_domain.split(".")
    if any(not label for label in labels):
        return None, None, "Invalid domain labels"
    if any(len(label) > 63 for label in labels):
        return None, None, "Domain label too long"
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return None, None, "Domain label has leading/trailing hyphen"
    if any(DOMAIN_LABEL_REGEX.match(label) is None for label in labels):
        return None, None, "Domain label has invalid characters"

    tld = labels[-1]
    if not (DOMAIN_TLD_REGEX.match(tld) or (tld.startswith("xn--") and len(tld) <= 63)):
        return None, None, "Invalid TLD"

    return unicode_domain, ascii_domain, None


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _http_json(
    url: str,
    headers: dict,
    timeout: float,
    proxy: Optional[str] = None,
    json_body: Optional[dict] = None,
    params: Optional[dict] = None,
) -> object:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    TRUELIST_RATE.acquire()
    r = TRUELIST_SESSION.post(
        url,
        headers=headers,
        params=params,
        json=json_body,
        timeout=(5.0, timeout),
        proxies=proxies,
    )
    if r.status_code == 408:
        raise requests.exceptions.Timeout("Truelist 408: request timed out")
    if r.status_code == 422:
        raise RuntimeError(f"Truelist 422: url={r.request.url} body={r.text}")
    if r.status_code == 429:
        ra = _parse_retry_after_seconds(r.headers.get("Retry-After"))
        sleep_s = ra if ra is not None else TRUELIST_CONFIG["rate_limit_fallback_sleep"]
        sleep_s = sleep_s + random.uniform(0.0, 0.5)
        TRUELIST_RATE.cooldown(sleep_s)
        raise TruelistRateLimited(sleep_s)
    r.raise_for_status()
    return r.json() if r.text else None


def _truelist_batch_delete(batch_id: str) -> bool:
    """
    Delete a Truelist batch after results are fetched.
    Truelist docs: DELETE /api/v1/batches/{batch_id} returns 204 on success.
    """
    if not batch_id or not TRUELIST_CONFIG["token"]:
        return False
    headers = {
        "Authorization": ("Bearer " + str(TRUELIST_CONFIG["token"])).strip(),
        "Accept": "application/json",
    }
    try:
        TRUELIST_RATE.acquire()
        r = TRUELIST_SESSION.delete(
            f"{TRUELIST_CONFIG['batch_url']}/{batch_id}",
            headers=headers,
            timeout=(5.0, 10.0),
        )
        if r.status_code == 204:
            logger.debug("Deleted batch %s...", batch_id[:8] if len(batch_id) > 8 else batch_id)
            return True
        logger.warning("Truelist batch delete failed: status %s", r.status_code)
        return False
    except Exception as exc:
        logger.warning("Truelist batch delete error: %s", exc)
        return False


def _fake_emails(domain: str) -> List[str]:
    return [
        f"{secrets.token_hex(8)}@{domain}",
        f"{secrets.token_hex(8)}@{domain}",
        f"{secrets.token_hex(8)}@{domain}",
    ]


def _map_truelist_state(item: object) -> str:
    if not isinstance(item, dict):
        return "temp_error"
    email_state = str(item.get("email_state") or "").strip().lower()
    email_sub_state = str(item.get("email_sub_state") or "").strip().lower()

    if email_sub_state == "failed_greylisted":
        return "temp_error"
    if email_sub_state == "failed_mx_check":
        return "rejected"
    if email_sub_state == "accept_all":
        return "rejected"
    if email_sub_state == "failed_no_mailbox":
        return "rejected"
    if email_sub_state == "is_role":
        return "rejected"

    # Truelist inline API returns email_state="ok" and email_sub_state="email_ok" for valid emails
    if email_sub_state == "email_ok":
        return "accepted"
    if email_state == "ok":
        return "accepted"
    if email_state == "email_ok":
        return "accepted"
    if email_state == "risky":
        return "temp_error"
    if email_state == "email_invalid":
        return "rejected"

    raw = ""
    for key in ("status", "state", "result", "sub_status", "sub_state", "email_status"):
        value = item.get(key)
        if value:
            raw = str(value).strip().lower()
            break
    if not raw:
        return "temp_error"
    if raw in TRUELIST_CONFIG["accepted_states"]:
        return "accepted"
    if raw in TRUELIST_CONFIG["rejected_states"]:
        return "rejected"
    if raw in TRUELIST_CONFIG["temp_states"]:
        return "temp_error"
    return "temp_error"


def _truelist_batch_create(emails: List[str], timeout: float) -> Optional[str]:
    if len(emails) < 2:
        return None
    headers = {
        "Authorization": ("Bearer " + str(TRUELIST_CONFIG["token"])).strip(),
        "Accept": "application/json",
    }
    batch_name = f"batch_{int(time.time() * 1_000_000)}_{uuid.uuid4().hex}.csv"

    def _parse_batch_id(data: Any) -> Optional[str]:
        if isinstance(data, dict):
            bid = (
                data.get("batch_id")
                or data.get("id")
                or data.get("batchId")
                or (data.get("data") or {}).get("id")
                or (data.get("data") or {}).get("batch_id")
                or (data.get("batch") or {}).get("id")
            )
            if bid:
                return str(bid)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0].get("batch_id") or data[0].get("id") or None
        return None

    # Try JSON body first (API v1 batches often expect this)
    TRUELIST_RATE.acquire()
    r = TRUELIST_SESSION.post(
        TRUELIST_CONFIG["batch_url"],
        headers={**headers, "Content-Type": "application/json"},
        json={
            "data": [[email] for email in emails],
            "name": batch_name,
            "validation_strategy": TRUELIST_CONFIG["batch_strategy"],
        },
        timeout=(5.0, timeout),
    )
    if r.status_code == 429:
        ra = _parse_retry_after_seconds(r.headers.get("Retry-After"))
        sleep_s = ra if ra is not None else TRUELIST_CONFIG["rate_limit_fallback_sleep"]
        TRUELIST_RATE.cooldown(sleep_s)
        raise TruelistRateLimited(sleep_s)
    if r.status_code in (422, 415, 400):
        # Fallback: some batch APIs expect form data with CSV
        TRUELIST_RATE.acquire()
        csv_data = "email\n" + "\n".join(emails)
        r2 = TRUELIST_SESSION.post(
            TRUELIST_CONFIG["batch_url"],
            headers=headers,
            data={
                "data": csv_data,
                "name": batch_name,
                "validation_strategy": TRUELIST_CONFIG["batch_strategy"],
            },
            timeout=(5.0, timeout),
        )
        if r2.status_code == 429:
            ra = _parse_retry_after_seconds(r2.headers.get("Retry-After"))
            sleep_s = ra if ra is not None else TRUELIST_CONFIG["rate_limit_fallback_sleep"]
            TRUELIST_RATE.cooldown(sleep_s)
            raise TruelistRateLimited(sleep_s)
        if r2.status_code == 422:
            raise RuntimeError(f"Truelist 422: url={r2.request.url} body={r2.text}")
        r2.raise_for_status()
        data = r2.json() if r2.text else {}
        bid = _parse_batch_id(data)
        if bid:
            return bid
        return None
    r.raise_for_status()
    data = r.json() if r.text else {}
    bid = _parse_batch_id(data)
    if bid:
        return bid
    return None


def _truelist_unwrap_batch_response(raw: Any) -> Optional[Dict[str, Any]]:
    """Extract batch object from API response (may be wrapped in data/batch/list)."""
    if isinstance(raw, dict):
        inner = raw.get("data") or raw.get("batch") or raw.get("result")
        if isinstance(inner, dict):
            return inner
        return raw
    if isinstance(raw, list) and raw and isinstance(raw[0], dict):
        return raw[0]
    return None


def _truelist_batch_poll(
    batch_id: str,
    timeout_s: float,
    interval_s: float,
) -> Dict[str, Any]:
    headers = {
        "Authorization": ("Bearer " + str(TRUELIST_CONFIG["token"])).strip(),
        "Accept": "application/json",
    }
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        TRUELIST_RATE.acquire()
        r = TRUELIST_SESSION.get(
            f"{TRUELIST_CONFIG['batch_url']}/{batch_id}",
            headers=headers,
            timeout=(5.0, min(30.0, timeout_s)),
        )
        if r.status_code == 429:
            ra = _parse_retry_after_seconds(r.headers.get("Retry-After"))
            sleep_s = ra if ra is not None else TRUELIST_CONFIG["rate_limit_fallback_sleep"]
            TRUELIST_RATE.cooldown(sleep_s)
            raise TruelistRateLimited(sleep_s)
        r.raise_for_status()
        data = r.json() if r.text else {}
        batch = _truelist_unwrap_batch_response(data)
        if isinstance(batch, dict):
            state = (
                str(
                    batch.get("batch_state")
                    or batch.get("state")
                    or batch.get("status")
                    or batch.get("batch_status")
                    or batch.get("processing_state")
                    or ""
                )
                .lower()
                .strip()
            )
            processed = int(batch.get("processed_count") or batch.get("processed") or 0)
            total = int(batch.get("email_count") or batch.get("total") or batch.get("count") or 0)
            completed_states = ("completed", "complete", "done", "finished", "ready", "processed", "success", "ok")
            if state in completed_states:
                return batch
            if total > 0 and processed >= total:
                return batch
            if state in {"failed", "error"}:
                raise RuntimeError(
                    f"Truelist batch failed: {batch.get('message') or batch.get('error') or state}"
                )
        time.sleep(interval_s)
    raise TimeoutError("Truelist batch timed out")


def _truelist_fetch_batch_results(batch_id: str, timeout: float) -> List[dict]:
    """
    Fetch batch validation results via GET /api/v1/email_addresses (Truelist docs).
    Paginates with page/per_page (max 100 per page) until no more results.
    """
    url = TRUELIST_CONFIG.get("email_addresses_url") or (
        TRUELIST_CONFIG["batch_url"].rsplit("/", 1)[0] + "/email_addresses"
    )
    headers = {
        "Authorization": ("Bearer " + str(TRUELIST_CONFIG["token"])).strip(),
        "Accept": "application/json",
    }
    per_page = 100
    page = 1
    all_items: List[dict] = []
    while True:
        TRUELIST_RATE.acquire()
        r = TRUELIST_SESSION.get(
            url,
            params={"batch_uuid": batch_id, "page": page, "per_page": per_page},
            headers=headers,
            timeout=(5.0, min(60.0, timeout)),
        )
        if r.status_code == 429:
            ra = _parse_retry_after_seconds(r.headers.get("Retry-After"))
            sleep_s = ra if ra is not None else TRUELIST_CONFIG["rate_limit_fallback_sleep"]
            TRUELIST_RATE.cooldown(sleep_s)
            raise TruelistRateLimited(sleep_s)
        r.raise_for_status()
        data = r.json() if r.text else {}
        logger.debug(
            "Truelist email_addresses response keys: %s",
            list(data.keys()) if isinstance(data, dict) else "not a dict",
        )
        logger.debug("Truelist email_addresses response sample: %s", (r.text or "")[:1000])
        items = (
            data.get("data")
            or data.get("emails")
            or data.get("email_addresses")
            or data.get("results")
            or data.get("items")
            or data.get("list")
            or (data if isinstance(data, list) else [])
        )
        if not isinstance(items, list):
            items = []
        for item in items:
            if isinstance(item, dict):
                normalized = _normalize_truelist_item(item)
                all_items.append(normalized)
        if len(items) < per_page:
            break
        page += 1
    return all_items


def _normalize_truelist_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure item has canonical keys email, email_state, email_sub_state for downstream."""
    out = dict(item)
    email = _truelist_extract_email(item)
    if email:
        out["email"] = email
    for dst, keys in (
        ("email_state", ("Email State", "email_state", "emailState", "state", "State", "status", "Status", "verification_status", "result")),
        ("email_sub_state", ("Email Sub-State", "Email Sub State", "email_sub_state", "emailSubState", "sub_state", "sub_status")),
    ):
        if out.get(dst):
            continue
        for k in keys:
            v = item.get(k)
            if v is not None and str(v).strip():
                out[dst] = str(v).strip()
                break
    return out


def _truelist_parse_batch_csv(csv_text: str) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        if not isinstance(row, dict):
            continue
        email = (
            row.get("Email Address")
            or row.get("email")
            or row.get("email_address")
            or row.get("Email")
            or row.get("emailAddress")
        )
        if not email:
            continue
        email = str(email).strip().lower()
        if "@" not in email:
            continue
        email_sub_state = (
            row.get("Email Sub-State")
            or row.get("Email Sub State")
            or row.get("email_sub_state")
            or row.get("emailSubState")
            or row.get("sub_status")
            or row.get("Status")
            or row.get("status")
            or row.get("result")
            or row.get("verification_status")
        )
        email_state = (
            row.get("Email State")
            or row.get("email_state")
            or row.get("emailState")
            or row.get("State")
            or row.get("state")
            or row.get("Status")
            or row.get("status")
        )
        results[email] = _normalize_truelist_item({
            "email": email,
            "email_sub_state": email_sub_state,
            "email_state": email_state,
            **row,
        })
    return results


def _truelist_extract_email(item: Dict[str, Any]) -> Optional[str]:
    for key in ("email", "address", "email_address", "Email Address", "Email", "emailAddress"):
        value = item.get(key)
        if value:
            email = str(value).strip().lower()
            if "@" in email:
                return email
    return None


def _truelist_batch_results(
    emails: List[str],
    timeout: float,
) -> List[dict]:
    batch_id = _truelist_batch_create(emails, timeout)
    if not batch_id:
        return []
    batch_info = _truelist_batch_poll(
        batch_id,
        timeout_s=TRUELIST_CONFIG["batch_timeout"],
        interval_s=TRUELIST_CONFIG["batch_poll_interval"],
    )

    results_map: Dict[str, Dict[str, Any]] = {}

    # Truelist API: results are fetched from GET /api/v1/email_addresses (not inline in batch status)
    try:
        fetched = _truelist_fetch_batch_results(batch_id, timeout)
        for item in fetched:
            email = item.get("email") or _truelist_extract_email(item)
            if email:
                results_map[email.strip().lower()] = dict(item)
    except Exception as exc:
        logger.warning("Truelist email_addresses fetch failed: %s", exc)

    if isinstance(batch_info, dict) and not results_map:
        results = (
            batch_info.get("results")
            or batch_info.get("data")
            or batch_info.get("emails")
            or batch_info.get("verifications")
            or batch_info.get("batch_results")
            or batch_info.get("items")
        )
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                normalized = _normalize_truelist_item(item)
                email = normalized.get("email") or _truelist_extract_email(item)
                if email:
                    results_map[email.strip().lower()] = normalized

        if not results_map:
            download_url = (
                batch_info.get("annotated_csv_url")
                or batch_info.get("annotatedCsvUrl")
                or batch_info.get("download_url")
                or batch_info.get("file_url")
                or batch_info.get("downloadUrl")
                or batch_info.get("safest_bet_csv_url")
                or batch_info.get("highest_reach_csv_url")
                or batch_info.get("result_url")
                or batch_info.get("csv_url")
                or batch_info.get("output_url")
                or batch_info.get("result_file_url")
                or batch_info.get("annotated_file_url")
                or batch_info.get("resultUrl")
                or batch_info.get("outputUrl")
                or batch_info.get("csv_download_url")
            )
            if download_url:
                TRUELIST_RATE.acquire()
                r = TRUELIST_SESSION.get(download_url, timeout=(5.0, min(120.0, timeout)))
                r.raise_for_status()
                csv_results = _truelist_parse_batch_csv(r.text)
                results_map.update(csv_results)

    ordered_results: List[dict] = []
    for email in emails:
        key = email.strip().lower()
        item = results_map.get(key)
        if item:
            ordered_results.append(item)
        else:
            ordered_results.append({})

    # Delete batch after fetching results (Truelist docs: free up storage, clear duplicate detection)
    _truelist_batch_delete(batch_id)

    return ordered_results


def _truelist_bulk_domain_check(domains: List[str]) -> Dict[str, Dict[str, Any]]:
    if not domains or not TRUELIST_CONFIG["token"]:
        return {}

    email_to_domain: Dict[str, str] = {}
    emails: List[str] = []
    for domain in domains:
        domain = domain.strip().lower()
        if not domain:
            continue
        fake = _fake_emails(domain)
        for email in fake:
            email_to_domain[email] = domain
            emails.append(email)

    if len(emails) < 2:
        return {}

    results = truelist_check(emails, TRUELIST_CONFIG["timeout"])
    per_domain: Dict[str, List[dict]] = {d: [] for d in domains}
    for result in results:
        if not isinstance(result, dict):
            continue
        email = _truelist_extract_email(result)
        if not email:
            continue
        domain = email_to_domain.get(email)
        if domain:
            per_domain[domain].append(result)

    out: Dict[str, Dict[str, Any]] = {}
    for domain in domains:
        items = per_domain.get(domain, [])
        details = _truelist_details_from_results(items, 3)
        out[domain] = details
        with TRUELIST_CACHE_LOCK:
            TRUELIST_CACHE[domain] = dict(details)
    return out


def truelist_check(emails: List[str], timeout: float) -> List[dict]:
    if not emails or not TRUELIST_CONFIG["token"]:
        return []
    if TRUELIST_CONFIG["use_batch"] and len(emails) >= 2:
        try:
            batch_results = _truelist_batch_results(emails, timeout)
            if batch_results:
                return batch_results
        except TruelistRateLimited:
            raise
        except Exception as exc:
            logger.warning("Truelist batch failed, falling back to inline: %s", exc)

    headers = {
        "Authorization": ("Bearer " + str(TRUELIST_CONFIG["token"])).strip(),
        "Accept": "application/json",
    }
    results: List[dict] = []
    for email in emails:
        if not email or "@" not in email:
            continue
        payload = {"email": email}
        result = _http_json(
            TRUELIST_CONFIG["verify_url"],
            headers=headers,
            timeout=timeout,
            proxy=None,
            json_body=payload,
        )
        if isinstance(result, dict):
            items = result.get("emails")
            if isinstance(items, list) and items:
                first = items[0]
                if isinstance(first, dict):
                    results.append(first)
                    continue
            if any(key in result for key in ("email_sub_state", "email_state", "status")):
                results.append(result)
    return results


def _truelist_details_from_results(results: List[dict], expected_count: int) -> Dict[str, Any]:
    details = dict(TRUELIST_CONFIG["details_default"])
    details["truelist_checked"] = True
    sub_states = [
        str(item.get("email_sub_state") or "").strip().lower()
        for item in results
        if isinstance(item, dict)
    ]
    all_failed_no_mailbox = bool(results) and all(state == "failed_no_mailbox" for state in sub_states)
    all_email_ok = bool(results) and all(state == "email_ok" for state in sub_states)
    any_accept_all = any(state == "accept_all" for state in sub_states)
    any_failed_mx_check = any(state == "failed_mx_check" for state in sub_states)
    any_unknown = any(state == "unknown" for state in sub_states)

    mapped = [_map_truelist_state(item) for item in results]
    if not results:
        mapped = []
    elif len(mapped) < expected_count:
        mapped.extend(["temp_error"] * (expected_count - len(mapped)))

    accepted_count = sum(1 for state in mapped if state == "accepted")
    rejected_count = sum(1 for state in mapped if state == "rejected")
    temp_count = sum(1 for state in mapped if state == "temp_error")
    total = accepted_count + rejected_count + temp_count

    if total == 0:
        status = "unknown"
    elif any_unknown or temp_count >= 1:
        status = "unknown"
    elif all_email_ok:
        status = "ok"
    elif all_failed_no_mailbox:
        status = "ok"
    elif accepted_count == total:
        status = "catch_all"
    elif rejected_count == total:
        status = "invalid"
    elif temp_count == total:
        status = "greylisted"
    elif accepted_count >= 1 and rejected_count >= 1:
        status = "ok"
    else:
        status = "unknown"

    if any_accept_all or status == "catch_all":
        status = "invalid"
    if any_failed_mx_check:
        status = "invalid"

    reason = None
    if status == "invalid":
        if any_failed_mx_check:
            reason = "failed_mx_check"
        elif any_accept_all:
            reason = "accept_all"
        elif any(state == "failed_no_mailbox" for state in sub_states):
            reason = "failed_no_mailbox"
        elif any(state == "is_role" for state in sub_states):
            reason = "is_role"
        elif any(state == "failed_greylisted" for state in sub_states):
            reason = "failed_greylisted"
        else:
            email_states = [
                str(item.get("email_state") or "").strip().lower()
                for item in results
                if isinstance(item, dict)
            ]
            if any(state == "email_invalid" for state in email_states):
                reason = "email_invalid"
            else:
                reason = "invalid"

    details.update(
        {
            "truelist_domain_status": status,
            "accept_all": any_accept_all,
            "greylisted": status == "greylisted",
            "is_real_ok_domain": status == "ok",
            "truelist_reason": reason,
        }
    )
    return details


def truelist_domain_check(domain: str) -> Dict[str, Any]:
    with TRUELIST_CACHE_LOCK:
        cached = TRUELIST_CACHE.get(domain)
    if cached:
        return dict(cached)

    details = dict(TRUELIST_CONFIG["details_default"])
    if not TRUELIST_CONFIG["token"]:
        return details

    emails = _fake_emails(domain)
    last_exc: Optional[Exception] = None
    last_was_timeout = False

    for attempt in range(TRUELIST_CONFIG["max_retries"] + 1):
        attempt_timeout = min(TRUELIST_CONFIG["timeout"] * (attempt + 1), TRUELIST_CONFIG["timeout_max"])

        t0 = time.perf_counter()
        t1 = t0
        t2 = t0

        try:
            t1 = time.perf_counter()
            results = truelist_check(emails, attempt_timeout)
            t2 = time.perf_counter()

            if TRUELIST_STATS:
                TRUELIST_STATS.record_truelist(t1 - t0, t2 - t1, timed_out=False)

            out = _truelist_details_from_results(results, len(emails))
            with TRUELIST_CACHE_LOCK:
                TRUELIST_CACHE[domain] = dict(out)
            return out

        except TruelistRateLimited as exc:
            last_exc = exc
            last_was_timeout = False
            t2 = time.perf_counter()
            if TRUELIST_STATS:
                TRUELIST_STATS.record_truelist(t1 - t0, t2 - t1, timed_out=False)
            if attempt < TRUELIST_CONFIG["max_retries"]:
                continue
            break

        except Exception as exc:
            last_exc = exc
            t2 = time.perf_counter()

            is_timeout = isinstance(
                exc,
                (TimeoutError, socket.timeout, requests.exceptions.Timeout),
            ) or ("timed out" in str(exc).lower())
            is_conn = isinstance(exc, requests.exceptions.ConnectionError)

            if TRUELIST_STATS:
                TRUELIST_STATS.record_truelist(t1 - t0, t2 - t1, timed_out=is_timeout)

            last_was_timeout = bool(is_timeout)

            if (is_timeout or is_conn) and attempt < TRUELIST_CONFIG["max_retries"]:
                backoff = TRUELIST_CONFIG["retry_backoff_base"] * (2 ** attempt) + random.uniform(0.0, 0.4)
                time.sleep(min(backoff, 6.0))
                continue

            break

    out = dict(details)
    out["truelist_checked"] = True
    if isinstance(last_exc, TruelistRateLimited):
        out["truelist_reason"] = "rate_limited"
    elif last_was_timeout:
        out["truelist_reason"] = "timeout"
    else:
        out["truelist_reason"] = "truelist_error"

    with TRUELIST_CACHE_LOCK:
        TRUELIST_CACHE[domain] = dict(out)
    return out


def _finalize_truelist(validation_details: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    truelist_status = validation_details.get("truelist_domain_status")
    truelist_reason = validation_details.get("truelist_reason")
    if truelist_status == "unknown":
        validation_details["valid"] = None
        validation_details["error"] = "Truelist unknown"
        return "unknown", validation_details
    if truelist_status != "ok":
        validation_details["valid"] = False
        if truelist_reason:
            validation_details["error"] = f"Truelist reject: {truelist_reason}"
        else:
            validation_details["error"] = f"Truelist reject: {truelist_status}"
        return "invalid", validation_details

    validation_details["valid"] = True
    return "valid", validation_details


def validate_stage1(
    lead: Dict,
    do_truelist: bool = True,
    truelist_bulk: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[str, Dict]:
    """
    Truelist batch-only validation: normalize domain, then look up result from
    the pre-fetched bulk batch. No per-domain API calls.

    Returns:
        (status, validation_details)
    """
    validation_details = {
        "valid": None,
        "error": None,
        "normalized_domain": None,
        "ascii_domain": None,
        "truelist_domain_status": "unknown",
        "accept_all": False,
        "greylisted": False,
        "truelist_checked": False,
        "is_real_ok_domain": False,
    }

    website = lead.get("website", "").strip()
    lead_index = lead.get("_index", -1)

    normalized_domain, ascii_domain, error = normalize_domain(website)
    if error:
        validation_details["valid"] = False
        validation_details["error"] = error
        logger.warning("Stage 1 failed for %s (index %s): %s", website, lead_index, error)
        return "invalid", validation_details

    validation_details["normalized_domain"] = normalized_domain
    validation_details["ascii_domain"] = ascii_domain

    if not do_truelist:
        validation_details["valid"] = True
        return "valid", validation_details

    if truelist_bulk and ascii_domain in truelist_bulk:
        validation_details.update(truelist_bulk[ascii_domain])

    return _finalize_truelist(validation_details)


# CSV-based domain classification ------------------------------------------------

def derive_output_paths(csv_path: Path) -> Path:
    base = csv_path.stem
    parent = csv_path.parent
    return parent / f"{base}_domain_valid.csv"


def _percentile(values: List[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def _format_stats(stats: Dict[str, Any]) -> str:
    wait = stats.get("truelist_wait", [])
    exec_time = stats.get("truelist_exec", [])
    row_time = stats.get("row_time", [])
    calls = stats.get("truelist_calls", 0)
    timeouts = stats.get("truelist_timeouts", 0)

    wait_p50 = _percentile(wait, 0.5)
    wait_p95 = _percentile(wait, 0.95)
    exec_p50 = _percentile(exec_time, 0.5)
    exec_p95 = _percentile(exec_time, 0.95)
    row_p50 = _percentile(row_time, 0.5)
    row_p95 = _percentile(row_time, 0.95)
    timeout_rate = (timeouts / calls) if calls else 0.0

    def _fmt(value: Optional[float]) -> str:
        return f"{value:.3f}s" if value is not None else "n/a"

    return (
        "Truelist stats | "
        f"wait p50/p95={_fmt(wait_p50)}/{_fmt(wait_p95)} "
        f"exec p50/p95={_fmt(exec_p50)}/{_fmt(exec_p95)} "
        f"timeout_rate={timeout_rate:.1%} "
        f"row p50/p95={_fmt(row_p50)}/{_fmt(row_p95)} "
        f"(calls={calls})"
    )


def _open_append_writer(path: Path, fieldnames: List[str]) -> Tuple[Any, csv.DictWriter]:
    exists = path.exists() and path.stat().st_size > 0
    fh = path.open("a", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    if not exists:
        writer.writeheader()
    return fh, writer


def _open_csv_reader(path: Path, encoding: str = "utf-8") -> Tuple[Any, csv.DictReader]:
    """Open a CSV with the given encoding."""
    fh = path.open(newline="", encoding=encoding)
    return fh, csv.DictReader(fh)


def _count_csv_data_rows(path: Path) -> int:
    """Return the number of data rows (excluding header). Tries utf-8 then cp1252."""
    if not path.exists():
        return 0
    for enc in ("utf-8", "cp1252"):
        try:
            fh, reader = _open_csv_reader(path, enc)
            with fh:
                return sum(1 for _ in reader)
        except UnicodeDecodeError:
            continue
    return 0


def _byte_offset_to_line(path: Path, offset: int) -> int:
    try:
        data = path.read_bytes()
    except Exception:
        return -1
    if offset < 0:
        return -1
    if offset > len(data):
        offset = len(data)
    return data[:offset].count(b"\n") + 1


def _has_multilevel_path(website_value: str) -> bool:
    """True if URL has 2+ levels (domain + at least one path segment), e.g. domain.com/foo or domain.com/foo/bar."""
    s = (website_value or "").strip().lower()
    if not s:
        return False
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    if "/" not in s:
        return False
    _host, path = s.split("/", 1)
    return bool(path.strip())


def classify_csv_by_domain(
    csv_path: Path,
    website_column: str = "website",
    valid_out: Optional[Path] = None,
    batch_size: int = 1000,
    skip_rewrite: bool = False,
    strict_unknown: bool = False,
) -> Tuple[Path, int, int, int, int]:
    """
    Process the first `batch_size` data rows from a CSV, append domain validation
    results to the valid output CSV and append unknown rows back to the source CSV.
    Optionally rewrite the source CSV without those processed rows (default),
    or skip rewriting for speed.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {csv_path}")

    valid_path = derive_output_paths(csv_path)
    if valid_out:
        valid_path = valid_out

    tmp_path = csv_path.with_suffix(csv_path.suffix + ".tmp")

    processed_rows: List[Dict[str, str]] = []
    processed_count = 0
    valid_count = 0
    unknown_count = 0
    truelist_bulk: Optional[Dict[str, Dict[str, Any]]] = None

    # First pass: grab the batch quickly (no rewriting yet); try utf-8 then cp1252
    used_encoding = "utf-8"
    rows_consumed = 0
    for enc in ("utf-8", "cp1252"):
        processed_rows = []
        processed_count = 0
        try:
            src_fh, reader = _open_csv_reader(csv_path, enc)
            with src_fh:
                if reader.fieldnames is None:
                    raise ValueError("CSV is missing a header row.")
                raw_fieldnames = list(reader.fieldnames)
                if website_column not in raw_fieldnames:
                    raise ValueError(f"Column '{website_column}' not found in CSV header.")
                # Sanitize so DictWriter never sees None (empty CSV headers become _unnamed)
                input_fieldnames = [f if f is not None else "_unnamed" for f in raw_fieldnames]
                fieldname_pairs = list(zip(input_fieldnames, raw_fieldnames))

                rows_consumed = 0
                for idx, row in enumerate(reader, start=1):
                    if rows_consumed >= batch_size:
                        break
                    rows_consumed += 1
                    website_value = (row.get(website_column) or "").strip()
                    if _has_multilevel_path(website_value):
                        continue
                    row["_batch_index"] = idx  # keep original position
                    processed_rows.append(row)
                    processed_count += 1
            used_encoding = enc
            if enc == "cp1252":
                logger.warning("CSV %s is not UTF-8; used cp1252.", csv_path)
            break
        except UnicodeDecodeError as exc:
            line = _byte_offset_to_line(csv_path, exc.start)
            if enc == "cp1252":
                logger.error("CSV decode error at byte %s (line %s): %s", exc.start, line, exc)
                raise
            logger.warning("CSV is not UTF-8 (error at line %s); retrying with cp1252.", line)

    if not processed_rows:
        return valid_path, 0, 0, 0, rows_consumed

    last_bulk_exc: Optional[Exception] = None
    if TRUELIST_CONFIG["use_batch"] and TRUELIST_CONFIG["token"]:
        domains = []
        seen = set()
        for row in processed_rows:
            website_value = (row.get(website_column) or "").strip()
            _, ascii_domain, err = normalize_domain(website_value)
            if not err and ascii_domain and ascii_domain not in seen:
                seen.add(ascii_domain)
                domains.append(ascii_domain)
        if len(domains) >= 1:
            try:
                truelist_bulk = _truelist_bulk_domain_check(domains)
            except Exception as exc:
                last_bulk_exc = exc
                logger.warning("Truelist bulk batch failed: %s", exc)
        if len(domains) >= 1 and (truelist_bulk is None or len(truelist_bulk) == 0):
            if last_bulk_exc is not None:
                raise last_bulk_exc from last_bulk_exc
            raise RuntimeError(
                "Truelist bulk check returned no results; cannot classify domains. Check API response or run with --log-level DEBUG."
            ) from None

    def _process_row(row: Dict[str, str]) -> Tuple[str, Dict[str, str], str, str, Optional[str]]:
        row_start = time.perf_counter()
        website_value = (row.get(website_column) or "").strip()
        lead = {"website": website_value, "_index": row.get("_batch_index", -1)}
        try:
            status, details = validate_stage1(
                lead,
                do_truelist=True,
                truelist_bulk=truelist_bulk,
            )
            if strict_unknown and status == "unknown":
                status = "invalid"
        except Exception as exc:
            status = "unknown"
            details = {}
            if strict_unknown:
                status = "invalid"
        row.pop("_batch_index", None)
        truelist_status = str(details.get("truelist_domain_status") or "unknown")
        truelist_reason = details.get("truelist_reason")
        if TRUELIST_STATS:
            TRUELIST_STATS.record_row_time(time.perf_counter() - row_start)
        return status, row, website_value, truelist_status, truelist_reason

    domain_only_fieldnames = [website_column]
    v_fh, valid_writer = _open_append_writer(valid_path, domain_only_fieldnames)
    truelist_status_counts: Dict[str, int] = {}
    unknown_rows: List[Dict[str, str]] = []
    previous_stats = TRUELIST_STATS
    stats_snapshot = None
    globals()["TRUELIST_STATS"] = TruelistStats()
    try:
        for idx, row in enumerate(processed_rows, start=1):
            status, row, website_value, truelist_status, _ = _process_row(row)
            output_row = {safe: row.get(orig, "") for safe, orig in fieldname_pairs}
            truelist_status_counts[truelist_status] = truelist_status_counts.get(truelist_status, 0) + 1
            if status == "valid":
                valid_writer.writerow({website_column: website_value})
                valid_count += 1
            elif status == "unknown":
                unknown_count += 1
                unknown_rows.append(output_row)
            if idx % 50 == 0:
                print(f"Progress: {idx}/{processed_count} | valid={valid_count} unknown={unknown_count}")
    finally:
        v_fh.close()
        stats_snapshot = TRUELIST_STATS.snapshot() if TRUELIST_STATS else None
        globals()["TRUELIST_STATS"] = previous_stats

    if not skip_rewrite:
        # Second pass: rewrite the remaining rows (skip the processed ones); retry with cp1252 if decode fails
        for rewrite_enc in (used_encoding, "cp1252"):
            try:
                src_fh, reader = _open_csv_reader(csv_path, rewrite_enc)
                with src_fh, tmp_path.open("w", newline="", encoding="utf-8") as tmp_file:
                    tmp_writer = csv.DictWriter(tmp_file, fieldnames=input_fieldnames)
                    tmp_writer.writeheader()
                    for idx, row in enumerate(reader, start=1):
                        if idx <= rows_consumed:
                            continue
                        row_safe = {safe: row.get(orig, "") for safe, orig in fieldname_pairs}
                        tmp_writer.writerow(row_safe)
                tmp_path.replace(csv_path)
                if rewrite_enc == "cp1252":
                    logger.warning("Rewrite used cp1252 (source has non-UTF-8 bytes after first batch).")
                break
            except UnicodeDecodeError as exc:
                if rewrite_enc == "cp1252":
                    line = _byte_offset_to_line(csv_path, exc.start)
                    logger.error("CSV decode error at byte %s (line %s): %s", exc.start, line, exc)
                    raise
                logger.warning("Rewrite failed with %s, retrying with cp1252.", used_encoding)

    if unknown_rows and not skip_rewrite:
        exists = csv_path.exists() and csv_path.stat().st_size > 0
        with csv_path.open("a", newline="", encoding="utf-8") as out_fh:
            writer = csv.DictWriter(out_fh, fieldnames=input_fieldnames)
            if not exists:
                writer.writeheader()
            for row in unknown_rows:
                writer.writerow(row)

    if skip_rewrite:
        logger.info(
            "Domain batch complete for %s: %d processed (%d valid, %d unknown); source CSV left untouched (skip_rewrite=True).",
            csv_path,
            processed_count,
            valid_count,
            unknown_count,
        )
    else:
        logger.info(
            "Domain batch complete for %s: %d processed (%d valid, %d unknown); remaining rows: rewrote source without processed batch.",
            csv_path,
            processed_count,
            valid_count,
            unknown_count,
        )
    if truelist_status_counts:
        status_summary = ", ".join(f"{key}={count}" for key, count in sorted(truelist_status_counts.items()))
        print(f"Truelist status summary: {status_summary}")
    if stats_snapshot:
        print(_format_stats(stats_snapshot))
    return valid_path, processed_count, valid_count, unknown_count, rows_consumed


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split a CSV into domain-valid and domain-unknown rows.")
    parser.add_argument("csv_path", type=Path, default="test.csv", help="Path to the input CSV file.")
    parser.add_argument("--website-column", default="website", help="Column name containing website URLs.")
    parser.add_argument("--valid-out", type=Path, help="Optional explicit path for the valid rows CSV.")
    parser.add_argument("--batch-size", type=int, default=1000, help="Number of data rows to process per run (default: 1000).")
    parser.add_argument("--until-rows-less-than", type=int, default=1000, metavar="N", help="Keep running batches until source CSV has fewer than N data rows.")
    parser.add_argument("--batch-delay", type=float, default=5.0, help="Seconds to wait between batch runs when using --until-rows-less-than (default: 5).")
    parser.add_argument("--once", action="store_true", help="Process one batch only, then exit.")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR).")
    parser.add_argument("--skip-rewrite", action="store_true", help="Skip rewriting the source CSV after processing the batch (faster; leaves source intact).")
    parser.add_argument("--strict", action="store_true", help="Treat unknown results as invalid.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s:%(name)s:%(message)s",
    )

    if args.once:
        single_start = time.perf_counter()
        try:
            valid_path, processed, valid_count, unknown_count, rows_consumed = classify_csv_by_domain(
                args.csv_path,
                website_column=args.website_column,
                valid_out=args.valid_out,
                batch_size=args.batch_size,
                skip_rewrite=args.skip_rewrite,
                strict_unknown=args.strict,
            )
        except Exception as exc:
            logger.error("Failed to classify CSV: %s", exc)
            print(f"Error: {exc}")
            return 1
        single_elapsed = time.perf_counter() - single_start
        print(f"Completed in {single_elapsed:.1f}s")
        print(f"Processed {processed} row(s).")
        if rows_consumed > processed:
            print(f"Skipped {rows_consumed - processed} row(s) with multilevel path (e.g. domain.com/foo).")
        print(f"Appended domain-valid rows to: {valid_path} ({valid_count})")
        print(f"Appended domain-unknown rows to source CSV ({unknown_count})")
        if args.skip_rewrite:
            print("Source CSV updated: no (skip_rewrite enabled).")
        else:
            print(f"Source CSV updated: first {rows_consumed} row(s) removed.")
        return 0

    if args.until_rows_less_than is not None:
        if args.skip_rewrite:
            logger.warning("--until-rows-less-than requires rewriting the source CSV; ignoring --skip-rewrite.")
            args.skip_rewrite = False
        batch_num = 0
        while True:
            remaining = _count_csv_data_rows(args.csv_path)
            if remaining < args.until_rows_less_than:
                print(f"Source CSV has {remaining} row(s) (< {args.until_rows_less_than}). Stopping.")
                break
            batch_num += 1
            print(f"--- Batch {batch_num} (source has {remaining} row(s)) ---")
            batch_start = time.perf_counter()
            try:
                valid_path, processed, valid_count, unknown_count, rows_consumed = classify_csv_by_domain(
                    args.csv_path,
                    website_column=args.website_column,
                    valid_out=args.valid_out,
                    batch_size=args.batch_size,
                    skip_rewrite=args.skip_rewrite,
                    strict_unknown=args.strict,
                )
            except Exception as exc:
                logger.error("Failed to classify CSV: %s", exc)
                print(f"Error: {exc}")
                return 1
            batch_elapsed = time.perf_counter() - batch_start
            print(f"Batch {batch_num} completed in {batch_elapsed:.1f}s")
            print(f"Processed {processed} row(s).")
            if rows_consumed > processed:
                print(f"Skipped {rows_consumed - processed} row(s) with multilevel path (e.g. domain.com/foo).")
            print(f"Appended domain-valid rows to: {valid_path} ({valid_count})")
            print(f"Appended domain-unknown rows to source CSV ({unknown_count})")
            print(f"Source CSV updated: first {rows_consumed} row(s) removed.")
            if _count_csv_data_rows(args.csv_path) >= args.until_rows_less_than:
                time.sleep(args.batch_delay)
        return 0

    single_start = time.perf_counter()
    try:
        valid_path, processed, valid_count, unknown_count, rows_consumed = classify_csv_by_domain(
            args.csv_path,
            website_column=args.website_column,
            valid_out=args.valid_out,
            batch_size=args.batch_size,
            skip_rewrite=args.skip_rewrite,
            strict_unknown=args.strict,
        )
    except Exception as exc:
        logger.error("Failed to classify CSV: %s", exc)
        print(f"Error: {exc}")
        return 1
    single_elapsed = time.perf_counter() - single_start

    print(f"Completed in {single_elapsed:.1f}s")
    print(f"Processed {processed} row(s).")
    if rows_consumed > processed:
        print(f"Skipped {rows_consumed - processed} row(s) with multilevel path (e.g. domain.com/foo).")
    print(f"Appended domain-valid rows to: {valid_path} ({valid_count})")
    print(f"Appended domain-unknown rows to source CSV ({unknown_count})")

    if args.skip_rewrite:
        print("Source CSV updated: no (skip_rewrite enabled).")
    else:
        print(f"Source CSV updated: first {rows_consumed} row(s) removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
