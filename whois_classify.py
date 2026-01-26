"""
Stage 1: DNS Layer Validation

Performs DNS-related validation checks:
- Domain age check (WHOIS, must be >= 7 days old) - HARD
- MX record check (email domain must have mail server) - HARD
- SPF/DMARC check (DNS TXT records) - SOFT (always passes, appends data)
"""

import argparse
import asyncio
import csv
import json
import io
import logging
import re
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse
import contextlib
import urllib.request
import urllib.error

try:
    import dns.resolver  # type: ignore
    import dns  # type: ignore
except ImportError:
    dns = None  # type: ignore

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
MAX_REP_SCORE = 38  # Wayback (6) + SEC (12) + WHOIS/DNSBL (10) + GDELT (10) = 38


class LRUCache:
    """LRU Cache implementation with TTL support using OrderedDict for O(1) operations."""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: OrderedDict[str, Tuple[Any, datetime]] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key in self.cache:
            self.cache.move_to_end(key)
            return True
        return False

    def __getitem__(self, key: str) -> Any:
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key][0]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        elif len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
        self.cache[key] = (value, datetime.now())

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def is_expired(self, key: str, ttl_hours: int) -> bool:
        if key not in self.cache:
            return True
        _, timestamp = self.cache[key]
        age = datetime.now() - timestamp
        return age.total_seconds() > (ttl_hours * 3600)


validation_cache = LRUCache(max_size=1000)
CACHE_TTLS = {"whois": 90, "dns_head": 24, "myemailverifier": 90, "dnsbl": 24}

DNS_RESOLVER = dns.resolver.Resolver() if dns else None  # type: ignore[union-attr]
if DNS_RESOLVER:
    DNS_RESOLVER.timeout = 1
    DNS_RESOLVER.lifetime = 1

WHOIS_SEMAPHORE = threading.Semaphore(20)  # allow more concurrent WHOIS lookups
WHOIS_DELAY = 0.0  # optional fixed delay between WHOIS requests (seconds)
WHOIS_TIMEOUT = 1
WHOIS_RETRIES = 2
WHOIS_RETRY_DELAY = 0.25
WHOIS_MIN_INTERVAL = 0.25  # global minimum spacing between WHOIS calls (seconds)
_WHOIS_RATE_LOCK = threading.Lock()
_WHOIS_LAST_CALL = 0.0
RDAP_TIMEOUT = 2.0
WHOIS_EXECUTOR = ThreadPoolExecutor(max_workers=20)  # reuse threads for WHOIS lookups

MYEMAILVERIFIER_SEMAPHORE = asyncio.Semaphore(1)
MYEMAILVERIFIER_DELAY = 0.5

REQUIRED_FIELDS = {
    "email": "Contact email address",
    "full_name": "Full name of the contact (or use first + last)",
    "first": "First name",
    "last": "Last name",
    "business": "Company/business name",
    "website": "Company website URL",
    "industry": "Primary industry category",
    "sub_industry": "Sub-industry or niche",
    "role": "Job title/role",
    "region": "Geographic location/region (or use country/state/city)",
    "country": "Country (required if region not provided)",
    "state": "State/Province (required for US if region not provided)",
    "city": "City (required if region not provided)",
    "linkedin": "LinkedIn profile URL",
    "source_url": "URL where this lead was found",
    "source_type": "Type of source",
}

OPTIONAL_FIELDS = {
    "description": "Company description",
    "phone_numbers": "List of phone numbers",
    "founded_year": "Year company was founded",
    "ownership_type": "Type of ownership",
    "company_type": "Type of company",
    "number_of_locations": "Number of locations",
    "socials": "Dictionary of social media profiles",
}

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "spam.dnsbl.anonmails.de",
]

RESTRICTED_SOURCES = [
    "zoominfo.com",
    "apollo.io",
    "people-data-labs.com",
    "peopledatalabs.com",
    "rocketreach.co",
    "hunter.io",
    "snov.io",
    "lusha.com",
    "clearbit.com",
    "leadiq.com",
]


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


def validate_linkedin_url(url: str) -> bool:
    """Validate LinkedIn URL format."""
    if not url:
        return False
    url = normalize_url(url)
    return "linkedin.com" in url.lower()


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


def extract_root_domain(website: str) -> str:
    """Extract the root domain from a website URL, removing www. prefix."""
    if not website:
        return ""
    normalized = normalize_url(website)
    domain = urlparse(normalized).netloc or normalized
    if "/" in domain:
        domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _parse_rdap_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Handle "Z" suffix for UTC
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except Exception:
        return None


def rdap_domain_age(domain: str) -> Tuple[str, str]:
    """Fallback to RDAP to determine domain age."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "whois-classify/1.0"})
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
            if resp.status >= 400:
                return "unknown", f"RDAP HTTP {resp.status}"
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "invalid", "Domain not found in RDAP"
        return "unknown", f"RDAP HTTP {e.code}"
    except Exception as e:
        return "unknown", f"RDAP lookup failed: {str(e)}"

    events = data.get("events") or []
    created_at: Optional[datetime] = None
    for event in events:
        action = (event.get("eventAction") or "").lower()
        if action in {"registration", "registered", "created"}:
            created_at = _parse_rdap_datetime(event.get("eventDate", ""))
            if created_at:
                break
    if not created_at:
        return "unknown", "RDAP missing creation date"
    if created_at.tzinfo is not None:
        created_at = created_at.replace(tzinfo=None)
    age_days = (datetime.now() - created_at).days
    if age_days < 7:
        return "invalid", f"Domain too new: {age_days} days old (minimum 7 days required)"
    return "valid", f"Domain age check passed ({age_days} days, RDAP)"


def save_stage_results(
    valid_leads: List[Dict],
    invalid_leads: List[Dict],
    stage_name: str,
    output_dir: Path,
    append: bool = False,
) -> None:
    """Save stage results to JSON files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    valid_file = output_dir / f"results_{stage_name}.json"
    if valid_leads:
        try:
            existing_valid = []
            if append and valid_file.exists():
                try:
                    with open(valid_file, "r", encoding="utf-8") as f:
                        existing_valid = json.load(f)
                        if not isinstance(existing_valid, list):
                            existing_valid = []
                except (json.JSONDecodeError, IOError):
                    existing_valid = []

            all_valid = existing_valid + valid_leads
            with open(valid_file, "w", encoding="utf-8") as f:
                json.dump(all_valid, f, indent=2, ensure_ascii=False)
            logger.info(
                "Saved %d valid leads to %s (total: %d)",
                len(valid_leads),
                valid_file,
                len(all_valid),
            )
        except Exception as e:
            logger.error("Error saving %s: %s", valid_file, e)

    invalid_file = output_dir / f"results_{stage_name}_invalid.json"
    if invalid_leads:
        try:
            existing_invalid = []
            if append and invalid_file.exists():
                try:
                    with open(invalid_file, "r", encoding="utf-8") as f:
                        existing_invalid = json.load(f)
                        if not isinstance(existing_invalid, list):
                            existing_invalid = []
                except (json.JSONDecodeError, IOError):
                    existing_invalid = []

            all_invalid = existing_invalid + invalid_leads
            with open(invalid_file, "w", encoding="utf-8") as f:
                json.dump(all_invalid, f, indent=2, ensure_ascii=False)
            logger.info(
                "Saved %d invalid leads to %s (total: %d)",
                len(invalid_leads),
                invalid_file,
                len(all_invalid),
            )
        except Exception as e:
            logger.error("Error saving %s: %s", invalid_file, e)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Suppress WHOIS library error logs (we handle timeouts ourselves)
whois_logger = logging.getLogger('whois')
whois_logger.setLevel(logging.CRITICAL)  # Suppress ERROR level logs


def validate_domain_age(domain: str) -> Tuple[str, str]:
    """Check domain age using WHOIS with rate limiting, caching, and timeout.

    Returns a status string: "valid", "invalid", or "unknown".
    """
    try:
        # Extract domain from URL if needed
        if '/' in domain or domain.startswith('http'):
            domain = extract_domain_from_url(domain) or domain

        # Check cache first
        cache_key = f"whois_age:{domain}"
        if cache_key in validation_cache and not validation_cache.is_expired(cache_key, CACHE_TTLS["whois"]):
            cached_result = validation_cache[cache_key]
            return cached_result
        
        # Rate limiting: acquire semaphore before WHOIS lookup
        WHOIS_SEMAPHORE.acquire()
        try:
            time.sleep(WHOIS_DELAY)
            
            # Add timeout wrapper around whois.whois() call
            def whois_lookup():
                import whois
                stdout_buf = io.StringIO()
                stderr_buf = io.StringIO()
                with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                    return whois.whois(domain)
            
            def _rate_limit_whois() -> None:
                if WHOIS_MIN_INTERVAL <= 0:
                    return
                with _WHOIS_RATE_LOCK:
                    now = time.monotonic()
                    wait = WHOIS_MIN_INTERVAL - (now - _WHOIS_LAST_CALL)
                    if wait > 0:
                        time.sleep(wait)
                    # update after sleep to keep spacing correct under contention
                    globals()["_WHOIS_LAST_CALL"] = time.monotonic()

            whois_info = None
            for attempt in range(WHOIS_RETRIES + 1):
                try:
                    _rate_limit_whois()
                    if WHOIS_DELAY > 0:
                        time.sleep(WHOIS_DELAY)
                    future = WHOIS_EXECUTOR.submit(whois_lookup)
                    whois_info = future.result(timeout=WHOIS_TIMEOUT)
                    break
                except FutureTimeoutError:
                    future.cancel()
                    if attempt < WHOIS_RETRIES:
                        time.sleep(WHOIS_RETRY_DELAY)
                        continue
                    return "unknown", "WHOIS timeout"
            
            if whois_info and whois_info.domain_name:
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    if isinstance(creation_date, datetime):
                        # Fix: Make timezone-naive if timezone-aware
                        if creation_date.tzinfo is not None:
                            creation_date = creation_date.replace(tzinfo=None)
                        age_days = (datetime.now() - creation_date).days
                    elif isinstance(creation_date, date):
                        age_days = (datetime.now().date() - creation_date).days
                    else:
                        age_days = 0
                    if age_days < 7:
                        result = ("invalid", f"Domain too new: {age_days} days old (minimum 7 days required)")
                    else:
                        result = ("valid", f"Domain age check passed ({age_days} days)")
                    validation_cache[cache_key] = result
                    return result
                # Try RDAP fallback for missing creation date
                rdap_status, rdap_msg = rdap_domain_age(domain)
                if rdap_status != "unknown":
                    validation_cache[cache_key] = (rdap_status, rdap_msg)
                return rdap_status, rdap_msg
            # WHOIS missing domain_name, try RDAP
            rdap_status, rdap_msg = rdap_domain_age(domain)
            if rdap_status != "unknown":
                validation_cache[cache_key] = (rdap_status, rdap_msg)
            return rdap_status, rdap_msg
        finally:
            WHOIS_SEMAPHORE.release()
    except Exception as e:
        return "unknown", f"WHOIS lookup failed: {str(e)}"


def validate_mx_record(email: str) -> Tuple[bool, str]:
    """Check MX record for a given email domain."""
    if DNS_RESOLVER is None or dns is None:
        return False, "DNS resolver unavailable"

    try:
        domain = email.split('@')[1] if '@' in email else email
        answers = DNS_RESOLVER.resolve(domain, 'MX')
        if answers:
            return True, "MX record check passed"
        else:
            return False, "No MX record found"
    except dns.resolver.NXDOMAIN:
        return False, "Domain not found in DNS"
    except dns.resolver.NoAnswer:
        return False, "No MX record found"
    except dns.resolver.Timeout:
        return False, "Timeout waiting for MX record"
    except Exception as e:
        return False, f"MX record exception: {str(e)}"


def check_spf_dmarc(email: str) -> Tuple[bool, bool, str]:
    """Check SPF and DMARC for a given email address (SOFT check - always passes)."""
    try:
        domain = email.split('@')[1] if '@' in email else email
    except IndexError:
        return False, False, "invalid_email"
    
    if DNS_RESOLVER is None or dns is None:
        return False, False, "dns_resolver_unavailable"

    try:
        # Check SPF
        try:
            spf_result = DNS_RESOLVER.resolve(domain, 'TXT')
            spf_txt = [str(rdata) for rdata in spf_result]
            has_spf = any('v=spf1' in txt for txt in spf_txt)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            has_spf = False
        
        # Check DMARC
        try:
            dmarc_result = DNS_RESOLVER.resolve(f"_dmarc.{domain}", 'TXT')
            dmarc_txt = [str(rdata) for rdata in dmarc_result]
            has_dmarc = any('v=DMARC1' in txt for txt in dmarc_txt)
            dmarc_policy_strict = "strict" if has_dmarc and any('p=reject' in txt for txt in dmarc_txt) else "relaxed"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            has_dmarc = False
            dmarc_policy_strict = "none"
        
        return has_spf, has_dmarc, dmarc_policy_strict
    except Exception as e:
        return False, False, f"exception: {str(e)}"


def validate_stage1(lead: Dict) -> Tuple[str, Dict]:
    """
    Validate DNS layer (Stage 1).

    Returns:
        (status, validation_details)
    """
    validation_details = {
        "valid": None,
        "error": None,
        "has_spf": False,
        "has_dmarc": False,
        "dmarc_policy_strict": "none"
    }
    
    email = lead.get('email', '').strip()
    website = lead.get('website', '').strip()
    lead_index = lead.get('_index', -1)
    
    # 1. Domain age check (website domain) - HARD
    if website:
        try:
            status, error = validate_domain_age(website)
            if status != "valid":
                # CRITICAL: Match validator behavior - validator FAILS on all WHOIS failures
                # Remove infrastructure error checking - validator doesn't skip them
                validation_details["valid"] = None if status == "unknown" else False
                validation_details["error"] = error
                logger.warning(f"Stage 1 failed for {website} ({email}, index {lead_index}): Domain age - {error}")
                return status, validation_details
            logger.debug(f"Stage 1: Domain age check passed for {website} (index {lead_index})")
        except Exception as e:
            logger.warning(f"Stage 1: Domain age check exception for {website} ({email}, index {lead_index}): {e}")
            validation_details["valid"] = None
            validation_details["error"] = f"Domain age check failed: {str(e)}"
            return "unknown", validation_details
    else:
        validation_details["valid"] = False
        validation_details["error"] = "No website provided"
        logger.warning(f"Stage 1 failed for {email} (index {lead_index}): No website provided")
        return "invalid", validation_details

    if DNS_RESOLVER is None or dns is None:
        validation_details["valid"] = None
        validation_details["error"] = "DNS resolver unavailable"
        logger.warning(f"Stage 1 failed for {email} (index {lead_index}): DNS resolver unavailable")
        return "unknown", validation_details
    
    # 2. MX record check - MUST use WEBSITE domain (matches validator behavior)
    # Validator checks website domain for MX, not email domain
    try:
        if not website:
            validation_details["valid"] = False
            validation_details["error"] = "No website provided for MX check"
            logger.warning(f"Stage 1 failed for {email} (index {lead_index}): No website provided")
            return False, validation_details
        
        # Extract root domain from website (matches validator logic)
        website_domain = extract_root_domain(website)
        
        if not website_domain:
            validation_details["valid"] = False
            validation_details["error"] = f"Invalid website format: {website}"
            logger.warning(f"Stage 1 failed for {email} (index {lead_index}): Invalid website format")
            return False, validation_details
        
        # Check MX records on WEBSITE domain (not email domain)
        try:
            answers = DNS_RESOLVER.resolve(website_domain, 'MX')
            if answers:
                logger.debug(f"Stage 1: MX record check passed for website domain {website_domain} (index {lead_index})")
            else:
                validation_details["valid"] = False
                validation_details["error"] = f"No MX records found for website domain: {website_domain}"
                logger.warning(f"Stage 1 failed for {email} (index {lead_index}): No MX records for {website_domain}")
            return "invalid", validation_details
        except dns.resolver.NXDOMAIN:
            validation_details["valid"] = False
            validation_details["error"] = f"Website domain not found in DNS: {website_domain}"
            logger.warning(f"Stage 1 failed for {email} (index {lead_index}): Domain not found: {website_domain}")
            return "invalid", validation_details
        except dns.resolver.NoAnswer:
            validation_details["valid"] = False
            validation_details["error"] = f"No MX records found for website domain: {website_domain}"
            logger.warning(f"Stage 1 failed for {email} (index {lead_index}): No MX records for {website_domain}")
            return "invalid", validation_details
        except dns.resolver.Timeout:
            validation_details["valid"] = None
            validation_details["error"] = f"Timeout waiting for MX record: {website_domain}"
            logger.warning(f"Stage 1 failed for {email} (index {lead_index}): MX timeout for {website_domain}")
            return "unknown", validation_details
        except Exception as e:
            validation_details["valid"] = None
            validation_details["error"] = f"MX record exception for {website_domain}: {str(e)}"
            logger.error(f"Stage 1 failed for {email} (index {lead_index}): MX exception for {website_domain}: {e}")
            return "unknown", validation_details
    except Exception as e:
        validation_details["valid"] = None
        validation_details["error"] = f"MX record check failed: {str(e)}"
        logger.error(f"Stage 1 failed for {email} (index {lead_index}): MX record exception: {e}")
        return "unknown", validation_details
    
    # 3. SPF/DMARC check (SOFT - always passes, just collects data)
    try:
        has_spf, has_dmarc, dmarc_policy_strict = check_spf_dmarc(email)
        validation_details.update({
            "valid": True,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "dmarc_policy_strict": dmarc_policy_strict
        })
        # Store in lead for reputation scoring
        lead["has_spf"] = has_spf
        lead["has_dmarc"] = has_dmarc
        lead["dmarc_policy_strict"] = dmarc_policy_strict
        logger.debug(f"Stage 1: SPF/DMARC check completed for {email} (index {lead_index}) - SPF: {has_spf}, DMARC: {has_dmarc}")
    except Exception as e:
        logger.warning(f"Stage 1: SPF/DMARC check exception for {email} (index {lead_index}): {e}")
        validation_details.update({"valid": True, "has_spf": False, "has_dmarc": False, "dmarc_policy_strict": "none"})
    
    return "valid", validation_details


def process_stage1_batch(leads: List[Dict], output_dir: Optional[Path] = None) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Process a batch of leads through Stage 1 validation."""
    valid_leads = []
    invalid_leads = []
    unknown_leads = []
    
    for lead in leads:
        status, validation_details = validate_stage1(lead)
        
        if "validation_details" not in lead:
            lead["validation_details"] = {}
        lead["validation_details"]["stage_1_dns"] = validation_details
        
        if status == "valid":
            valid_leads.append(lead)
        elif status == "invalid":
            invalid_leads.append(lead)
        else:
            unknown_leads.append(lead)
    
    if output_dir:
        save_stage_results(valid_leads, invalid_leads, "stage1", output_dir)
    
    return valid_leads, invalid_leads, unknown_leads


# CSV-based WHOIS classification ------------------------------------------------

def derive_output_paths(csv_path: Path) -> Tuple[Path, Path, Path]:
    base = csv_path.stem
    parent = csv_path.parent
    valid_out = parent / f"{base}_whois_valid.csv"
    invalid_out = parent / f"{base}_whois_invalid.csv"
    unknown_out = parent / f"{base}_whois_unknown.csv"
    return valid_out, invalid_out, unknown_out


def _shorten_reason(reason: str, max_length: int = 200) -> str:
    """Trim WHOIS failure text to a single, short line for CSV output."""
    if not reason:
        return ""
    first_line = reason.strip().splitlines()[0].strip()
    if len(first_line) <= max_length:
        return first_line
    return first_line[: max_length - 3] + "..."


def _open_append_writers(
    valid_path: Path,
    invalid_path: Path,
    unknown_path: Path,
    fieldnames: List[str],
) -> Tuple[csv.writer, csv.writer, csv.writer, Any, Any, Any]:
    """Open valid/invalid/unknown CSVs for appending, writing header if the file is empty/non-existent."""
    def _open_one(path: Path):
        exists = path.exists() and path.stat().st_size > 0
        fh = path.open("a", newline="", encoding="utf-8")
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        return fh, writer

    v_fh, v_writer = _open_one(valid_path)
    i_fh, i_writer = _open_one(invalid_path)
    u_fh, u_writer = _open_one(unknown_path)
    return v_writer, i_writer, u_writer, v_fh, i_fh, u_fh


def _open_csv_reader(path: Path) -> Tuple[Any, csv.DictReader]:
    """Open a CSV with UTF-8, falling back to cp1252 if needed."""
    try:
        fh = path.open(newline="", encoding="utf-8")
        return fh, csv.DictReader(fh)
    except UnicodeDecodeError:
        fh = path.open(newline="", encoding="cp1252")
        logger.warning("CSV %s is not UTF-8; using cp1252 fallback.", path)
        return fh, csv.DictReader(fh)


def classify_csv_by_whois(
    csv_path: Path,
    website_column: str = "website",
    reason_column: str = "whois_result",
    valid_out: Optional[Path] = None,
    invalid_out: Optional[Path] = None,
    unknown_out: Optional[Path] = None,
    batch_size: int = 1000,
    workers: int = 8,
    skip_rewrite: bool = False,
    strict_unknown: bool = False,
) -> Tuple[Path, Path, Path, int, int, int, int]:
    """
    Process the first `batch_size` data rows from a CSV, append WHOIS validation
    results to valid/invalid/unknown output CSVs. Optionally rewrite the source
    CSV without those processed rows (default), or skip rewriting for speed.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {csv_path}")

    valid_path, invalid_path, unknown_path = derive_output_paths(csv_path)
    if valid_out:
        valid_path = valid_out
    if invalid_out:
        invalid_path = invalid_out
    if unknown_out:
        unknown_path = unknown_out

    tmp_path = csv_path.with_suffix(csv_path.suffix + ".tmp")

    processed_rows: List[Dict[str, str]] = []
    processed_count = 0
    valid_count = 0
    invalid_count = 0
    unknown_count = 0

    # First pass: grab the batch quickly (no rewriting yet)
    src_fh, reader = _open_csv_reader(csv_path)
    with src_fh:
        if reader.fieldnames is None:
            raise ValueError("CSV is missing a header row.")
        if website_column not in reader.fieldnames:
            raise ValueError(f"Column '{website_column}' not found in CSV header.")

        input_fieldnames = list(reader.fieldnames)
        output_fieldnames = list(reader.fieldnames)
        if reason_column not in output_fieldnames:
            output_fieldnames.append(reason_column)

        for idx, row in enumerate(reader, start=1):
            if processed_count >= batch_size:
                break
            row["_batch_index"] = idx  # keep original position
            processed_rows.append(row)
            processed_count += 1

    if not processed_rows:
        return valid_path, invalid_path, unknown_path, 0, 0, 0, 0

    # Process batch in parallel to improve throughput (rate limiting still applies in WHOIS)
    def _process_row(row: Dict[str, str]) -> Tuple[str, str, Dict[str, str], str]:
        website_value = (row.get(website_column) or "").strip()
        lead = {"website": website_value, "_index": row.get("_batch_index", -1)}
        try:
            status, details = validate_stage1(lead)
            message = details.get("error") or "valid"
        except Exception as exc:
            status, message = "unknown", f"Validation failed: {exc}"
        if status == "unknown" and strict_unknown:
            status = "invalid"
            message = f"{message} (strict)"
        short_message = _shorten_reason(message)
        row[reason_column] = short_message
        row.pop("_batch_index", None)
        return status, short_message, row, website_value

    valid_writer, invalid_writer, unknown_writer, v_fh, i_fh, u_fh = _open_append_writers(
        valid_path,
        invalid_path,
        unknown_path,
        output_fieldnames,
    )
    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            for idx, (status, message, row, website_value) in enumerate(executor.map(_process_row, processed_rows), start=1):
                output_row = {name: row.get(name, "") for name in output_fieldnames}
                if status == "valid":
                    valid_writer.writerow(output_row)
                    valid_count += 1
                    print(f"success ({website_value or 'blank'}): {message}")
                elif status == "invalid":
                    invalid_writer.writerow(output_row)
                    invalid_count += 1
                    print(f"failed ({website_value or 'blank'}): {message}")
                else:
                    unknown_writer.writerow(output_row)
                    unknown_count += 1
                    print(f"unknown ({website_value or 'blank'}): {message}")
                if idx % 50 == 0:
                    print(f"Progress: {idx}/{processed_count} | valid={valid_count} invalid={invalid_count} unknown={unknown_count}")
    finally:
        v_fh.close()
        i_fh.close()
        u_fh.close()

    if not skip_rewrite:
        # Second pass: rewrite the remaining rows (skip the processed ones)
        src_fh, reader = _open_csv_reader(csv_path)
        with src_fh, tmp_path.open("w", newline="", encoding="utf-8") as tmp_file:
            tmp_writer = csv.DictWriter(tmp_file, fieldnames=input_fieldnames)
            tmp_writer.writeheader()
            for idx, row in enumerate(reader, start=1):
                if idx <= processed_count:
                    continue
                tmp_writer.writerow(row)

        tmp_path.replace(csv_path)

    if skip_rewrite:
        logger.info(
            "WHOIS batch complete for %s: %d processed (%d valid, %d invalid, %d unknown); source CSV left untouched (skip_rewrite=True).",
            csv_path,
            processed_count,
            valid_count,
            invalid_count,
            unknown_count,
        )
    else:
        logger.info(
            "WHOIS batch complete for %s: %d processed (%d valid, %d invalid, %d unknown); remaining rows: rewrote source without processed batch.",
            csv_path,
            processed_count,
            valid_count,
            invalid_count,
            unknown_count,
        )
    return valid_path, invalid_path, unknown_path, processed_count, valid_count, invalid_count, unknown_count


def retry_unknown_csv(
    unknown_csv: Path,
    website_column: str,
    reason_column: str,
    valid_out: Path,
    invalid_out: Path,
    unknown_out: Path,
    workers: int,
    strict_unknown: bool,
) -> Tuple[int, int, int]:
    """Reprocess the unknown CSV with current WHOIS/RDAP settings."""
    if not unknown_csv.exists():
        return 0, 0, 0
    _, _, _, processed, valid_count, invalid_count, unknown_count = classify_csv_by_whois(
        unknown_csv,
        website_column=website_column,
        reason_column=reason_column,
        valid_out=valid_out,
        invalid_out=invalid_out,
        unknown_out=unknown_out,
        batch_size=10**9,
        workers=workers,
        skip_rewrite=False,
        strict_unknown=strict_unknown,
    )
    return processed, valid_count, invalid_count


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split a CSV into WHOIS-valid, WHOIS-invalid, and WHOIS-unknown rows.")
    parser.add_argument("csv_path", type=Path, help="Path to the input CSV file.")
    parser.add_argument("--website-column", default="website", help="Column name containing website URLs.")
    parser.add_argument("--reason-column", default="whois_result", help="Column name to store WHOIS result text.")
    parser.add_argument("--valid-out", type=Path, help="Optional explicit path for the valid rows CSV.")
    parser.add_argument("--invalid-out", type=Path, help="Optional explicit path for the invalid rows CSV.")
    parser.add_argument("--unknown-out", type=Path, help="Optional explicit path for the unknown rows CSV.")
    parser.add_argument("--batch-size", type=int, default=1000, help="Number of data rows to process per run (default: 1000).")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent WHOIS workers per batch (default: 10).")
    parser.add_argument("--skip-rewrite", action="store_true", help="Skip rewriting the source CSV after processing the batch (faster; leaves source intact).")
    parser.add_argument("--strict", action="store_true", help="Treat unknown WHOIS/DNS results as invalid.")
    parser.add_argument("--retry-unknown", action="store_true", help="Reprocess the unknown CSV with current WHOIS settings.")
    parser.add_argument("--retry-timeout", type=float, default=3.0, help="WHOIS timeout for retry-unknown (default: 3).")
    parser.add_argument("--retry-retries", type=int, default=1, help="WHOIS retries for retry-unknown (default: 1).")
    parser.add_argument("--retry-min-interval", type=float, default=0.5, help="Minimum spacing between WHOIS calls in retry-unknown (default: 0.5).")
    parser.add_argument("--whois-timeout", type=float, default=WHOIS_TIMEOUT, help="WHOIS timeout in seconds (default: 1).")
    parser.add_argument("--whois-retries", type=int, default=WHOIS_RETRIES, help="WHOIS retries on timeout (default: 2).")
    parser.add_argument("--whois-retry-delay", type=float, default=WHOIS_RETRY_DELAY, help="Delay between WHOIS retries in seconds (default: 0.25).")
    parser.add_argument("--whois-min-interval", type=float, default=WHOIS_MIN_INTERVAL, help="Minimum spacing between WHOIS calls in seconds (default: 0.25).")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    globals()["WHOIS_TIMEOUT"] = max(0.1, float(args.whois_timeout))
    globals()["WHOIS_RETRIES"] = max(0, int(args.whois_retries))
    globals()["WHOIS_RETRY_DELAY"] = max(0.0, float(args.whois_retry_delay))
    globals()["WHOIS_MIN_INTERVAL"] = max(0.0, float(args.whois_min_interval))
    try:
        valid_path, invalid_path, unknown_path, processed, valid_count, invalid_count, unknown_count = classify_csv_by_whois(
            args.csv_path,
            website_column=args.website_column,
            reason_column=args.reason_column,
            valid_out=args.valid_out,
            invalid_out=args.invalid_out,
            unknown_out=args.unknown_out,
            batch_size=args.batch_size,
            workers=args.workers,
            skip_rewrite=args.skip_rewrite,
            strict_unknown=args.strict,
        )
    except Exception as exc:
        logger.error("Failed to classify CSV: %s", exc)
        print(f"Error: {exc}")
        return 1

    print(f"Processed {processed} row(s).")
    print(f"Appended WHOIS-valid rows to: {valid_path} ({valid_count})")
    print(f"Appended WHOIS-invalid rows to: {invalid_path} ({invalid_count})")
    print(f"Appended WHOIS-unknown rows to: {unknown_path} ({unknown_count})")
    if args.retry_unknown:
        prev_timeout = WHOIS_TIMEOUT
        prev_retries = WHOIS_RETRIES
        prev_min_interval = WHOIS_MIN_INTERVAL
        globals()["WHOIS_TIMEOUT"] = max(0.1, float(args.retry_timeout))
        globals()["WHOIS_RETRIES"] = max(0, int(args.retry_retries))
        globals()["WHOIS_MIN_INTERVAL"] = max(0.0, float(args.retry_min_interval))
        print("Retrying unknown rows with relaxed WHOIS settings...")
        retry_processed, retry_valid, retry_invalid = retry_unknown_csv(
            unknown_path,
            website_column=args.website_column,
            reason_column=args.reason_column,
            valid_out=valid_path,
            invalid_out=invalid_path,
            unknown_out=unknown_path,
            workers=max(1, args.workers),
            strict_unknown=args.strict,
        )
        globals()["WHOIS_TIMEOUT"] = prev_timeout
        globals()["WHOIS_RETRIES"] = prev_retries
        globals()["WHOIS_MIN_INTERVAL"] = prev_min_interval
        print(f"Retry processed {retry_processed} row(s).")
        print(f"Retry moved to valid: {retry_valid}")
        print(f"Retry moved to invalid: {retry_invalid}")

    if args.skip_rewrite:
        print("Source CSV updated: no (skip_rewrite enabled).")
    else:
        print(f"Source CSV updated: first {processed} row(s) removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
