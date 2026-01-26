import argparse
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


DEFAULT_FETCH_COUNT = 5000
APIFY_BATCH_SIZE = 100
TRUELIST_SUB_STATES = [
    "email_ok",
    "accept_all",
    "is_role",
    "failed_no_mailbox",
    "failed_greylisted",
]


def _normalize_domain(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    domain = parsed.netloc or parsed.path
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _http_json(url: str, payload: Optional[dict], headers: dict, timeout: int = 120) -> object:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json"}
    req = Request(url, data=data, headers=headers)
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    if not body:
        return None
    return json.loads(body)


def _run_apify_actor(
    actor_id: str,
    token: str,
    company_domains: Iterable[str],
    email_status: Iterable[str],
    fetch_count: int,
    timeout: int,
) -> list[dict]:
    url = (
        f"https://api.apify.com/v2/acts/{actor_id}/run-sync-get-dataset-items?"
        + urlencode({"token": token})
    )
    payload = {
        "company_domain": list(company_domains),
        "email_status": list(email_status),
        "fetch_count": fetch_count,
    }
    result = _http_json(url, payload, headers={}, timeout=timeout)
    if isinstance(result, list):
        return result
    return []


def _truelist_auth_header(token: str, prefix: str) -> str:
    if not token:
        return ""
    if " " in token:
        return token
    return f"{prefix} {token}".strip()


def _verify_emails_truelist(
    token: str,
    emails: list[str],
    auth_prefix: str,
    timeout: int,
) -> list[dict]:
    if not emails:
        return []
    query = {"email": " ".join(emails)}
    url = f"{TRUELIST_VERIFY_URL}?{urlencode(query)}"
    headers = {"Authorization": _truelist_auth_header(token, auth_prefix)}
    result = _http_json(url, payload={}, headers=headers, timeout=timeout)
    if isinstance(result, dict):
        items = result.get("emails")
        if isinstance(items, list):
            return items
    return []


def derive_output_path(csv_path: Path) -> Path:
    base = csv_path.stem
    return csv_path.with_name(f"{base}_catchall.csv")


def derive_ok_emails_path(csv_path: Path) -> Path:
    base = csv_path.stem
    return csv_path.with_name(f"{base}_ok_emails.json")


def derive_apify_leads_path(csv_path: Path) -> Path:
    base = csv_path.stem
    return csv_path.with_name(f"{base}_apify_leads.json")


def check_catchall(
    csv_path: Path,
    fetch_count: int = DEFAULT_FETCH_COUNT,
    email_status: Iterable[str] = ("validated",),
    truelist_auth_prefix: str = "Bearer",
    apify_timeout: int = 300,
    truelist_timeout: int = 60,
    truelist_delay: float = 0.2,
) -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    output_path = derive_output_path(csv_path)
    ok_emails_path = derive_ok_emails_path(csv_path)
    apify_leads_path = derive_apify_leads_path(csv_path)
    ok_email_rows: list[dict] = []
    apify_leads: list[dict] = []
    row_infos: list[dict] = []
    email_to_rows: dict[str, list[int]] = {}

    with csv_path.open(newline="", encoding="utf-8") as src:
        reader = csv.reader(src)

        try:
            header = next(reader)
        except StopIteration:
            print("Dataset is empty; no rows to process.")
            return

        try:
            website_idx = header.index("website")
        except ValueError:
            print(f"No 'website' column found in dataset header.")
            return

        processed = 0
        domains: list[str] = []
        for row in reader:
            processed += 1
            website = row[website_idx] if len(row) > website_idx else ""
            domain = _normalize_domain(website)
            row_info = {
                "row": row,
                "checked_emails": [],
                "skipped_null": 0,
                "truelist_counts": {state: 0 for state in TRUELIST_SUB_STATES},
                "truelist_other": 0,
                "apify_item_count": 0,
                "error": "missing_domain" if not domain else "",
                "domain": domain,
                "email_to_item": {},
            }
            row_infos.append(row_info)
            if domain:
                domains.append(domain)

        unique_domains = list(dict.fromkeys(domains))
        for i in range(0, len(unique_domains), APIFY_BATCH_SIZE):
            batch = unique_domains[i:i + APIFY_BATCH_SIZE]
            print(f"[apify] batch {i // APIFY_BATCH_SIZE + 1} size={len(batch)}")
            try:
                items = _run_apify_actor(
                    actor_id=DEFAULT_ACTOR_ID,
                    token=APIFY_TOKEN,
                    company_domains=batch,
                    email_status=email_status,
                    fetch_count=fetch_count,
                    timeout=apify_timeout,
                )
            except Exception as exc:
                print(f"[apify] batch {i // APIFY_BATCH_SIZE + 1} error {exc}")
                continue

            print(f"[apify] batch {i // APIFY_BATCH_SIZE + 1} items={len(items)}")
            for item in items:
                if not isinstance(item, dict):
                    continue
                item_domain = _normalize_domain(str(item.get("company_domain") or ""))
                if not item_domain:
                    continue
                for idx, info in enumerate(row_infos):
                    if info["domain"] == item_domain:
                        info["apify_item_count"] += 1
                        email = item.get("email")
                        if not email:
                            info["skipped_null"] += 1
                            continue
                        info["checked_emails"].append(email)
                        info["email_to_item"].setdefault(email, []).append(item)
                apify_leads.append(item)

        for idx, info in enumerate(row_infos):
            for email in info["checked_emails"]:
                email_to_rows.setdefault(email, []).append(idx)

    if apify_leads_path.exists():
        try:
            with apify_leads_path.open("r", encoding="utf-8") as in_fh:
                existing = json.load(in_fh)
            if isinstance(existing, list):
                apify_leads = existing + apify_leads
            else:
                print(f"Warning: {apify_leads_path} is not a JSON list; overwriting.")
        except Exception as exc:
            print(f"Warning: failed to read existing {apify_leads_path}: {exc}")

    with apify_leads_path.open("w", encoding="utf-8") as out_fh:
        json.dump(apify_leads, out_fh, indent=2, ensure_ascii=False)

    print(f"Finished {processed} rows.")
    print(f"Wrote apify leads to {apify_leads_path}")
    return

    out_header = header + [
        "checked_count",
        "ok_email_count",
        "null_email_count",
        *[f"truelist_{state}" for state in TRUELIST_SUB_STATES],
        "truelist_other",
        "apify_item_count",
        "error",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as dst:
        writer = csv.writer(dst)
        writer.writerow(out_header)
        for info in row_infos:
            out_row = info["row"] + [
                str(len(info["checked_emails"])),
                str(len(info["checked_emails"])),
                str(info["skipped_null"]),
                *[str(info["truelist_counts"][state]) for state in TRUELIST_SUB_STATES],
                str(info["truelist_other"]),
                str(info["apify_item_count"]),
                info["error"],
            ]
            writer.writerow(out_row)

    with ok_emails_path.open("w", encoding="utf-8") as out_fh:
        json.dump(ok_email_rows, out_fh, indent=2, ensure_ascii=False)

    print(f"Finished {processed} rows.")
    print(f"Wrote output to {output_path}")
    print(f"Wrote ok emails to {ok_emails_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check company domains for catch-all using Apify + Truelist.")
    parser.add_argument("csv_path", type=Path, help="Path to input CSV.")
    parser.add_argument("--fetch-count", type=int, default=DEFAULT_FETCH_COUNT, help="Leads to fetch per company.")
    parser.add_argument("--truelist-auth-prefix", default="Bearer",
                        help="Authorization prefix for Truelist (use '' to send raw token).")
    parser.add_argument("--apify-timeout", type=int, default=300, help="Apify request timeout in seconds.")
    parser.add_argument("--truelist-timeout", type=int, default=60, help="Truelist request timeout in seconds.")
    parser.add_argument("--truelist-delay", type=float, default=0.2, help="Delay between Truelist calls (seconds).")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    check_catchall(
        csv_path=args.csv_path,
        fetch_count=args.fetch_count,
        truelist_auth_prefix=args.truelist_auth_prefix,
        apify_timeout=args.apify_timeout,
        truelist_timeout=args.truelist_timeout,
        truelist_delay=args.truelist_delay,
    )


if __name__ == "__main__":
    main()
