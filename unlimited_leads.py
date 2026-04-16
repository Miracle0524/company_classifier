"""
Download scraped results from Apify API.

Fetches all runs for a fixed actor, merges into total.json, deletes runs after fetch.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(_ENV_PATH)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

APIFY_BASE = "https://api.apify.com/v2"
APIFY_TOKEN = (os.environ.get("APIFY_TOKEN") or os.environ.get("APIFY_API_TOKEN") or "").strip()

ACTOR_ID = "Vd7FKoadBUvv0aWP1"
OUTPUT_FILE = Path("total.json")

# Run statuses that are finished (can be deleted). Skip RUNNING, READY, ABORTING, TIMING-OUT.
FINISHED_RUN_STATUSES = frozenset({"SUCCEEDED", "FAILED", "TIMED-OUT", "ABORTED"})


def list_actor_runs(actor_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """List all runs for an actor or task. Tries actor-tasks, acts, then user runs filtered by actId."""
    if not APIFY_TOKEN:
        raise ValueError("APIFY_TOKEN or APIFY_API_TOKEN required")
    headers = {"Authorization": f"Bearer {APIFY_TOKEN}"}
    params = {"limit": limit, "offset": 0}

    def _fetch_paginated(url: str) -> Optional[List[Dict[str, Any]]]:
        runs: List[Dict[str, Any]] = []
        offset = 0
        try:
            while True:
                r = requests.get(url, headers=headers, params={**params, "offset": offset}, timeout=60)
                if r.status_code == 404:
                    logger.debug("404 for %s", url)
                    return None
                r.raise_for_status()
                data = r.json()
                inner = data.get("data", data)
                items = inner.get("items", [])
                total = int(inner.get("total", 0))
                for run in items:
                    if isinstance(run, dict):
                        runs.append(run)
                if not items or offset + len(items) >= total:
                    break
                offset += len(items)
            return runs
        except requests.exceptions.HTTPError:
            return None

    # Try 1: GET /actor-tasks/{taskId}/runs (task runs)
    runs = _fetch_paginated(f"{APIFY_BASE}/actor-tasks/{actor_id}/runs")
    if runs:
        logger.debug("Found %d runs via actor-tasks endpoint", len(runs))
        return runs
    # Try 2: GET /acts/{actorId}/runs (actor runs)
    runs = _fetch_paginated(f"{APIFY_BASE}/acts/{actor_id}/runs")
    if runs is None:
        runs = []
    if runs:
        logger.debug("Found %d runs via acts endpoint", len(runs))
        return runs
    # Try 3: GET /actor-runs (all user runs) + filter by actId
    all_runs = []
    offset = 0
    while True:
        r = requests.get(
            f"{APIFY_BASE}/actor-runs",
            headers=headers,
            params={"limit": limit, "offset": offset},
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        inner = data.get("data", data)
        items = inner.get("items", [])
        total = int(inner.get("total", 0))
        for run in items:
            if isinstance(run, dict) and run.get("actId") == actor_id:
                all_runs.append(run)
        if not items or offset + len(items) >= total:
            break
        offset += len(items)
    if all_runs:
        logger.debug("Found %d runs via actor-runs filtered by actId", len(all_runs))
    return all_runs


def delete_run(run_id: str) -> bool:
    """Delete a finished run. Returns True on success (204)."""
    if not APIFY_TOKEN:
        raise ValueError("APIFY_TOKEN or APIFY_API_TOKEN required")
    url = f"{APIFY_BASE}/actor-runs/{run_id}"
    r = requests.delete(
        url,
        headers={"Authorization": f"Bearer {APIFY_TOKEN}"},
        timeout=30,
    )
    if r.status_code == 204:
        return True
    logger.warning("Delete run %s failed: status %s %s", run_id, r.status_code, r.text[:200])
    return False


def fetch_dataset_items(
    dataset_id: str,
    format: str = "json",
    offset: int = 0,
    limit: Optional[int] = None,
    clean: bool = True,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Fetch dataset items with pagination.
    Returns (items, total_count).
    """
    if not APIFY_TOKEN:
        raise ValueError("APIFY_TOKEN or APIFY_API_TOKEN required")
    url = f"{APIFY_BASE}/datasets/{dataset_id}/items"
    params = {"format": format, "offset": offset, "clean": 1 if clean else 0}
    if limit is not None:
        params["limit"] = limit
    r = requests.get(
        url,
        headers={"Authorization": f"Bearer {APIFY_TOKEN}"},
        params=params,
        timeout=60,
    )
    r.raise_for_status()
    total = int(r.headers.get("X-Apify-Pagination-Total", 0))
    if format == "json":
        items = r.json()
    elif format == "jsonl":
        items = [json.loads(line) for line in r.text.strip().split("\n") if line]
    else:
        return ([], total)
    return (items if isinstance(items, list) else [items], total)


def iterate_all_items(
    dataset_id: str,
    page_size: int = 1000,
) -> Iterator[Dict[str, Any]]:
    """Stream all dataset items with pagination."""
    offset = 0
    while True:
        items, total = fetch_dataset_items(
            dataset_id,
            format="json",
            offset=offset,
            limit=page_size,
        )
        for item in items:
            yield item
        if not items or offset + len(items) >= total:
            break
        offset += len(items)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download scraped results from Apify API (actor runs -> total.json)."
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Do not delete runs after fetch",
    )
    parser.add_argument(
        "--act-id",
        type=str,
        default=None,
        help="Override actor ID (use if ACTOR_ID from console URL returns no runs)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Items per API request (default: 1000)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    return parser.parse_args(argv)


def run(actor_id: str, out_path: Path, page_size: int, delete_after_fetch: bool) -> int:
    """Fetch all runs for actor, merge into total.json, optionally delete runs."""
    runs = list_actor_runs(actor_id)
    finished = [r for r in runs if str(r.get("status", "")).upper() in FINISHED_RUN_STATUSES]
    if runs and not finished:
        statuses = {}
        for r in runs:
            s = str(r.get("status", "?")).upper()
            statuses[s] = statuses.get(s, 0) + 1
        logger.info("Got %d runs but none finished. Statuses: %s", len(runs), statuses)
    if not finished:
        logger.info("No finished runs found for actor %s", actor_id)
        print("No finished runs to process.")
        return 0
    logger.info("Found %d finished run(s) for actor %s", len(finished), actor_id)
    all_items: List[Dict[str, Any]] = []
    fetched = 0
    deleted = 0
    for run in finished:
        run_id = run.get("id")
        dataset_id = run.get("defaultDatasetId")
        if not run_id or not dataset_id:
            logger.warning("Run %s missing id or defaultDatasetId, skipping", run_id)
            continue
        try:
            before = len(all_items)
            for item in iterate_all_items(dataset_id, page_size):
                all_items.append(item)
            run_count = len(all_items) - before
            fetched += 1
            print(f"  Downloaded {run_count} items from run {run_id}")
        except Exception as exc:
            logger.exception("Failed to fetch run %s: %s", run_id, exc)
            print(f"  Error fetching run {run_id}: {exc}", file=sys.stderr)
            continue
        if delete_after_fetch:
            if delete_run(run_id):
                deleted += 1
                logger.info("Deleted run %s", run_id)
            else:
                print(f"  Warning: could not delete run {run_id}", file=sys.stderr)

    if all_items:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(all_items, f, ensure_ascii=False, indent=2)
        print(f"Saved to {out_path}")

    print(f"Processed {fetched} run(s), {len(all_items)} total items, deleted {deleted} run(s)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s:%(name)s:%(message)s",
    )
    if not APIFY_TOKEN:
        logger.error("APIFY_TOKEN or APIFY_API_TOKEN not set")
        print("Error: Set APIFY_TOKEN or APIFY_API_TOKEN", file=sys.stderr)
        return 1
    actor_id = args.act_id or ACTOR_ID
    try:
        return run(
            actor_id=actor_id,
            out_path=OUTPUT_FILE,
            page_size=args.page_size,
            delete_after_fetch=not args.no_delete,
        )
    except Exception as exc:
        logger.exception("Download failed")
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
