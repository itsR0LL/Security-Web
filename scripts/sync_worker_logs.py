from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/")


def request_json(url: str, *, method: str = "GET", timeout: float = 10.0) -> dict[str, Any]:
    data = b"" if method.upper() != "GET" else None
    request = Request(
        url,
        data=data,
        method=method.upper(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SecurityStudioLocalWorkerSync/0.1",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError("API returned non-object JSON.")
    return payload


def wait_for_backend(api_url: str, *, wait_seconds: int, interval_seconds: float, timeout_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    health_url = f"{api_url}/api/health"
    last_error = ""

    while time.monotonic() <= deadline:
        try:
            payload = request_json(health_url, timeout=timeout_seconds)
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            if payload.get("success") is True and data.get("status") == "online":
                print(f"[OK] Backend online: {health_url}")
                return
            last_error = f"Unexpected health payload: {payload}"
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, RuntimeError) as error:
            last_error = str(error)
        time.sleep(interval_seconds)

    raise TimeoutError(f"Backend did not become ready within {wait_seconds}s. Last error: {last_error}")


def sync_once(api_url: str, *, limit: int, timeout_seconds: float) -> dict[str, Any]:
    query = urlencode({"limit": limit})
    payload = request_json(f"{api_url}/api/worker-logs/sync?{query}", method="POST", timeout=timeout_seconds)
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    if payload.get("success") is not True:
        raise RuntimeError(f"Sync API returned failure wrapper: {payload}")
    if data.get("status") != "success":
        message = data.get("message") or "Worker log sync failed."
        raise RuntimeError(str(message))
    return data


def sync_all(api_url: str, *, limit: int, max_pages: int, timeout_seconds: float) -> dict[str, int]:
    totals = {
        "pages": 0,
        "accessLogs": 0,
        "events": 0,
        "aggregates": 0,
    }

    for page in range(1, max_pages + 1):
        data = sync_once(api_url, limit=limit, timeout_seconds=timeout_seconds)
        totals["pages"] = page
        totals["accessLogs"] += int(data.get("accessLogs") or 0)
        totals["events"] += int(data.get("events") or 0)
        totals["aggregates"] += int(data.get("aggregates") or 0)

        print(
            "[OK] Sync page {page}: cursor={cursor} nextCursor={next_cursor} "
            "accessLogs={access_logs} events={events} aggregates={aggregates} hasMore={has_more}".format(
                page=page,
                cursor=data.get("cursor"),
                next_cursor=data.get("nextCursor"),
                access_logs=data.get("accessLogs"),
                events=data.get("events"),
                aggregates=data.get("aggregates"),
                has_more=data.get("hasMore"),
            )
        )

        if not data.get("hasMore"):
            break
    else:
        print(f"[WARN] Reached max pages: {max_pages}. Run the script again if D1 still has more rows.")

    return totals


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync Cloudflare Worker D1 access logs into local Security Studio SQLite.")
    parser.add_argument("--api-url", default="http://127.0.0.1:8787", help="Local Security Studio API base URL.")
    parser.add_argument("--limit", type=int, default=1000, help="Rows to request per backend sync call.")
    parser.add_argument("--max-pages", type=int, default=20, help="Maximum backend sync calls for one local startup.")
    parser.add_argument("--wait-seconds", type=int, default=90, help="How long to wait for the local backend.")
    parser.add_argument("--interval-seconds", type=float, default=1.5, help="Backend health polling interval.")
    parser.add_argument("--timeout-seconds", type=float, default=20.0, help="HTTP request timeout.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    api_url = normalize_base_url(args.api_url)
    limit = max(1, min(args.limit, 1000))
    max_pages = max(1, args.max_pages)

    print("[INFO] Security Studio Worker/D1 local sync helper")
    print(f"[INFO] API URL: {api_url}")
    print(f"[INFO] Limit: {limit}, max pages: {max_pages}")

    try:
        wait_for_backend(
            api_url,
            wait_seconds=max(1, args.wait_seconds),
            interval_seconds=max(0.2, args.interval_seconds),
            timeout_seconds=max(1.0, args.timeout_seconds),
        )
        totals = sync_all(api_url, limit=limit, max_pages=max_pages, timeout_seconds=max(1.0, args.timeout_seconds))
    except Exception as error:
        print(f"[ERROR] Worker/D1 sync failed: {error}")
        print("[INFO] Check SECURITY_WORKER_LOG_EXPORT_URL and SECURITY_WORKER_LOG_EXPORT_TOKEN in the backend environment.")
        return 1

    print(
        "[OK] Worker/D1 sync complete: pages={pages} accessLogs={accessLogs} events={events} aggregates={aggregates}".format(
            **totals
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
