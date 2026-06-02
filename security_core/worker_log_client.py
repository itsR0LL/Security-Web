from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class WorkerLogClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerLogExport:
    rows: list[dict[str, Any]]
    cursor: int
    next_cursor: int
    has_more: bool


def fetch_worker_log_export(export_url: str, export_token: str, *, cursor: int = 0, limit: int = 500) -> WorkerLogExport:
    if not export_url.strip():
        raise WorkerLogClientError("SECURITY_WORKER_LOG_EXPORT_URL is not configured.")
    if not export_token.strip():
        raise WorkerLogClientError("SECURITY_WORKER_LOG_EXPORT_TOKEN is not configured.")

    separator = "&" if "?" in export_url else "?"
    url = f"{export_url}{separator}{urlencode({'cursor': cursor, 'limit': limit})}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {export_token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) SecurityStudioWorkerLogSync/0.1 Safari/537.36",
            "X-Security-Studio-Client": "worker-log-sync",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise WorkerLogClientError(f"Worker log export returned HTTP {error.code}: {detail}") from error
    except URLError as error:
        raise WorkerLogClientError(f"Worker log export request failed: {error}") from error
    except json.JSONDecodeError as error:
        raise WorkerLogClientError("Worker log export returned invalid JSON.") from error

    if payload.get("success") is False:
        raise WorkerLogClientError(str(payload.get("message") or "Worker log export failed."))

    data = payload.get("data") or {}
    rows = data.get("rows") or []
    if not isinstance(rows, list):
        raise WorkerLogClientError("Worker log export rows field is not a list.")
    return WorkerLogExport(
        rows=[row for row in rows if isinstance(row, dict)],
        cursor=int(data.get("cursor") or cursor),
        next_cursor=int(data.get("nextCursor") or cursor),
        has_more=bool(data.get("hasMore")),
    )
