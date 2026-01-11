import argparse
import glob
import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_endpoint_template(endpoint: str, paper_id: str) -> str:
    if not endpoint or not paper_id:
        return endpoint
    placeholders = ("<paperId>", "{PAPER_ID}", "{paper_id}")
    if any(p in endpoint for p in placeholders):
        return (
            endpoint.replace("<paperId>", paper_id)
            .replace("{PAPER_ID}", paper_id)
            .replace("{paper_id}", paper_id)
        )

    parts = urlsplit(endpoint)
    existing_path = parts.path or ""
    normalized_existing = existing_path.rstrip("/")
    candidate_path = normalized_existing + "/" + paper_id

    if normalized_existing.endswith("/" + paper_id) or normalized_existing == paper_id:
        candidate_path = existing_path

    return urlunsplit((parts.scheme, parts.netloc, candidate_path, parts.query, parts.fragment))


def _newest_png(temp_dir: str) -> Optional[Path]:
    candidates = [Path(p) for p in glob.glob(str(Path(temp_dir) / "*.png"))]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _redacted_headers(headers: dict) -> dict:
    out = {}
    for k, v in headers.items():
        lk = str(k).lower()
        if lk in {"authorization", "cookie", "x-api-key", "x-ipp-token"}:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload newest temp PNG using POST_* env vars")
    parser.add_argument("--temp-dir", default=_env_str("IPP_TEMP_DIR", "./temp"))
    parser.add_argument("--endpoint", default=_env_str("POST_ENDPOINT", ""))
    parser.add_argument("--timeout", type=int, default=int(_env_str("POST_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args()

    load_dotenv()

    endpoint = args.endpoint or _env_str("POST_ENDPOINT", "")
    if not endpoint:
        raise SystemExit("POST_ENDPOINT is empty; set it in .env")

    paper_id = os.getenv("PAPER_ID") or ""
    endpoint = _resolve_endpoint_template(endpoint, paper_id.strip())

    file_field = _env_str("POST_FILE_FIELD", "file")
    include_meta_fields = _env_bool("POST_INCLUDE_META_FIELDS", True)

    auth_header = os.getenv("POST_AUTH_HEADER") or ""
    auth_value = os.getenv("POST_AUTH_VALUE") or ""

    newest = _newest_png(args.temp_dir)
    if newest is None:
        raise SystemExit(f"No PNG files found in {Path(args.temp_dir).resolve()}")

    headers = {}
    if auth_header and auth_value:
        headers[auth_header] = auth_value

    data = {}
    if include_meta_fields:
        data = {"source": "tools/upload_latest_png.py", "filename": newest.name}

    png_bytes = newest.read_bytes()
    files = {
        (file_field or "file"): (
            newest.name,
            png_bytes,
            "image/png",
        )
    }

    resp = requests.post(endpoint, data=data, files=files, headers=headers, timeout=args.timeout)
    print(f"POST {endpoint} -> {resp.status_code}")
    if resp.status_code >= 400:
        print(f"Request headers: {_redacted_headers(headers)}")
        try:
            body = resp.text
        except Exception:
            body = "<unreadable response body>"
        if body and len(body) > 2000:
            body = body[:2000] + "...<truncated>"
        if body:
            print(f"Response body: {body}")
    resp.raise_for_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
