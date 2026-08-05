import datetime as _dt
import hashlib
import io
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import fitz  # PyMuPDF
import requests
from dotenv import load_dotenv
from PIL import Image, ImageColor, ImageOps


logger = logging.getLogger("ipp")
_PROCESS_STARTED_MONOTONIC = time.monotonic()
_MAX_TARGET_PIXELS = 100_000_000
_BUILT_IN_MEDIA_PROFILES = (
    {
        "media_id": "open-paper-l-13.3-inch",
        "display_name": "Open Paper L (13.3 inch)",
        "width": 1200,
        "height": 1600,
        "fit": "contain",
        "auto_rotate": False,
        "background": "#ffffff",
    },
    {
        "media_id": "openpaper-7-7.3-inch",
        "display_name": "OpenPaper 7 (7.3 inch)",
        "width": 480,
        "height": 800,
        "fit": "contain",
        "auto_rotate": False,
        "background": "#ffffff",
    },
)
_JOB_LAYOUT_FIELDS = (
    "media",
    "media-key",
    "media-size-name",
    "media-x-dimension",
    "media-y-dimension",
    "orientation-requested",
)
_STANDARD_MEDIA_MARGIN = 300  # 3 mm, expressed in hundredths of a millimetre


def _utc_timestamp_compact() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _resolve_endpoint_template(endpoint: str, paper_id: str) -> str:
    if not endpoint or not paper_id:
        return endpoint
    # Support a few common placeholder styles.
    placeholders = ("<paperId>", "{PAPER_ID}", "{paper_id}")
    if any(p in endpoint for p in placeholders):
        return (
            endpoint.replace("<paperId>", paper_id)
            .replace("{PAPER_ID}", paper_id)
            .replace("{paper_id}", paper_id)
        )

    # If no placeholder is present, treat POST_ENDPOINT as a base URL and
    # append the paper_id as the final path segment.
    parts = urlsplit(endpoint)
    existing_path = parts.path or ""
    normalized_existing = existing_path.rstrip("/")
    candidate_path = normalized_existing + "/" + paper_id

    # Avoid double-appending if it's already present.
    if normalized_existing.endswith("/" + paper_id) or normalized_existing == paper_id:
        candidate_path = existing_path

    return urlunsplit((parts.scheme, parts.netloc, candidate_path, parts.query, parts.fragment))


def _split_ipp_path_and_overrides(raw_path: str, ipp_base_path: str) -> Tuple[Optional[str], Dict[str, str], str]:
    """Return (path_only, overrides, safe_path_for_logs).

    Accepts:
    - /ipp/print
    - /ipp/print?paper_id=123&auth_value=TOKEN
    - /ipp/print/123
    - /ipp/print/123/TOKEN
    - /ipp/print/job/<id>  (from Create-Job job-uri)
    """
    parts = urlsplit(raw_path)
    path_only = parts.path or ""

    if path_only != ipp_base_path and not path_only.startswith(ipp_base_path.rstrip("/") + "/"):
        return None, {}, raw_path

    qs = parse_qs(parts.query or "", keep_blank_values=True)

    def _first(qname: str) -> str:
        values = qs.get(qname)
        if not values:
            return ""
        return (values[0] or "").strip()

    overrides: Dict[str, str] = {}

    # Query params (preferred)
    # Note: accept both snake_case and a few historical/alternate spellings.
    # Some systems refer to these as PAPER_ID / AUTH_VALUE (waitlist-style).
    paper_id_q = _first("paper_id") or _first("paperId") or _first("paper") or _first("PAPER_ID")
    auth_value_q = _first("auth_value") or _first("token") or _first("auth") or _first("AUTH_VALUE")
    if paper_id_q:
        overrides["paper_id"] = paper_id_q
    if auth_value_q:
        overrides["auth_value"] = auth_value_q

    # Optional path segments after the base path.
    remainder = path_only[len(ipp_base_path) :]
    remainder = remainder.lstrip("/")
    if remainder and not remainder.startswith("job/"):
        segs = [unquote(s) for s in remainder.split("/") if s]
        if segs and "paper_id" not in overrides:
            overrides["paper_id"] = segs[0].strip()
        if len(segs) >= 2 and "auth_value" not in overrides:
            overrides["auth_value"] = segs[1].strip()

    # Redact secrets in logs (never log auth_value/token). The second custom
    # path segment carries the API credential, so it must be redacted too.
    safe_path_only = path_only
    if remainder and not remainder.startswith("job/"):
        raw_segments = [segment for segment in remainder.split("/") if segment]
        if len(raw_segments) >= 2:
            safe_segments = [raw_segments[0], "<redacted>", *raw_segments[2:]]
            safe_path_only = ipp_base_path.rstrip("/") + "/" + "/".join(safe_segments)

    safe_query_parts = []
    for k, v in qs.items():
        lk = k.lower()
        if lk in {"auth_value", "token", "auth"}:
            safe_query_parts.append(f"{k}=<redacted>")
        else:
            safe_query_parts.append(f"{k}={v[0] if v else ''}")
    safe_query = "&".join(safe_query_parts)
    safe_path_for_logs = safe_path_only + (("?" + safe_query) if safe_query else "")
    return path_only, overrides, safe_path_for_logs


def _ipp_uri_resource(uri: str) -> str:
    """Return the path/query portion of an IPP URI, or an empty string."""
    if not uri:
        return ""
    parts = urlsplit(uri)
    path = parts.path or ""
    if not path:
        return ""
    return path + (("?" + parts.query) if parts.query else "")


def _overrides_from_ipp_uri(uri: str, ipp_base_path: str) -> Dict[str, str]:
    resource = _ipp_uri_resource(uri)
    if not resource:
        return {}
    _, overrides, _ = _split_ipp_path_and_overrides(resource, ipp_base_path)
    return overrides


def _merge_overrides(primary: Dict[str, str], fallback: Dict[str, str]) -> Dict[str, str]:
    merged = dict(primary)
    for key in ("paper_id", "auth_value"):
        if not (merged.get(key) or "").strip():
            value = (fallback.get(key) or "").strip()
            if value:
                merged[key] = value
    return merged


def _redact_http_request_line(request_line: str, ipp_base_path: str) -> str:
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return request_line
    path_only, _, safe_path = _split_ipp_path_and_overrides(parts[1], ipp_base_path)
    if path_only is None:
        return request_line
    parts[1] = safe_path
    return " ".join(parts)


def _external_ipp_uri(headers, request_path: str, ipp_base_path: str, ipp_printer_uri: str = "") -> str:
    """Build the canonical externally reachable URI returned to IPP clients.

    Reverse proxies terminate TLS, while the application itself sees plain HTTP.
    Windows can also POST to the conventional base path while retaining the full
    configured resource in the IPP printer-uri attribute, so prefer the resource
    that contains per-printer routing information.
    """
    forwarded_proto = (headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip().lower()
    scheme = "ipps" if forwarded_proto in {"https", "ipps"} else "ipp"
    host = (
        (headers.get("X-Forwarded-Host") or "").split(",", 1)[0].strip()
        or (headers.get("Host") or "").strip()
        or "127.0.0.1"
    )

    request_resource = _ipp_uri_resource(request_path) or ipp_base_path
    ipp_resource = _ipp_uri_resource(ipp_printer_uri)

    def _valid(resource: str) -> bool:
        path = urlsplit(resource).path or ""
        base = ipp_base_path.rstrip("/")
        return path == ipp_base_path or path.startswith(base + "/")

    resource = request_resource if _valid(request_resource) else ipp_base_path
    if _valid(ipp_resource):
        _, request_overrides, _ = _split_ipp_path_and_overrides(resource, ipp_base_path)
        _, ipp_overrides, _ = _split_ipp_path_and_overrides(ipp_resource, ipp_base_path)
        if ipp_overrides and not request_overrides:
            resource = ipp_resource

    return f"{scheme}://{host}{resource}"


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


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


def _parse_target_profiles(raw: str) -> Dict[str, Dict[str, object]]:
    """Parse and validate per-paper output profiles from JSON."""
    if not (raw or "").strip():
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"IPP_TARGET_PROFILES must be valid JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("IPP_TARGET_PROFILES must be a JSON object keyed by paper ID")

    profiles: Dict[str, Dict[str, object]] = {}
    for raw_paper_id, raw_profile in decoded.items():
        paper_id = str(raw_paper_id).strip()
        if not paper_id:
            raise ValueError("IPP_TARGET_PROFILES contains an empty paper ID")
        if not isinstance(raw_profile, dict):
            raise ValueError(f"Target profile {paper_id!r} must be a JSON object")

        raw_width = raw_profile.get("width")
        raw_height = raw_profile.get("height")
        if isinstance(raw_width, bool) or isinstance(raw_height, bool):
            raise ValueError(f"Target profile {paper_id!r} width/height must be integers")
        try:
            width = int(raw_width)
            height = int(raw_height)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Target profile {paper_id!r} width/height must be integers") from exc
        if width <= 0 or height <= 0:
            raise ValueError(f"Target profile {paper_id!r} width/height must be positive")
        if width > 20_000 or height > 20_000 or width * height > _MAX_TARGET_PIXELS:
            raise ValueError(f"Target profile {paper_id!r} dimensions are too large")

        fit = str(raw_profile.get("fit", "contain")).strip().lower()
        if fit not in {"contain", "cover", "stretch"}:
            raise ValueError(f"Target profile {paper_id!r} fit must be contain, cover, or stretch")

        auto_rotate = raw_profile.get("auto_rotate", False)
        if not isinstance(auto_rotate, bool):
            raise ValueError(f"Target profile {paper_id!r} auto_rotate must be true or false")

        background = str(raw_profile.get("background", "#ffffff")).strip()
        try:
            background_rgb = ImageColor.getrgb(background)
        except ValueError as exc:
            raise ValueError(f"Target profile {paper_id!r} has an invalid background color") from exc
        if len(background_rgb) != 3:
            raise ValueError(f"Target profile {paper_id!r} background must be an opaque color")

        profiles[paper_id] = {
            "width": width,
            "height": height,
            "fit": fit,
            "auto_rotate": auto_rotate,
            "background": background,
        }
    return profiles


def _target_profile_for_paper_id(
    profiles: Dict[str, Dict[str, object]], paper_id: str
) -> Optional[Dict[str, object]]:
    profile = profiles.get((paper_id or "").strip()) or profiles.get("*")
    return dict(profile) if profile else None


def _target_media_definition(profile: Dict[str, object], dpi: int) -> Tuple[str, list[Tuple[str, int, object]]]:
    width = int(profile["width"])
    height = int(profile["height"])
    effective_dpi = max(1, int(dpi))
    width_hundredths_mm = max(1, round(width * 2540 / effective_dpi))
    height_hundredths_mm = max(1, round(height * 2540 / effective_dpi))
    width_mm = width_hundredths_mm / 100
    height_mm = height_hundredths_mm / 100
    raw_media_id = str(profile.get("media_id") or f"{width}x{height}").strip().lower()
    media_id = re.sub(r"[^a-z0-9.-]+", "-", raw_media_id).strip("-") or f"{width}x{height}"
    media_name = f"custom_{media_id}_{width_mm:.2f}x{height_mm:.2f}mm"
    return media_name, [
        ("x-dimension", VT_INTEGER, width_hundredths_mm),
        ("y-dimension", VT_INTEGER, height_hundredths_mm),
    ]


def _selectable_target_profiles(
    default_profile: Optional[Dict[str, object]] = None,
) -> list[Dict[str, object]]:
    base_profiles = [dict(profile) for profile in _BUILT_IN_MEDIA_PROFILES]
    if default_profile:
        default_size = (int(default_profile["width"]), int(default_profile["height"]))
        for index, profile in enumerate(base_profiles):
            if (int(profile["width"]), int(profile["height"])) == default_size:
                merged = dict(profile)
                merged.update(default_profile)
                base_profiles[index] = merged
                base_profiles.insert(0, base_profiles.pop(index))
                break
        else:
            custom = dict(default_profile)
            custom.setdefault("display_name", f"{default_size[0]}×{default_size[1]}")
            base_profiles.insert(0, custom)

    profiles: list[Dict[str, object]] = []
    for base in base_profiles:
        base_media_id = str(base.get("media_id") or f"{base['width']}x{base['height']}")
        base_display_name = str(
            base.get("display_name") or f"{base['width']}×{base['height']}"
        )
        standard = dict(base)
        standard["borderless"] = False
        standard["media_margin"] = _STANDARD_MEDIA_MARGIN
        profiles.append(standard)

        borderless = dict(base)
        borderless["borderless"] = True
        borderless["media_margin"] = 0
        borderless["media_id"] = f"{base_media_id}.borderless"
        borderless["display_name"] = f"{base_display_name} – Randlos"
        profiles.append(borderless)
    return profiles


def _target_profile_for_job(
    meta: Dict[str, str],
    dpi: int,
    default_profile: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    profiles = _selectable_target_profiles(default_profile)
    selected_names = {
        (meta.get(field) or "").strip().lower()
        for field in ("media", "media-key", "media-size-name")
        if (meta.get(field) or "").strip()
    }
    if selected_names:
        for profile in profiles:
            media_name, _ = _target_media_definition(profile, dpi)
            if media_name.lower() in selected_names:
                return dict(profile)

    try:
        selected_size = (
            int(meta.get("media-x-dimension") or "0"),
            int(meta.get("media-y-dimension") or "0"),
        )
    except ValueError:
        selected_size = (0, 0)
    if selected_size != (0, 0):
        for profile in profiles:
            _, size = _target_media_definition(profile, dpi)
            profile_size = (int(size[0][2]), int(size[1][2]))
            if profile_size == selected_size:
                return dict(profile)

    return dict(profiles[0])


def _job_layout_context(meta: Dict[str, str]) -> Dict[str, str]:
    return {
        field: meta[field]
        for field in _JOB_LAYOUT_FIELDS
        if (meta.get(field) or "").strip()
    }


def _stored_job_context(overrides: Dict[str, str]) -> Dict[str, str]:
    context = {
        "paper_id": (overrides.get("paper_id") or "").strip(),
        "auth_value": (overrides.get("auth_value") or "").strip(),
    }
    context.update(_job_layout_context(overrides))
    return context


def _redacted_headers(headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in {"authorization", "cookie", "x-api-key", "x-ipp-token"}:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _document_debug_fields(document: bytes) -> Dict[str, object]:
    tail_window = document[-1024:] if len(document) > 1024 else document
    return {
        "bytes": len(document),
        "sha256": hashlib.sha256(document).hexdigest() if document else "",
        "first16": document[:16].hex(),
        "last16": document[-16:].hex() if document else "",
        "has_pdf_header": document.startswith(b"%PDF"),
        "has_ps_header": document.startswith(b"%!PS"),
        "has_pdf_eof": b"%%EOF" in tail_window,
        "has_startxref": b"startxref" in tail_window,
    }


def _log_document_diagnostics(prefix: str, document: bytes) -> None:
    info = _document_debug_fields(document)
    logger.debug(
        "%s bytes=%s sha256=%s first16=%s last16=%s pdf_header=%s ps_header=%s pdf_eof=%s startxref=%s",
        prefix,
        info["bytes"],
        info["sha256"],
        info["first16"],
        info["last16"],
        info["has_pdf_header"],
        info["has_ps_header"],
        info["has_pdf_eof"],
        info["has_startxref"],
    )


def _log_pdf_state(prefix: str, doc, pdf_bytes: bytes) -> None:
    metadata = getattr(doc, "metadata", None) or {}
    logger.debug(
        "%s page_count=%s needs_pass=%s is_encrypted=%s producer=%s title=%s",
        prefix,
        getattr(doc, "page_count", None),
        bool(getattr(doc, "needs_pass", False)),
        bool(getattr(doc, "is_encrypted", False)),
        (metadata.get("producer") or "")[:120],
        (metadata.get("title") or "")[:120],
    )
    _log_document_diagnostics(f"{prefix} bytes", pdf_bytes)


def _ghostscript_command() -> str:
    return shutil.which("gs") or shutil.which("ghostscript") or ""


def _pwg_raster_converter_command() -> str:
    candidates = (
        shutil.which("rastertopdf"),
        "/usr/lib/cups/filter/rastertopdf",
        "/usr/libexec/cups/filter/rastertopdf",
        shutil.which("rastertotiff"),
        "/usr/lib/cups/filter/rastertotiff",
        "/usr/libexec/cups/filter/rastertotiff",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _supported_document_formats() -> list[str]:
    formats = ["application/pdf", "image/jpeg"]
    if _pwg_raster_converter_command():
        formats.append("image/pwg-raster")
    if _ghostscript_command():
        formats.extend(["application/postscript", "application/vnd.cups-postscript"])
    return formats


def _detect_document_kind(document: bytes, meta: Dict[str, str]) -> str:
    if document.startswith(b"%PDF"):
        return "pdf"
    if document.startswith(b"%!PS"):
        return "postscript"
    if document.startswith((b"RaS2", b"RaS3", b"RaS4")):
        return "pwg-raster"
    if document.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if document.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"

    declared_format = (meta.get("document-format", "") or "").strip().lower()
    if declared_format == "application/pdf":
        return "pdf"
    if declared_format in {"application/postscript", "application/vnd.cups-postscript"}:
        return "postscript"
    if declared_format == "image/pwg-raster":
        return "pwg-raster"
    if declared_format in {"image/jpeg", "image/jpg"}:
        return "jpeg"
    if declared_format == "image/png":
        return "png"
    return "unknown"


def render_image_to_pngs(image_bytes: bytes, filetype: str) -> Tuple[int, Dict[int, bytes]]:
    doc = fitz.open(stream=image_bytes, filetype=filetype)
    try:
        total = doc.page_count
        if total <= 0:
            raise ValueError(f"{filetype.upper()} payload contains zero pages")
        pages: Dict[int, bytes] = {}
        for index in range(total):
            pix = doc.load_page(index).get_pixmap(alpha=False)
            pages[index + 1] = pix.tobytes("png")
        return total, pages
    finally:
        doc.close()


def render_pwg_raster_to_pngs(raster_bytes: bytes, dpi: int, job_name: str = "") -> Tuple[int, Dict[int, bytes]]:
    converter = _pwg_raster_converter_command()
    if not converter:
        raise ValueError(
            "PWG Raster payload received but rastertopdf/rastertotiff is not installed; "
            "install cups-filters-core-drivers"
        )

    with tempfile.TemporaryDirectory(prefix="ipp-pwg-raster-") as temp_dir:
        input_path = Path(temp_dir) / "input.pwg"
        input_path.write_bytes(raster_bytes)
        result = subprocess.run(
            [converter, "1", "paperlesspaper", job_name or "IPP job", "1", "", str(input_path)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout:
            details = (result.stderr or b"PWG Raster conversion failed").decode("utf-8", errors="replace").strip()
            raise ValueError(f"Failed to convert PWG Raster payload: {details}")

        converter_name = Path(converter).name.lower()
        if converter_name == "rastertopdf":
            return render_pdf_to_pngs(result.stdout, dpi=dpi)
        return render_image_to_pngs(result.stdout, "tiff")


def render_postscript_to_pngs(document: bytes, dpi: int) -> Tuple[int, Dict[int, bytes]]:
    gs_command = _ghostscript_command()
    if not gs_command:
        raise ValueError(
            "PostScript payload received but Ghostscript is not installed; install Ghostscript to accept Generic IPP/PostScript printer output"
        )

    with tempfile.TemporaryDirectory(prefix="ipp-postscript-") as temp_dir:
        input_path = Path(temp_dir) / "input.ps"
        output_pattern = Path(temp_dir) / "page-%04d.png"
        input_path.write_bytes(document)

        result = subprocess.run(
            [
                gs_command,
                "-q",
                "-dSAFER",
                "-dBATCH",
                "-dNOPAUSE",
                "-sDEVICE=png16m",
                f"-r{dpi}",
                f"-sOutputFile={output_pattern}",
                str(input_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        output_files = sorted(Path(temp_dir).glob("page-*.png"))
        if result.returncode != 0 or not output_files:
            details = (result.stderr or result.stdout or "Ghostscript conversion failed").strip()
            raise ValueError(f"Failed to render PostScript payload: {details}")

        pages: Dict[int, bytes] = {}
        for index, output_file in enumerate(output_files, start=1):
            pages[index] = output_file.read_bytes()
        return len(output_files), pages


def _op_name(operation_id: int) -> str:
    return {
        IPP_OP_PRINT_JOB: "Print-Job",
        IPP_OP_VALIDATE_JOB: "Validate-Job",
        IPP_OP_CREATE_JOB: "Create-Job",
        IPP_OP_SEND_DOCUMENT: "Send-Document",
        IPP_OP_CANCEL_JOB: "Cancel-Job",
        IPP_OP_GET_JOB_ATTRIBUTES: "Get-Job-Attributes",
        IPP_OP_GET_JOBS: "Get-Jobs",
        IPP_OP_GET_PRINTER_ATTRIBUTES: "Get-Printer-Attributes",
        IPP_OP_CANCEL_MY_JOBS: "Cancel-My-Jobs",
        IPP_OP_CLOSE_JOB: "Close-Job",
        IPP_OP_IDENTIFY_PRINTER: "Identify-Printer",
    }.get(operation_id, f"op-0x{operation_id:04x}")


def _read_exact(rfile, n: int) -> bytes:
    data = rfile.read(n)
    if data is None:
        return b""
    return data


def _read_chunked_body(rfile, max_bytes: int) -> bytes:
    body = bytearray()
    chunk_count = 0
    while True:
        # chunk-size line (hex) optionally followed by extensions
        line = rfile.readline(65536)
        if not line:
            raise ValueError("Incomplete chunked body: missing terminating chunk")
        line = line.strip()
        if b";" in line:
            line = line.split(b";", 1)[0]
        try:
            chunk_size = int(line.decode("ascii", errors="ignore") or "0", 16)
        except ValueError:
            raise ValueError("Invalid chunk size")
        if chunk_size == 0:
            # consume trailer headers until CRLF
            while True:
                trailer = rfile.readline(65536)
                if not trailer or trailer in {b"\r\n", b"\n"}:
                    break
            logger.debug("Finished chunked request body: chunks=%d total_bytes=%d", chunk_count, len(body))
            break
        if len(body) + chunk_size > max_bytes:
            raise ValueError("Chunked body exceeds limit")
        chunk_count += 1
        body += _read_exact(rfile, chunk_size)
        # consume CRLF
        chunk_ending = rfile.readline(3)
        if chunk_ending not in {b"\r\n", b"\n"}:
            raise ValueError("Invalid chunk terminator")
    return bytes(body)


DELIMITER_TAGS = {
    0x01,  # operation-attributes-tag
    0x02,  # job-attributes-tag
    0x03,  # end-of-attributes-tag
    0x04,  # printer-attributes-tag
    0x05,  # unsupported-attributes-tag
}


IPP_OP_PRINT_JOB = 0x0002
IPP_OP_VALIDATE_JOB = 0x0004
IPP_OP_CREATE_JOB = 0x0005
IPP_OP_SEND_DOCUMENT = 0x0006
IPP_OP_CANCEL_JOB = 0x0008
IPP_OP_GET_JOB_ATTRIBUTES = 0x0009
IPP_OP_GET_JOBS = 0x000A
IPP_OP_GET_PRINTER_ATTRIBUTES = 0x000B
IPP_OP_CANCEL_MY_JOBS = 0x0039
IPP_OP_CLOSE_JOB = 0x003B
IPP_OP_IDENTIFY_PRINTER = 0x003C


IPP_STATUS_SUCCESSFUL_OK = 0x0000
IPP_STATUS_CLIENT_ERROR_BAD_REQUEST = 0x0400
IPP_STATUS_CLIENT_ERROR_NOT_POSSIBLE = 0x0404
IPP_STATUS_SERVER_ERROR_OPERATION_NOT_SUPPORTED = 0x0501
IPP_STATUS_SERVER_ERROR_VERSION_NOT_SUPPORTED = 0x0503


TAG_OPERATION_ATTRIBUTES = 0x01
TAG_PRINTER_ATTRIBUTES = 0x04
TAG_END_OF_ATTRIBUTES = 0x03


VT_TEXT_WITHOUT_LANGUAGE = 0x41
VT_NAME_WITHOUT_LANGUAGE = 0x42
VT_KEYWORD = 0x44
VT_URI = 0x45
VT_CHARSET = 0x47
VT_NATURAL_LANGUAGE = 0x48
VT_MIME_MEDIA_TYPE = 0x49
VT_BOOLEAN = 0x22
VT_INTEGER = 0x21
VT_ENUM = 0x23
VT_OCTET_STRING = 0x30
VT_DATETIME = 0x31
VT_RESOLUTION = 0x32
VT_RANGE_OF_INTEGER = 0x33
VT_BEGIN_COLLECTION = 0x34
VT_END_COLLECTION = 0x37
VT_URI_SCHEME = 0x46
VT_MEMBER_ATTR_NAME = 0x4A


def _ipp_attr(tag: int, name: str, value: bytes) -> bytes:
    name_b = name.encode("utf-8")
    return bytes([tag]) + struct.pack(">H", len(name_b)) + name_b + struct.pack(">H", len(value)) + value


def _ipp_attr_str(tag: int, name: str, value: str) -> bytes:
    return _ipp_attr(tag, name, value.encode("utf-8"))


def _ipp_attr_bool(name: str, value: bool) -> bytes:
    return _ipp_attr(VT_BOOLEAN, name, b"\x01" if value else b"\x00")


def _ipp_attr_i32(tag: int, name: str, value: int) -> bytes:
    return _ipp_attr(tag, name, struct.pack(">i", int(value)))


def _ipp_attr_i32_set(tag: int, name: str, values: list[int]) -> bytes:
    if not values:
        return b""
    out = bytearray()
    first = True
    for v in values:
        if first:
            out += _ipp_attr(tag, name, struct.pack(">i", int(v)))
            first = False
        else:
            # additional value: name-length = 0
            out += bytes([tag]) + struct.pack(">H", 0) + struct.pack(">H", 4) + struct.pack(">i", int(v))
    return bytes(out)


def _ipp_attr_range(name: str, lower: int, upper: int) -> bytes:
    return _ipp_attr(VT_RANGE_OF_INTEGER, name, struct.pack(">ii", int(lower), int(upper)))


def _ipp_attr_resolution(name: str, xdpi: int, ydpi: int, units: int = 3) -> bytes:
    return _ipp_attr(VT_RESOLUTION, name, struct.pack(">iiB", int(xdpi), int(ydpi), int(units)))


def _ipp_attr_datetime(name: str, value: _dt.datetime) -> bytes:
    current = value.astimezone(_dt.UTC)
    encoded = struct.pack(
        ">HBBBBBBcBB",
        current.year,
        current.month,
        current.day,
        current.hour,
        current.minute,
        current.second,
        0,
        b"+",
        0,
        0,
    )
    return _ipp_attr(VT_DATETIME, name, encoded)


def _ipp_collection(name: str, members: list[Tuple[str, int, object]]) -> bytes:
    out = bytearray(_ipp_attr(VT_BEGIN_COLLECTION, name, b""))
    for member_name, tag, value in members:
        out += _ipp_attr(VT_MEMBER_ATTR_NAME, "", member_name.encode("utf-8"))
        if tag == VT_BEGIN_COLLECTION:
            out += _ipp_collection("", value)  # type: ignore[arg-type]
        elif isinstance(value, int):
            out += _ipp_attr(tag, "", struct.pack(">i", value))
        elif isinstance(value, bytes):
            out += _ipp_attr(tag, "", value)
        else:
            out += _ipp_attr(tag, "", str(value).encode("utf-8"))
    out += _ipp_attr(VT_END_COLLECTION, "", b"")
    return bytes(out)


def _ipp_collection_set(name: str, collections: list[list[Tuple[str, int, object]]]) -> bytes:
    out = bytearray()
    for index, members in enumerate(collections):
        out += _ipp_collection(name if index == 0 else "", members)
    return bytes(out)


def _ipp_attr_str_set(tag: int, name: str, values: list[str]) -> bytes:
    if not values:
        return b""
    out = bytearray()
    first = True
    for v in values:
        value_b = (v or "").encode("utf-8")
        if first:
            out += _ipp_attr(tag, name, value_b)
            first = False
        else:
            # additional value: name-length = 0
            out += bytes([tag]) + struct.pack(">H", 0) + struct.pack(">H", len(value_b)) + value_b
    return bytes(out)


def build_ipp_response(status_code: int, request_id: int, attribute_bytes: bytes) -> bytes:
    return build_ipp_response_with_version(1, 1, status_code, request_id, attribute_bytes)


def build_ipp_response_with_version(
    version_major: int,
    version_minor: int,
    status_code: int,
    request_id: int,
    attribute_bytes: bytes,
) -> bytes:
    response = bytearray()
    response += bytes([version_major & 0xFF, version_minor & 0xFF])
    response += struct.pack(">H", status_code)
    response += struct.pack(">I", request_id)
    response += attribute_bytes
    response += bytes([TAG_END_OF_ATTRIBUTES])
    return bytes(response)


def build_get_printer_attributes_response(
    host_header: str,
    ipp_path: str,
    *,
    scheme: str = "ipp",
    printer_uri: str = "",
    requested_attributes: Optional[list[str]] = None,
    render_dpi: int = 150,
    target_profile: Optional[Dict[str, object]] = None,
) -> bytes:
    host = host_header or "127.0.0.1"
    canonical_uri = printer_uri or f"{scheme}://{host}{ipp_path}"
    security = "tls" if canonical_uri.lower().startswith("ipps://") else "none"
    http_scheme = "https" if security == "tls" else "http"
    info_uri = f"{http_scheme}://{host}/"
    printer_uuid = uuid.uuid5(uuid.NAMESPACE_URL, canonical_uri)
    up_time = max(1, int(time.monotonic() - _PROCESS_STARTED_MONOTONIC))
    now = _dt.datetime.now(_dt.UTC)

    formats = _supported_document_formats()
    supports_pwg = "image/pwg-raster" in formats
    default_format = "image/pwg-raster" if supports_pwg else "application/pdf"

    selectable_profiles = _selectable_target_profiles(target_profile)
    media_definitions = [
        (*_target_media_definition(profile, render_dpi), profile)
        for profile in selectable_profiles
    ]
    default_media_name, default_media_size, _ = media_definitions[0]
    printer_info = "paperlesspaper virtual IPP printer for Open Paper displays"

    def media_col(
        size: list[Tuple[str, int, object]],
        media_name: str,
        profile: Dict[str, object],
    ) -> list[Tuple[str, int, object]]:
        margin = int(profile.get("media_margin", 0))
        return [
            ("media-size", VT_BEGIN_COLLECTION, size),
            ("media-bottom-margin", VT_INTEGER, margin),
            ("media-left-margin", VT_INTEGER, margin),
            ("media-right-margin", VT_INTEGER, margin),
            ("media-top-margin", VT_INTEGER, margin),
            ("media-source", VT_KEYWORD, "auto"),
            ("media-type", VT_KEYWORD, "stationery"),
            ("media-key", VT_KEYWORD, media_name),
            (
                "media-info",
                VT_TEXT_WITHOUT_LANGUAGE,
                str(profile.get("display_name") or f"{profile['width']}×{profile['height']}"),
            ),
            ("media-size-name", VT_KEYWORD, media_name),
        ]

    attributes: list[Tuple[str, bytes]] = []

    def add(name: str, encoded: bytes) -> None:
        attributes.append((name, encoded))

    add("printer-uri-supported", _ipp_attr_str(VT_URI, "printer-uri-supported", canonical_uri))
    add("uri-authentication-supported", _ipp_attr_str(VT_KEYWORD, "uri-authentication-supported", "none"))
    add("uri-security-supported", _ipp_attr_str(VT_KEYWORD, "uri-security-supported", security))
    add("printer-name", _ipp_attr_str(VT_NAME_WITHOUT_LANGUAGE, "printer-name", "paperlesspaper"))
    add("printer-info", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-info", printer_info))
    add("printer-location", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-location", "Cloud"))
    add("printer-geo-location", _ipp_attr_str(VT_URI, "printer-geo-location", "geo:0,0"))
    add("printer-make-and-model", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-make-and-model", "paperlesspaper IPP Printer"))
    add("printer-more-info", _ipp_attr_str(VT_URI, "printer-more-info", info_uri))
    add("printer-icons", _ipp_attr_str(VT_URI, "printer-icons", f"{info_uri.rstrip('/')}/favicon.ico"))
    add("printer-uuid", _ipp_attr_str(VT_URI, "printer-uuid", f"urn:uuid:{printer_uuid}"))
    add(
        "printer-device-id",
        _ipp_attr_str(
            VT_TEXT_WITHOUT_LANGUAGE,
            "printer-device-id",
            "MFG:paperlesspaper;MDL:Virtual IPP Printer;CMD:PDF,PWG-Raster,JPEG,POSTSCRIPT;",
        ),
    )
    add("ipp-versions-supported", _ipp_attr_str_set(VT_KEYWORD, "ipp-versions-supported", ["1.1", "2.0"]))
    if supports_pwg:
        add("ipp-features-supported", _ipp_attr_str(VT_KEYWORD, "ipp-features-supported", "ipp-everywhere"))
    add(
        "operations-supported",
        _ipp_attr_i32_set(
            VT_ENUM,
            "operations-supported",
            [
                IPP_OP_PRINT_JOB,
                IPP_OP_VALIDATE_JOB,
                IPP_OP_CREATE_JOB,
                IPP_OP_SEND_DOCUMENT,
                IPP_OP_CANCEL_JOB,
                IPP_OP_GET_JOB_ATTRIBUTES,
                IPP_OP_GET_JOBS,
                IPP_OP_GET_PRINTER_ATTRIBUTES,
                IPP_OP_CANCEL_MY_JOBS,
                IPP_OP_CLOSE_JOB,
                IPP_OP_IDENTIFY_PRINTER,
            ],
        ),
    )
    add("charset-configured", _ipp_attr_str(VT_CHARSET, "charset-configured", "utf-8"))
    add("charset-supported", _ipp_attr_str(VT_CHARSET, "charset-supported", "utf-8"))
    add("natural-language-configured", _ipp_attr_str(VT_NATURAL_LANGUAGE, "natural-language-configured", "en"))
    add("generated-natural-language-supported", _ipp_attr_str(VT_NATURAL_LANGUAGE, "generated-natural-language-supported", "en"))
    add("printer-is-accepting-jobs", _ipp_attr_bool("printer-is-accepting-jobs", True))
    add("printer-state", _ipp_attr_i32(VT_ENUM, "printer-state", 3))
    add("printer-state-reasons", _ipp_attr_str(VT_KEYWORD, "printer-state-reasons", "none"))
    add("queued-job-count", _ipp_attr_i32(VT_INTEGER, "queued-job-count", 0))
    add("printer-up-time", _ipp_attr_i32(VT_INTEGER, "printer-up-time", up_time))
    add("printer-config-change-time", _ipp_attr_i32(VT_INTEGER, "printer-config-change-time", 0))
    add("printer-config-change-date-time", _ipp_attr_datetime("printer-config-change-date-time", now))
    add("printer-state-change-time", _ipp_attr_i32(VT_INTEGER, "printer-state-change-time", 0))
    add("printer-state-change-date-time", _ipp_attr_datetime("printer-state-change-date-time", now))
    add("document-format-default", _ipp_attr_str(VT_MIME_MEDIA_TYPE, "document-format-default", default_format))
    add("document-format-supported", _ipp_attr_str_set(VT_MIME_MEDIA_TYPE, "document-format-supported", formats))
    add("compression-supported", _ipp_attr_str(VT_KEYWORD, "compression-supported", "none"))
    add("pdl-override-supported", _ipp_attr_str(VT_KEYWORD, "pdl-override-supported", "attempted"))
    add("printer-get-attributes-supported", _ipp_attr_str(VT_KEYWORD, "printer-get-attributes-supported", "document-format"))
    add("job-ids-supported", _ipp_attr_bool("job-ids-supported", True))
    add("multiple-document-jobs-supported", _ipp_attr_bool("multiple-document-jobs-supported", False))
    add("multiple-operation-time-out", _ipp_attr_i32(VT_INTEGER, "multiple-operation-time-out", 30))
    add("multiple-operation-time-out-action", _ipp_attr_str(VT_KEYWORD, "multiple-operation-time-out-action", "process-job"))
    add("overrides-supported", _ipp_attr_str_set(VT_KEYWORD, "overrides-supported", ["document-number", "pages"]))
    add("which-jobs-supported", _ipp_attr_str_set(VT_KEYWORD, "which-jobs-supported", ["completed", "not-completed", "all"]))
    add("preferred-attributes-supported", _ipp_attr_bool("preferred-attributes-supported", False))
    add(
        "job-creation-attributes-supported",
        _ipp_attr_str_set(
            VT_KEYWORD,
            "job-creation-attributes-supported",
            [
                "copies",
                "finishings",
                "ipp-attribute-fidelity",
                "job-name",
                "media",
                "media-col",
                "orientation-requested",
                "output-bin",
                "page-ranges",
                "print-color-mode",
                "print-quality",
                "printer-resolution",
                "requesting-user-name",
                "sides",
            ],
        ),
    )
    add("copies-default", _ipp_attr_i32(VT_INTEGER, "copies-default", 1))
    add("copies-supported", _ipp_attr_range("copies-supported", 1, 1))
    add("finishings-default", _ipp_attr_i32(VT_ENUM, "finishings-default", 3))
    add("finishings-supported", _ipp_attr_i32(VT_ENUM, "finishings-supported", 3))
    add("media-default", _ipp_attr_str(VT_KEYWORD, "media-default", default_media_name))
    add(
        "media-supported",
        _ipp_attr_str_set(VT_KEYWORD, "media-supported", [name for name, _, _ in media_definitions]),
    )
    add("media-ready", _ipp_attr_str(VT_KEYWORD, "media-ready", default_media_name))
    add(
        "media-col-default",
        _ipp_collection(
            "media-col-default",
            media_col(default_media_size, default_media_name, media_definitions[0][2]),
        ),
    )
    add(
        "media-col-ready",
        _ipp_collection(
            "media-col-ready",
            media_col(default_media_size, default_media_name, media_definitions[0][2]),
        ),
    )
    add(
        "media-col-database",
        _ipp_collection_set(
            "media-col-database",
            [media_col(size, name, profile) for name, size, profile in media_definitions],
        ),
    )
    add(
        "media-col-supported",
        _ipp_attr_str_set(
            VT_KEYWORD,
            "media-col-supported",
            [
                "media-size",
                "media-source",
                "media-type",
                "media-key",
                "media-info",
                "media-size-name",
                "media-bottom-margin",
                "media-left-margin",
                "media-right-margin",
                "media-top-margin",
            ],
        ),
    )
    add(
        "media-size-supported",
        _ipp_collection_set(
            "media-size-supported",
            [
                size
                for index, (_, size, _) in enumerate(media_definitions)
                if (int(size[0][2]), int(size[1][2]))
                not in {
                    (int(previous[1][0][2]), int(previous[1][1][2]))
                    for previous in media_definitions[:index]
                }
            ],
        ),
    )
    for margin in ("bottom", "left", "right", "top"):
        name = f"media-{margin}-margin-supported"
        add(name, _ipp_attr_i32_set(VT_INTEGER, name, [0, _STANDARD_MEDIA_MARGIN]))
    add("media-source-supported", _ipp_attr_str(VT_KEYWORD, "media-source-supported", "auto"))
    add("media-type-supported", _ipp_attr_str(VT_KEYWORD, "media-type-supported", "stationery"))
    add("orientation-requested-default", _ipp_attr_i32(VT_ENUM, "orientation-requested-default", 3))
    add("orientation-requested-supported", _ipp_attr_i32_set(VT_ENUM, "orientation-requested-supported", [3, 4, 5, 6]))
    add("output-bin-default", _ipp_attr_str(VT_KEYWORD, "output-bin-default", "face-down"))
    add("output-bin-supported", _ipp_attr_str(VT_KEYWORD, "output-bin-supported", "face-down"))
    add("print-quality-default", _ipp_attr_i32(VT_ENUM, "print-quality-default", 4))
    add("print-quality-supported", _ipp_attr_i32_set(VT_ENUM, "print-quality-supported", [3, 4, 5]))
    add("printer-resolution-default", _ipp_attr_resolution("printer-resolution-default", render_dpi, render_dpi))
    add("printer-resolution-supported", _ipp_attr_resolution("printer-resolution-supported", render_dpi, render_dpi))
    add("sides-default", _ipp_attr_str(VT_KEYWORD, "sides-default", "one-sided"))
    add("sides-supported", _ipp_attr_str(VT_KEYWORD, "sides-supported", "one-sided"))
    add("page-ranges-supported", _ipp_attr_bool("page-ranges-supported", True))
    add("color-supported", _ipp_attr_bool("color-supported", True))
    add("print-color-mode-supported", _ipp_attr_str_set(VT_KEYWORD, "print-color-mode-supported", ["auto", "color", "monochrome"]))
    add("print-color-mode-default", _ipp_attr_str(VT_KEYWORD, "print-color-mode-default", "auto"))
    add("output-mode-supported", _ipp_attr_str_set(VT_KEYWORD, "output-mode-supported", ["auto", "color", "monochrome"]))
    add("output-mode-default", _ipp_attr_str(VT_KEYWORD, "output-mode-default", "auto"))
    add("print-content-optimize-default", _ipp_attr_str(VT_KEYWORD, "print-content-optimize-default", "auto"))
    add("print-content-optimize-supported", _ipp_attr_str_set(VT_KEYWORD, "print-content-optimize-supported", ["auto", "graphic", "photo", "text", "text-and-graphic"]))
    add("print-rendering-intent-default", _ipp_attr_str(VT_KEYWORD, "print-rendering-intent-default", "auto"))
    add("print-rendering-intent-supported", _ipp_attr_str_set(VT_KEYWORD, "print-rendering-intent-supported", ["auto", "perceptual", "relative", "saturation"]))
    add("pages-per-minute", _ipp_attr_i32(VT_INTEGER, "pages-per-minute", 1))
    add("pages-per-minute-color", _ipp_attr_i32(VT_INTEGER, "pages-per-minute-color", 1))
    add("identify-actions-default", _ipp_attr_str(VT_KEYWORD, "identify-actions-default", "display"))
    add("identify-actions-supported", _ipp_attr_str(VT_KEYWORD, "identify-actions-supported", "display"))
    add("printer-organization", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-organization", "paperlesspaper"))
    add("printer-organizational-unit", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-organizational-unit", "IPP service"))
    add(
        "printer-supply",
        _ipp_attr_str(
            VT_OCTET_STRING,
            "printer-supply",
            "index=1;class=supplyThatIsConsumed;type=ink;unit=percent;maxcapacity=100;level=100;colorantname=none;",
        ),
    )
    add("printer-supply-description", _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-supply-description", "Virtual supply"))
    add("printer-supply-info-uri", _ipp_attr_str(VT_URI, "printer-supply-info-uri", info_uri))
    if supports_pwg:
        add("pwg-raster-document-resolution-supported", _ipp_attr_resolution("pwg-raster-document-resolution-supported", render_dpi, render_dpi))
        add("pwg-raster-document-sheet-back", _ipp_attr_str(VT_KEYWORD, "pwg-raster-document-sheet-back", "normal"))
        add("pwg-raster-document-type-supported", _ipp_attr_str_set(VT_KEYWORD, "pwg-raster-document-type-supported", ["sgray_8", "srgb_8"]))

    requested = {value for value in (requested_attributes or []) if value}
    if requested and "all" not in requested:
        if "printer-description" not in requested and "job-template" not in requested:
            attributes = [(name, encoded) for name, encoded in attributes if name in requested]

    attrs = bytearray(build_operation_attributes())
    attrs += bytes([TAG_PRINTER_ATTRIBUTES])
    for _, encoded in attributes:
        attrs += encoded
    return bytes(attrs)


def build_operation_attributes() -> bytes:
    attrs = bytearray()
    attrs += bytes([TAG_OPERATION_ATTRIBUTES])
    attrs += _ipp_attr_str(VT_CHARSET, "attributes-charset", "utf-8")
    attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "attributes-natural-language", "en")
    return bytes(attrs)


def _job_attributes(
    printer_uri: str,
    job_id: int,
    job_state: int,
    job_name: str = "IPP job",
    requested_attributes: Optional[list[str]] = None,
    default_minimal: bool = False,
) -> bytes:
    attributes = [
        ("job-id", _ipp_attr_i32(VT_INTEGER, "job-id", job_id)),
        ("job-uri", _ipp_attr_str(VT_URI, "job-uri", f"{printer_uri.rstrip('/')}/job/{job_id}")),
        ("job-printer-uri", _ipp_attr_str(VT_URI, "job-printer-uri", printer_uri)),
        ("job-name", _ipp_attr_str(VT_NAME_WITHOUT_LANGUAGE, "job-name", job_name or "IPP job")),
        (
            "job-originating-user-name",
            _ipp_attr_str(VT_NAME_WITHOUT_LANGUAGE, "job-originating-user-name", "anonymous"),
        ),
        ("job-state", _ipp_attr_i32(VT_ENUM, "job-state", job_state)),
        ("job-state-reasons", _ipp_attr_str(VT_KEYWORD, "job-state-reasons", "none")),
        ("time-at-creation", _ipp_attr_i32(VT_INTEGER, "time-at-creation", 0)),
        ("time-at-processing", _ipp_attr_i32(VT_INTEGER, "time-at-processing", 0)),
        (
            "time-at-completed",
            _ipp_attr_i32(VT_INTEGER, "time-at-completed", 0 if job_state != 9 else 1),
        ),
        (
            "job-printer-up-time",
            _ipp_attr_i32(
                VT_INTEGER,
                "job-printer-up-time",
                max(1, int(time.monotonic() - _PROCESS_STARTED_MONOTONIC)),
            ),
        ),
    ]
    requested = {name for name in (requested_attributes or []) if name}
    if requested and "all" not in requested:
        attributes = [(name, value) for name, value in attributes if name in requested]
    elif not requested and default_minimal:
        attributes = [(name, value) for name, value in attributes if name in {"job-id", "job-uri"}]
    return b"".join(value for _, value in attributes)


def build_get_job_attributes_response(
    host_header: str,
    ipp_path: str,
    job_id: int,
    job_state: int,
    printer_uri: str = "",
) -> bytes:
    host = host_header or "127.0.0.1"
    canonical_uri = printer_uri or f"ipp://{host}{ipp_path}"
    attrs = bytearray(build_operation_attributes())
    if job_id > 0:
        attrs += bytes([0x02])  # job-attributes-tag
        attrs += _job_attributes(canonical_uri, job_id, job_state)
    return bytes(attrs)


def build_get_jobs_response(
    host_header: str,
    ipp_path: str,
    jobs: list[Tuple[int, int]],
    printer_uri: str = "",
    requested_attributes: Optional[list[str]] = None,
) -> bytes:
    host = host_header or "127.0.0.1"
    canonical_uri = printer_uri or f"ipp://{host}{ipp_path}"
    attrs = bytearray(build_operation_attributes())
    for job_id, job_state in jobs:
        attrs += bytes([0x02])  # job-attributes-tag
        attrs += _job_attributes(
            canonical_uri,
            job_id,
            job_state,
            requested_attributes=requested_attributes,
            default_minimal=True,
        )
    return bytes(attrs)


def parse_ipp_request(raw: bytes) -> Tuple[Dict[str, str], bytes]:
    """Extract minimal metadata and the document bytes from an IPP request.

    For Print-Job, document data follows immediately after the end-of-attributes tag (0x03).
    We parse enough of the attribute stream to find that boundary and a couple of common fields.
    """
    if len(raw) < 8:
        raise ValueError("IPP request too short")

    version_major = raw[0]
    version_minor = raw[1]
    operation_id = struct.unpack(">H", raw[2:4])[0]
    request_id = struct.unpack(">I", raw[4:8])[0]

    meta: Dict[str, str] = {
        "ipp_version": f"{version_major}.{version_minor}",
        "ipp_version_major": str(version_major),
        "ipp_version_minor": str(version_minor),
        "operation_id": str(operation_id),
        "request_id": str(request_id),
    }

    pos = 8
    current_group = None
    operation_attribute_names: list[str] = []
    collection_depth = 0
    current_member_name = ""

    def _read_u16() -> int:
        nonlocal pos
        if pos + 2 > len(raw):
            raise ValueError("IPP truncated (u16)")
        value = struct.unpack(">H", raw[pos : pos + 2])[0]
        pos += 2
        return value

    def _read_bytes(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(raw):
            raise ValueError("IPP truncated (bytes)")
        b = raw[pos : pos + n]
        pos += n
        return b

    last_name: Optional[bytes] = None

    while pos < len(raw):
        tag = raw[pos]
        pos += 1

        if tag in DELIMITER_TAGS:
            if tag == 0x03:
                # End of attributes: remainder is document data
                break
            current_group = tag
            continue

        # value-tag: name-length (2), name, value-length (2), value
        name_len = _read_u16()
        if name_len == 0:
            # additional value for previous attribute
            if last_name is None:
                raise ValueError("IPP additional value without previous name")
            name = last_name
        else:
            name = _read_bytes(name_len)
            last_name = name

        value_len = _read_u16()
        value = _read_bytes(value_len)

        # Collection members use memberAttrName followed by an unnamed value.
        # Preserve the semantic member name so media-col selections from
        # Windows/macOS/CUPS can drive exact output sizing.
        name_str = name.decode("utf-8", errors="ignore")
        semantic_name = name_str
        if tag == VT_MEMBER_ATTR_NAME:
            current_member_name = value.decode("utf-8", errors="ignore")
            continue
        if collection_depth and name_len == 0 and current_member_name:
            semantic_name = current_member_name
            current_member_name = ""

        if tag == VT_BEGIN_COLLECTION:
            collection_depth += 1
        elif tag == VT_END_COLLECTION:
            collection_depth = max(0, collection_depth - 1)

        if current_group == 0x01 and name_len > 0:
            operation_attribute_names.append(name_str)
        if semantic_name in {
            "compression",
            "document-format",
            "document-name",
            "job-name",
            "job-uri",
            "printer-uri",
            "requesting-user-name",
            "requested-attributes",
            "which-jobs",
            "media",
            "media-key",
            "media-size-name",
        }:
            decoded = value.decode("utf-8", errors="ignore")
            if semantic_name == "requested-attributes" and meta.get(semantic_name):
                meta[semantic_name] += "," + decoded
            else:
                meta[semantic_name] = decoded

        if semantic_name in {"job-id", "orientation-requested"} and len(value) == 4:
            try:
                meta[semantic_name] = str(struct.unpack(">i", value)[0])
            except Exception:
                pass

        if semantic_name in {"x-dimension", "y-dimension"} and len(value) == 4:
            try:
                meta[f"media-{semantic_name}"] = str(struct.unpack(">i", value)[0])
            except Exception:
                pass

        if semantic_name in {"last-document", "my-jobs"} and len(value) == 1:
            meta[semantic_name] = "true" if value != b"\x00" else "false"

    meta["_operation-attribute-names"] = ",".join(operation_attribute_names)
    document = raw[pos:]
    return meta, document


def render_pdf_to_pngs(pdf_bytes: bytes, dpi: int) -> Tuple[int, Dict[int, bytes]]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        _log_pdf_state("PDF diagnostics", doc, pdf_bytes)
        if bool(getattr(doc, "needs_pass", False)):
            if not doc.authenticate(""):
                _log_pdf_state("PDF password required", doc, pdf_bytes)
                raise ValueError("PDF payload is encrypted and requires a password")

        total = doc.page_count
        if total <= 0:
            encrypted = bool(getattr(doc, "is_encrypted", False))
            _log_pdf_state("PDF zero-page diagnostics", doc, pdf_bytes)
            if encrypted:
                raise ValueError("PDF payload could not be rendered because it is encrypted")
            raise ValueError("PDF payload contains zero pages")

        pages: Dict[int, bytes] = {}
        for index in range(total):
            page = doc.load_page(index)
            pix = page.get_pixmap(dpi=dpi, alpha=False)
            pages[index + 1] = pix.tobytes("png")
        return total, pages
    finally:
        doc.close()


def render_document_to_pngs(document: bytes, meta: Dict[str, str], dpi: int) -> Tuple[int, Dict[int, bytes]]:
    document_kind = _detect_document_kind(document, meta)
    if document_kind == "pdf":
        if not meta.get("document-format"):
            meta["document-format"] = "application/pdf"
        logger.info("Rendering PDF payload to PNG via PyMuPDF")
        return render_pdf_to_pngs(document, dpi=dpi)

    if document_kind == "postscript":
        if not meta.get("document-format"):
            meta["document-format"] = "application/postscript"
        logger.info("Rendering PostScript payload to PNG via Ghostscript")
        return render_postscript_to_pngs(document, dpi=dpi)

    if document_kind == "pwg-raster":
        meta["document-format"] = "image/pwg-raster"
        logger.info("Rendering PWG Raster payload to PNG via CUPS filters")
        return render_pwg_raster_to_pngs(document, dpi=dpi, job_name=meta.get("job-name", ""))

    if document_kind in {"jpeg", "png"}:
        meta["document-format"] = "image/jpeg" if document_kind == "jpeg" else "image/png"
        logger.info("Rendering %s payload to PNG via PyMuPDF", document_kind.upper())
        return render_image_to_pngs(document, document_kind)

    raise ValueError(f"Unsupported document payload (first bytes={document[:12]!r})")


def _should_rotate_for_target(source_size: Tuple[int, int], target_size: Tuple[int, int]) -> bool:
    source_width, source_height = source_size
    target_width, target_height = target_size
    if source_width <= 0 or source_height <= 0 or target_width <= 0 or target_height <= 0:
        return False
    source_ratio = source_width / source_height
    rotated_ratio = source_height / source_width
    target_ratio = target_width / target_height
    normal_error = abs(source_ratio - target_ratio) / target_ratio
    rotated_error = abs(rotated_ratio - target_ratio) / target_ratio
    return rotated_error + 1e-9 < normal_error


def fit_png_to_target(png_bytes: bytes, profile: Dict[str, object]) -> bytes:
    width = int(profile["width"])
    height = int(profile["height"])
    fit = str(profile.get("fit", "contain"))
    auto_rotate = bool(profile.get("auto_rotate", False))
    background = ImageColor.getrgb(str(profile.get("background", "#ffffff")))

    with Image.open(io.BytesIO(png_bytes)) as source:
        if source.mode in {"RGBA", "LA"} or "transparency" in source.info:
            foreground = source.convert("RGBA")
            composite = Image.new("RGBA", foreground.size, (*background, 255))
            composite.alpha_composite(foreground)
            image = composite.convert("RGB")
        else:
            image = source.convert("RGB")
        if auto_rotate and _should_rotate_for_target(image.size, (width, height)):
            image = image.transpose(Image.Transpose.ROTATE_270)

        if fit == "cover":
            output = ImageOps.fit(
                image,
                (width, height),
                method=Image.Resampling.LANCZOS,
                centering=(0.5, 0.5),
            )
        elif fit == "stretch":
            output = image.resize((width, height), Image.Resampling.LANCZOS)
        else:
            fitted = ImageOps.contain(image, (width, height), Image.Resampling.LANCZOS)
            output = Image.new("RGB", (width, height), background)
            output.paste(
                fitted,
                ((width - fitted.width) // 2, (height - fitted.height) // 2),
            )

        encoded = io.BytesIO()
        output.save(encoded, format="PNG")
        return encoded.getvalue()


def apply_target_profile_to_pages(
    pages: Dict[int, bytes], profile: Optional[Dict[str, object]], meta: Dict[str, str]
) -> Dict[int, bytes]:
    if not profile:
        return pages

    width = int(profile["width"])
    height = int(profile["height"])
    fit = str(profile.get("fit", "contain"))
    meta["target-width"] = str(width)
    meta["target-height"] = str(height)
    meta["target-fit"] = fit
    logger.info(
        "Fitting rendered pages to target: size=%sx%s fit=%s auto_rotate=%s orientation_requested=%s background=%s",
        width,
        height,
        fit,
        bool(profile.get("auto_rotate", False)),
        meta.get("orientation-requested", ""),
        profile.get("background", "#ffffff"),
    )
    return {
        page_number: fit_png_to_target(png_bytes, profile)
        for page_number, png_bytes in pages.items()
    }


def render_document_for_target(
    document: bytes,
    meta: Dict[str, str],
    dpi: int,
    target_profile: Optional[Dict[str, object]],
) -> Tuple[int, Dict[int, bytes]]:
    total, pages = render_document_to_pngs(document, meta, dpi=dpi)
    return total, apply_target_profile_to_pages(pages, target_profile, meta)


def store_first_png_in_temp(temp_dir: str, job_id: str, page_num: int, png_bytes: bytes) -> None:
    if not temp_dir:
        return
    out_dir = Path(temp_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{job_id}_p{page_num}.png").write_bytes(png_bytes)


def post_pages(
    endpoint: str,
    auth_header: Optional[str],
    auth_value: Optional[str],
    timeout_seconds: int,
    file_field: str,
    include_meta_fields: bool,
    send_all_pages: bool,
    job_id: str,
    meta: Dict[str, str],
    total_pages: int,
    png_pages: Dict[int, bytes],
) -> None:
    headers = {}
    if auth_header and auth_value:
        headers[auth_header] = auth_value

    if not png_pages:
        logger.warning("Skipping upload: no PNG pages to POST for job_id=%s", job_id)
        return

    page_numbers = sorted(png_pages.keys())
    if not send_all_pages:
        page_numbers = [1 if 1 in png_pages else page_numbers[0]]

    page_label = str(page_numbers[0]) if len(page_numbers) == 1 else f"{page_numbers[0]}-{page_numbers[-1]}"
    total_png_bytes = sum(len(png_pages[page_num]) for page_num in page_numbers)
    logger.info(
        "POST start: endpoint=%s job_id=%s pages=%s file_parts=%s total_pages=%s png_bytes=%d mode=%s",
        endpoint,
        job_id,
        page_label,
        len(page_numbers),
        total_pages,
        total_png_bytes,
        "all-pages-single-post" if send_all_pages else "first-page-only",
    )

    data = {}
    if include_meta_fields:
        data = {
            "job_id": job_id,
            "request_id": meta.get("request_id", ""),
            "total_pages": str(total_pages),
            "document_format": meta.get("document-format", ""),
            "job_name": meta.get("job-name", ""),
            "printer_uri": meta.get("printer-uri", ""),
            "user": meta.get("requesting-user-name", ""),
        }
        if meta.get("target-width") and meta.get("target-height"):
            data["target_width"] = meta["target-width"]
            data["target_height"] = meta["target-height"]
            data["target_fit"] = meta.get("target-fit", "")
        if len(page_numbers) == 1:
            data["page"] = str(page_numbers[0])

    files = [
        (
            file_field or "file",
            (
                f"{job_id}_p{page_num}.png",
                png_pages[page_num],
                "image/png",
            ),
        )
        for page_num in page_numbers
    ]

    try:
        resp = requests.post(endpoint, data=data, files=files, headers=headers, timeout=timeout_seconds)
        logger.info(
            "POST response: endpoint=%s status=%s job_id=%s pages=%s file_parts=%s",
            endpoint,
            resp.status_code,
            job_id,
            page_label,
            len(page_numbers),
        )
        if resp.status_code >= 400:
            try:
                body = resp.text
            except Exception:
                body = "<unreadable response body>"
            if body and len(body) > 2000:
                body = body[:2000] + "...<truncated>"
            if body:
                logger.warning("POST response body: %s", body)
        resp.raise_for_status()
        logger.info("POST succeeded: endpoint=%s job_id=%s pages=%s", endpoint, job_id, page_label)
    except Exception:
        # Never crash the server thread on upload failures.
        logger.exception("Upload failed: endpoint=%s job_id=%s pages=%s", endpoint, job_id, page_label)


class IppHandler(BaseHTTPRequestHandler):
    server_version = "ipp-to-png/0.1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        # Lightweight health endpoint for container platforms (Fly.io, etc.)
        path_only = (self.path or "/").split("?", 1)[0]
        if path_only in {"/healthz", "/health"}:
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing health response")
            return

        self.send_error(404)

    def do_POST(self) -> None:
        config = self.server.config  # type: ignore[attr-defined]

        path_only, overrides, safe_path_for_logs = _split_ipp_path_and_overrides(self.path, config["IPP_PATH"])

        if config.get("LOG_HEADERS"):
            logger.debug(
                "HTTP request: client=%s path=%s headers=%s",
                self.client_address,
                safe_path_for_logs,
                _redacted_headers(self.headers),
            )
        else:
            logger.debug("HTTP request: client=%s path=%s", self.client_address, safe_path_for_logs)

        if path_only is None:
            logger.warning("Unexpected path %s (expected %s)", safe_path_for_logs, config["IPP_PATH"])
            self.send_error(404)
            return

        # Cache per-client overrides when present. macOS and Windows may later
        # omit them from the HTTP resource while retaining them in IPP data.
        forwarded_for = (self.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
        client_ip = forwarded_for or (self.headers.get("X-Real-Ip") or "").strip()
        if not client_ip:
            client_ip = (self.client_address[0] if self.client_address else "") or ""
        user_agent = (self.headers.get("User-Agent") or "").strip()
        client_key = f"{client_ip}|{user_agent}"
        try:
            self.server.register_client_overrides(client_key, overrides)  # type: ignore[attr-defined]
        except Exception:
            logger.exception("Failed to register client overrides")

        shared = config.get("IPP_SHARED_TOKEN")
        if shared:
            token = self.headers.get("X-IPP-Token")
            if token != shared:
                logger.warning("Unauthorized: missing/invalid X-IPP-Token")
                self.send_error(401)
                return

        # Some proxy paths mis-handle an origin-generated 100-continue response.
        # Default to suppressing it unless explicitly re-enabled.
        if (self.headers.get("Expect") or "").lower() == "100-continue":
            if config.get("IPP_SEND_EXPECT_CONTINUE", True):
                logger.debug("Sending 100-continue")
                self.send_response_only(100)
                self.end_headers()
            else:
                logger.debug("Suppressing 100-continue response due to IPP_SEND_EXPECT_CONTINUE=false")

        raw: bytes
        length = self.headers.get("Content-Length")
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()

        if length is not None:
            try:
                content_length = int(length)
            except ValueError:
                self.send_error(400)
                return

            if content_length < 0 or content_length > config["IPP_MAX_BYTES"]:
                logger.warning("Invalid Content-Length=%s (max=%s)", content_length, config["IPP_MAX_BYTES"])
                self.send_error(413)
                return

            raw = self.rfile.read(content_length)
            logger.debug("Read %d bytes from request body (Content-Length)", len(raw))

        elif "chunked" in transfer_encoding:
            try:
                raw = _read_chunked_body(self.rfile, max_bytes=config["IPP_MAX_BYTES"])
            except Exception as e:
                logger.exception("Failed to read chunked body")
                self.send_error(400, str(e))
                return
            logger.debug("Read %d bytes from request body (chunked)", len(raw))

        else:
            # No Content-Length and no chunked encoding: treat as empty body.
            # (macOS may send probe-like requests during setup)
            logger.warning("Missing Content-Length and not chunked; treating body as empty")
            raw = b""

        try:
            meta, document = parse_ipp_request(raw)
        except Exception as e:
            logger.exception("Failed to parse IPP request")
            self.send_error(400, str(e))
            return

        operation_id = int(meta.get("operation_id", "0") or "0")
        request_id = int(meta.get("request_id", "0") or "0")
        vmaj = int(meta.get("ipp_version_major", "1") or "1")
        vmin = int(meta.get("ipp_version_minor", "1") or "1")

        def send_ipp_error(status_code: int, reason: str) -> None:
            logger.warning("Rejecting IPP request: %s", reason)
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                status_code,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")

        # Validate the small set of protocol invariants discovery clients rely
        # on. Always answer at the IPP layer so they never parse an HTML error
        # body as a printer response.
        if request_id == 0:
            send_ipp_error(IPP_STATUS_CLIENT_ERROR_BAD_REQUEST, "reserved request-id 0")
            return
        if vmaj not in {1, 2}:
            send_ipp_error(
                IPP_STATUS_SERVER_ERROR_VERSION_NOT_SUPPORTED,
                f"unsupported IPP version {vmaj}.{vmin}",
            )
            return

        operation_attribute_names = [
            name
            for name in (meta.get("_operation-attribute-names", "") or "").split(",")
            if name
        ]
        if operation_attribute_names[:2] != ["attributes-charset", "attributes-natural-language"]:
            send_ipp_error(
                IPP_STATUS_CLIENT_ERROR_BAD_REQUEST,
                "attributes-charset and attributes-natural-language must be first",
            )
            return
        printer_uri_operations = {
            IPP_OP_PRINT_JOB,
            IPP_OP_VALIDATE_JOB,
            IPP_OP_CREATE_JOB,
            IPP_OP_GET_JOBS,
            IPP_OP_GET_PRINTER_ATTRIBUTES,
            IPP_OP_CANCEL_MY_JOBS,
            IPP_OP_IDENTIFY_PRINTER,
        }
        if operation_id in printer_uri_operations and not meta.get("printer-uri"):
            send_ipp_error(IPP_STATUS_CLIENT_ERROR_BAD_REQUEST, "missing printer-uri operation attribute")
            return

        # Windows can use the conventional HTTP resource (/ipp/print) while
        # carrying the full configured URI in the IPP operation attributes.
        # Recover per-printer routing from that URI before consulting the
        # per-client cache and optional deployment defaults.
        overrides = _merge_overrides(
            overrides,
            _overrides_from_ipp_uri(meta.get("printer-uri", ""), config["IPP_PATH"]),
        )
        try:
            self.server.register_client_overrides(client_key, overrides)  # type: ignore[attr-defined]
            cached = self.server.get_client_overrides(client_key)  # type: ignore[attr-defined]
        except Exception:
            cached = {}
            logger.exception("Failed to update client overrides")
        overrides = _merge_overrides(overrides, cached)
        overrides = _merge_overrides(
            overrides,
            {
                "paper_id": config.get("PAPER_ID") or "",
                "auth_value": config.get("POST_AUTH_VALUE") or "",
            },
        )
        effective_paper_id = (overrides.get("paper_id") or "").strip()
        effective_auth_value = (overrides.get("auth_value") or "").strip()
        paper_default_profile = _target_profile_for_paper_id(
            config.get("IPP_TARGET_PROFILES") or {},
            effective_paper_id,
        )
        target_profile = _target_profile_for_job(
            meta,
            config["IPP_RENDER_DPI"],
            paper_default_profile,
        )
        effective_endpoint = _resolve_endpoint_template(config.get("POST_ENDPOINT") or "", effective_paper_id)
        post_enabled = bool(effective_endpoint and effective_paper_id)
        external_printer_uri = _external_ipp_uri(
            self.headers,
            self.path,
            config["IPP_PATH"],
            meta.get("printer-uri", ""),
        )
        logger.debug(
            "Request transport: content_length_header=%s transfer_encoding=%s raw_bytes=%d",
            length,
            transfer_encoding,
            len(raw),
        )
        if document:
            _log_document_diagnostics("Received document diagnostics", document)
        logger.info(
            "IPP request: op=%s request_id=%s job_name=%s document_format=%s document_bytes=%d",
            _op_name(operation_id),
            request_id,
            meta.get("job-name", ""),
            meta.get("document-format", ""),
            len(document),
        )

        # macOS, Windows, and CUPS/Linux probe capabilities before queue creation.
        if operation_id == IPP_OP_GET_PRINTER_ATTRIBUTES:
            requested_attributes = [
                value.strip()
                for value in (meta.get("requested-attributes", "") or "").split(",")
                if value.strip()
            ]
            logger.debug("Handling Get-Printer-Attributes requested=%s", requested_attributes or "all")
            external_parts = urlsplit(external_printer_uri)
            attr_bytes = build_get_printer_attributes_response(
                external_parts.netloc,
                external_parts.path or config["IPP_PATH"],
                scheme=external_parts.scheme or "ipp",
                printer_uri=external_printer_uri,
                requested_attributes=requested_attributes,
                render_dpi=config["IPP_RENDER_DPI"],
                target_profile=target_profile,
            )
            response = build_ipp_response_with_version(vmaj, vmin, IPP_STATUS_SUCCESSFUL_OK, request_id, attr_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_VALIDATE_JOB:
            logger.debug("Handling Validate-Job")
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_SUCCESSFUL_OK,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_GET_JOB_ATTRIBUTES:
            logger.debug("Handling Get-Job-Attributes")
            job_id_str = meta.get("job-id", "")
            job_id_int = int(job_id_str) if job_id_str.isdigit() else 0
            job_state = self.server.get_job_state(job_id_int, default=9)  # type: ignore[attr-defined]
            attr_bytes = build_get_job_attributes_response(
                self.headers.get("Host", ""),
                config["IPP_PATH"],
                job_id_int,
                job_state,
                external_printer_uri,
            )
            response = build_ipp_response_with_version(vmaj, vmin, IPP_STATUS_SUCCESSFUL_OK, request_id, attr_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_GET_JOBS:
            logger.debug("Handling Get-Jobs")
            which_jobs = (meta.get("which-jobs") or "not-completed").strip().lower()
            requested_attributes = [
                value.strip()
                for value in (meta.get("requested-attributes", "") or "").split(",")
                if value.strip()
            ]
            jobs = self.server.list_jobs()  # type: ignore[attr-defined]
            if which_jobs == "completed":
                jobs = [(job_id, state) for job_id, state in jobs if state in {7, 8, 9}]
            elif which_jobs != "all":
                jobs = [(job_id, state) for job_id, state in jobs if state not in {7, 8, 9}]
            attr_bytes = build_get_jobs_response(
                self.headers.get("Host", ""),
                config["IPP_PATH"],
                jobs,
                external_printer_uri,
                requested_attributes,
            )
            response = build_ipp_response_with_version(vmaj, vmin, IPP_STATUS_SUCCESSFUL_OK, request_id, attr_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_CANCEL_JOB:
            job_id_str = meta.get("job-id", "")
            job_id_int = int(job_id_str) if job_id_str.isdigit() else 0
            logger.debug("Handling Cancel-Job job-id=%s", job_id_int or "(unknown)")
            job_state = self.server.get_job_state(job_id_int, default=9)  # type: ignore[attr-defined]
            if job_id_int and job_state not in {7, 8, 9}:
                self.server.set_job_state(job_id_int, 7)  # type: ignore[attr-defined]
                status_code = IPP_STATUS_SUCCESSFUL_OK
            else:
                status_code = IPP_STATUS_CLIENT_ERROR_NOT_POSSIBLE
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                status_code,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_CANCEL_MY_JOBS:
            logger.debug("Handling Cancel-My-Jobs")
            self.server.cancel_active_jobs()  # type: ignore[attr-defined]
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_SUCCESSFUL_OK,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id in {IPP_OP_CLOSE_JOB, IPP_OP_IDENTIFY_PRINTER}:
            logger.debug("Handling %s", _op_name(operation_id))
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_SUCCESSFUL_OK,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        # macOS/AirPrint often uses Create-Job + Send-Document instead of Print-Job.
        if operation_id == IPP_OP_CREATE_JOB:
            logger.debug("Handling Create-Job")

            job_id_int = self.server.allocate_job_id()  # type: ignore[attr-defined]
            job_uuid = uuid.uuid4().hex
            now = _utc_timestamp_compact()
            spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_{job_id_int}_{job_uuid}"
            spool_dir.mkdir(parents=True, exist_ok=True)

            logger.info("Spooling Create-Job job-id=%s to %s", job_id_int, spool_dir)
            (spool_dir / "request.ipp").write_bytes(raw)
            (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
            self.server.register_job(job_id_int, spool_dir)  # type: ignore[attr-defined]
            # Persist any per-request overrides so Send-Document can reuse them.
            # macOS may not preserve query params/path segments on the follow-up request.
            try:
                self.server.register_job_overrides(  # type: ignore[attr-defined]
                    job_id_int,
                    {**overrides, **_job_layout_context(meta)},
                )
            except Exception:
                logger.exception("Failed to register job overrides")

            attrs = bytearray(build_operation_attributes())
            attrs += bytes([0x02])  # job-attributes-tag
            attrs += _job_attributes(
                external_printer_uri,
                job_id_int,
                3,
                meta.get("job-name", "IPP job"),
            )

            response = build_ipp_response_with_version(vmaj, vmin, IPP_STATUS_SUCCESSFUL_OK, request_id, bytes(attrs))
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id == IPP_OP_SEND_DOCUMENT:
            logger.debug("Handling Send-Document")

            if meta.get("last-document") != "true":
                response = build_ipp_response_with_version(
                    vmaj,
                    vmin,
                    IPP_STATUS_CLIENT_ERROR_BAD_REQUEST,
                    request_id,
                    build_operation_attributes(),
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/ipp")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                try:
                    self.wfile.write(response)
                except ConnectionResetError:
                    logger.debug("Client reset connection while writing response")
                return

            job_id_str = meta.get("job-id", "")
            job_id_int = int(job_id_str) if job_id_str.isdigit() else 0
            if job_id_int:
                self.server.set_job_state(job_id_int, 5)  # type: ignore[attr-defined]

            # Resolve overrides for this job.
            # If the HTTP path doesn't carry query params anymore (common on macOS), reuse Create-Job overrides.
            job_context: Dict[str, str] = {}
            if job_id_int:
                try:
                    job_context = self.server.get_job_overrides(job_id_int)  # type: ignore[attr-defined]
                except Exception:
                    logger.exception("Failed to fetch job overrides")
                if not effective_paper_id:
                    effective_paper_id = (job_context.get("paper_id") or "").strip()
                if not effective_auth_value:
                    effective_auth_value = (job_context.get("auth_value") or "").strip()
                for field in _JOB_LAYOUT_FIELDS:
                    if not (meta.get(field) or "").strip() and (job_context.get(field) or "").strip():
                        meta[field] = job_context[field]

            # Recompute endpoint/post_enabled now that we may have effective_paper_id.
            paper_default_profile = _target_profile_for_paper_id(
                config.get("IPP_TARGET_PROFILES") or {},
                effective_paper_id,
            )
            target_profile = _target_profile_for_job(
                meta,
                config["IPP_RENDER_DPI"],
                paper_default_profile,
            )
            effective_endpoint = _resolve_endpoint_template(config.get("POST_ENDPOINT") or "", effective_paper_id)
            post_enabled = bool(effective_endpoint)

            # If paper_id is missing, the PaperlessPaper uploadSingleImage endpoint will be invalid.
            if post_enabled and not effective_paper_id:
                logger.warning("Upload disabled for this job: missing paper_id (path=%s)", safe_path_for_logs)
                post_enabled = False
            spool_dir = self.server.get_job_spool_dir(job_id_int) if job_id_int else None  # type: ignore[attr-defined]
            if spool_dir is None:
                job_uuid = uuid.uuid4().hex
                now = _utc_timestamp_compact()
                spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_send_{job_uuid}"
                spool_dir.mkdir(parents=True, exist_ok=True)

            logger.info("Spooling Send-Document job-id=%s to %s", job_id_int or "(unknown)", spool_dir)
            (spool_dir / "request.ipp").write_bytes(raw)
            (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
            (spool_dir / "document.bin").write_bytes(document)

            if not document:
                logger.warning(
                    "Rejecting Send-Document with empty payload: request_id=%s job_id=%s content_length_header=%s transfer_encoding=%s",
                    request_id,
                    job_id_int or "(unknown)",
                    length,
                    transfer_encoding,
                )
                response = build_ipp_response_with_version(
                    vmaj,
                    vmin,
                    IPP_STATUS_CLIENT_ERROR_BAD_REQUEST,
                    request_id,
                    build_operation_attributes(),
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/ipp")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                try:
                    self.wfile.write(response)
                except ConnectionResetError:
                    logger.debug("Client reset connection while writing response")
                return

            try:
                total, pages = render_document_for_target(
                    document,
                    meta,
                    dpi=config["IPP_RENDER_DPI"],
                    target_profile=target_profile,
                )
                (spool_dir / "meta.json").write_text(
                    json.dumps(meta, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                for page_num, png_bytes in pages.items():
                    (spool_dir / f"page_{page_num:04d}.png").write_bytes(png_bytes)
                logger.info(
                    "PNG generation succeeded: job_id=%s total_pages=%s spool_dir=%s",
                    job_id_int or "(unknown)",
                    total,
                    spool_dir,
                )

                if pages:
                    first_page_num = 1 if 1 in pages else sorted(pages.keys())[0]
                    temp_dir = config.get("IPP_TEMP_DIR", "./temp")
                    temp_job_id = str(job_id_int) if job_id_int else "send"
                    store_first_png_in_temp(temp_dir, temp_job_id, first_page_num, pages[first_page_num])
                    first_png_path = (Path(temp_dir) / f"{temp_job_id}_p{first_page_num}.png").resolve()
                    logger.info(
                        "PNG stored: job_id=%s first_page=%s png_bytes=%s path=%s",
                        temp_job_id,
                        first_page_num,
                        len(pages[first_page_num]),
                        first_png_path,
                    )

                # POST in background so the IPP response is quick
                if post_enabled:
                    upload_job_id = str(job_id_int) if job_id_int else "send"
                    thread = threading.Thread(
                        target=post_pages,
                        kwargs={
                            "endpoint": effective_endpoint,
                            "auth_header": config.get("POST_AUTH_HEADER"),
                            "auth_value": effective_auth_value,
                            "timeout_seconds": config["POST_TIMEOUT_SECONDS"],
                            "file_field": config.get("POST_FILE_FIELD", "file"),
                            "include_meta_fields": bool(config.get("POST_INCLUDE_META_FIELDS", False)),
                            "send_all_pages": bool(config.get("POST_SEND_ALL_PAGES", False)),
                            "job_id": upload_job_id,
                            "meta": meta,
                            "total_pages": total,
                            "png_pages": pages,
                        },
                        daemon=True,
                    )
                    thread.start()
                else:
                    logger.info("Upload disabled (POST_ENDPOINT empty); skipping POST")

                if job_id_int:
                    self.server.set_job_state(job_id_int, 9)  # type: ignore[attr-defined]

            except ValueError as e:
                if job_id_int:
                    self.server.set_job_state(job_id_int, 8)  # type: ignore[attr-defined]
                logger.warning("%s", e)
                self.send_error(415, str(e))
                return
            except Exception as e:
                if job_id_int:
                    self.server.set_job_state(job_id_int, 8)  # type: ignore[attr-defined]
                logger.exception("Render failed")
                self.send_error(500, f"Render failed: {e}")
                return

            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_SUCCESSFUL_OK,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        if operation_id != IPP_OP_PRINT_JOB:
            logger.warning("Unsupported IPP operation %s; returning operation-not-supported", _op_name(operation_id))
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_SERVER_ERROR_OPERATION_NOT_SUPPORTED,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        # Everything below is for Print-Job.
        job_id_int = self.server.allocate_job_id()  # type: ignore[attr-defined]
        job_id = str(job_id_int)
        job_uuid = uuid.uuid4().hex
        now = _utc_timestamp_compact()
        spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_{job_id}_{job_uuid}"
        spool_dir.mkdir(parents=True, exist_ok=True)
        self.server.register_job(job_id_int, spool_dir)  # type: ignore[attr-defined]
        self.server.register_job_overrides(  # type: ignore[attr-defined]
            job_id_int,
            {**overrides, **_job_layout_context(meta)},
        )
        self.server.set_job_state(job_id_int, 5)  # type: ignore[attr-defined]

        logger.info("Spooling job %s to %s", job_id, spool_dir)

        (spool_dir / "request.ipp").write_bytes(raw)
        (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        (spool_dir / "document.bin").write_bytes(document)

        if not document:
            logger.warning(
                "Rejecting Print-Job with empty payload: request_id=%s content_length_header=%s transfer_encoding=%s",
                request_id,
                length,
                transfer_encoding,
            )
            response = build_ipp_response_with_version(
                vmaj,
                vmin,
                IPP_STATUS_CLIENT_ERROR_BAD_REQUEST,
                request_id,
                build_operation_attributes(),
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except ConnectionResetError:
                logger.debug("Client reset connection while writing response")
            return

        try:
            total, pages = render_document_for_target(
                document,
                meta,
                dpi=config["IPP_RENDER_DPI"],
                target_profile=target_profile,
            )
            (spool_dir / "meta.json").write_text(
                json.dumps(meta, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            for page_num, png_bytes in pages.items():
                (spool_dir / f"page_{page_num:04d}.png").write_bytes(png_bytes)
            logger.info(
                "PNG generation succeeded: job_id=%s total_pages=%s spool_dir=%s",
                job_id,
                total,
                spool_dir,
            )

            # Also store the first page PNG into /temp (or configured temp dir)
            if pages:
                first_page_num = 1 if 1 in pages else sorted(pages.keys())[0]
                temp_dir = config.get("IPP_TEMP_DIR", "./temp")
                store_first_png_in_temp(temp_dir, job_id, first_page_num, pages[first_page_num])
                first_png_path = (Path(temp_dir) / f"{job_id}_p{first_page_num}.png").resolve()
                logger.info(
                    "PNG stored: job_id=%s first_page=%s png_bytes=%s path=%s",
                    job_id,
                    first_page_num,
                    len(pages[first_page_num]),
                    first_png_path,
                )

            # POST in background so the IPP response is quick
            if post_enabled:
                thread = threading.Thread(
                    target=post_pages,
                    kwargs={
                        "endpoint": effective_endpoint,
                        "auth_header": config.get("POST_AUTH_HEADER"),
                        "auth_value": effective_auth_value,
                        "timeout_seconds": config["POST_TIMEOUT_SECONDS"],
                        "file_field": config.get("POST_FILE_FIELD", "file"),
                        "include_meta_fields": bool(config.get("POST_INCLUDE_META_FIELDS", False)),
                        "send_all_pages": bool(config.get("POST_SEND_ALL_PAGES", False)),
                        "job_id": job_id,
                        "meta": meta,
                        "total_pages": total,
                        "png_pages": pages,
                    },
                    daemon=True,
                )
                thread.start()
            else:
                if config.get("POST_ENDPOINT") and not effective_paper_id:
                    logger.warning("Upload disabled for this job: missing paper_id (path=%s)", safe_path_for_logs)
                else:
                    logger.info("Upload disabled (POST_ENDPOINT empty); skipping POST")

            self.server.set_job_state(job_id_int, 9)  # type: ignore[attr-defined]

        except ValueError as e:
            self.server.set_job_state(job_id_int, 8)  # type: ignore[attr-defined]
            logger.warning("%s", e)
            self.send_error(415, str(e))
            return
        except Exception as e:
            self.server.set_job_state(job_id_int, 8)  # type: ignore[attr-defined]
            logger.exception("Render/POST failed")
            self.send_error(500, f"Render/POST failed: {e}")
            return

        response_attrs = bytearray(build_operation_attributes())
        response_attrs += bytes([0x02])
        response_attrs += _job_attributes(
            external_printer_uri,
            job_id_int,
            9,
            meta.get("job-name", "IPP job"),
        )
        response = build_ipp_response_with_version(
            vmaj,
            vmin,
            IPP_STATUS_SUCCESSFUL_OK,
            request_id,
            bytes(response_attrs),
        )

        self.send_response(200)
        self.send_header("Content-Type", "application/ipp")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        try:
            self.wfile.write(response)
        except ConnectionResetError:
            logger.debug("Client reset connection while writing response")
        logger.debug("IPP response sent: status=successful-ok request_id=%s", request_id)

    def log_message(self, format: str, *args) -> None:
        # BaseHTTPRequestHandler logs the raw HTTP request line separately from
        # our structured request log. Redact the credential-bearing URL there
        # as well so access logs cannot leak per-printer tokens.
        ipp_base_path = getattr(self.server, "config", {}).get("IPP_PATH", "/ipp/print")
        safe_args = tuple(
            _redact_http_request_line(value, ipp_base_path) if isinstance(value, str) else value
            for value in args
        )
        super().log_message(format, *safe_args)


class IppServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self._job_lock = threading.Lock()
        self._next_job_id = 1
        self._jobs: Dict[int, Path] = {}
        self._job_states: Dict[int, int] = {}
        self._job_overrides: Dict[int, Dict[str, str]] = {}
        self._client_overrides: Dict[str, Dict[str, str]] = {}

    def allocate_job_id(self) -> int:
        with self._job_lock:
            job_id = self._next_job_id
            self._next_job_id += 1
            return job_id

    def register_job(self, job_id: int, spool_dir: Path) -> None:
        with self._job_lock:
            self._jobs[job_id] = spool_dir
            self._job_states[job_id] = 3

    def set_job_state(self, job_id: int, job_state: int) -> None:
        if job_id <= 0:
            return
        with self._job_lock:
            self._job_states[job_id] = job_state

    def get_job_state(self, job_id: int, default: int = 9) -> int:
        if job_id <= 0:
            return default
        with self._job_lock:
            return int(self._job_states.get(job_id, default))

    def list_jobs(self) -> list[Tuple[int, int]]:
        with self._job_lock:
            return [(job_id, int(self._job_states.get(job_id, 9))) for job_id in sorted(self._jobs)]

    def cancel_active_jobs(self) -> None:
        with self._job_lock:
            for job_id, state in list(self._job_states.items()):
                if state not in {7, 8, 9}:
                    self._job_states[job_id] = 7

    def register_job_overrides(self, job_id: int, overrides: Dict[str, str]) -> None:
        # Keep routing and media choice across Create-Job/Send-Document.
        context = _stored_job_context(overrides)
        with self._job_lock:
            self._job_overrides[job_id] = context

    def get_job_overrides(self, job_id: int) -> Dict[str, str]:
        with self._job_lock:
            return dict(self._job_overrides.get(job_id) or {})

    def get_job_spool_dir(self, job_id: int) -> Optional[Path]:
        with self._job_lock:
            return self._jobs.get(job_id)

    def register_client_overrides(self, key: str, overrides: Dict[str, str]) -> None:
        if not key:
            return
        paper_id = (overrides.get("paper_id") or "").strip()
        auth_value = (overrides.get("auth_value") or "").strip()
        if not paper_id and not auth_value:
            return
        with self._job_lock:
            existing = self._client_overrides.get(key) or {}
            merged = dict(existing)
            if paper_id:
                merged["paper_id"] = paper_id
            if auth_value:
                merged["auth_value"] = auth_value
            self._client_overrides[key] = merged

    def get_client_overrides(self, key: str) -> Dict[str, str]:
        if not key:
            return {}
        with self._job_lock:
            return dict(self._client_overrides.get(key) or {})


def main() -> None:
    load_dotenv()

    log_level = (os.getenv("LOG_LEVEL") or "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    ipp_listen_port_raw = (os.getenv("IPP_LISTEN_PORT") or "").strip()
    if not ipp_listen_port_raw:
        # On Fly.io, a reverse proxy forwards traffic to $PORT by convention.
        ipp_listen_port_raw = (os.getenv("PORT") or "").strip()

    config = {
        "IPP_LISTEN_HOST": _env_str("IPP_LISTEN_HOST", "0.0.0.0"),
        "IPP_LISTEN_PORT": int(ipp_listen_port_raw) if ipp_listen_port_raw else 8631,
        "IPP_PATH": _env_str("IPP_PATH", "/ipp/print"),
        "IPP_MAX_BYTES": _env_int("IPP_MAX_BYTES", 100 * 1024 * 1024),
        "IPP_SPOOL_DIR": _env_str("IPP_SPOOL_DIR", "./spool"),
        "IPP_RENDER_DPI": _env_int("IPP_RENDER_DPI", 150),
        "IPP_TARGET_PROFILES": _parse_target_profiles(os.getenv("IPP_TARGET_PROFILES") or ""),
        "IPP_TEMP_DIR": _env_str("IPP_TEMP_DIR", "./temp"),
        "IPP_SEND_EXPECT_CONTINUE": _env_bool("IPP_SEND_EXPECT_CONTINUE", False),
        "IPP_SHARED_TOKEN": os.getenv("IPP_SHARED_TOKEN") or "",
        "PAPER_ID": os.getenv("PAPER_ID") or "",
        "POST_ENDPOINT": _env_str("POST_ENDPOINT", ""),
        "POST_AUTH_HEADER": os.getenv("POST_AUTH_HEADER") or "",
        "POST_AUTH_VALUE": os.getenv("POST_AUTH_VALUE") or "",
        "POST_TIMEOUT_SECONDS": _env_int("POST_TIMEOUT_SECONDS", 30),
        "POST_FILE_FIELD": _env_str("POST_FILE_FIELD", "file"),
        "POST_INCLUDE_META_FIELDS": _env_bool("POST_INCLUDE_META_FIELDS", False),
        "POST_SEND_ALL_PAGES": _env_bool("POST_SEND_ALL_PAGES", False),
    }

    config["LOG_HEADERS"] = _env_bool("LOG_HEADERS", False)

    # Uploading is optional; if POST_ENDPOINT is empty, the server will only store the files.
    # Note: per-request overrides (paper_id) may change the effective endpoint.
    config["POST_ENABLED"] = bool(config["POST_ENDPOINT"])

    server = IppServer((config["IPP_LISTEN_HOST"], config["IPP_LISTEN_PORT"]), IppHandler)
    server.config = config  # type: ignore[attr-defined]

    print(
        f"Listening on http://{config['IPP_LISTEN_HOST']}:{config['IPP_LISTEN_PORT']}{config['IPP_PATH']}"
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def run_with_restart() -> None:
    auto_restart = _env_bool("AUTO_RESTART", False)
    if not auto_restart:
        main()
        return

    delay_seconds = _env_int("AUTO_RESTART_DELAY_SECONDS", 2)
    max_restarts = _env_int("AUTO_RESTART_MAX", 0)
    attempt = 0

    while True:
        try:
            main()
            return
        except KeyboardInterrupt:
            raise
        except Exception:
            attempt += 1
            logger.exception(
                "Server crashed; restarting in %s seconds (attempt %s)",
                delay_seconds,
                attempt,
            )
            if max_restarts > 0 and attempt >= max_restarts:
                logger.error("Reached AUTO_RESTART_MAX=%s; exiting.", max_restarts)
                raise
            time.sleep(max(0, delay_seconds))


if __name__ == "__main__":
    run_with_restart()
