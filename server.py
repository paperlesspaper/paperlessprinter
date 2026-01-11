import datetime as _dt
import json
import logging
import os
import struct
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import fitz  # PyMuPDF
import requests
from dotenv import load_dotenv


logger = logging.getLogger("ipp")


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

    # Redact secrets in logs (never log auth_value/token).
    safe_query_parts = []
    for k, v in qs.items():
        lk = k.lower()
        if lk in {"auth_value", "token", "auth"}:
            safe_query_parts.append(f"{k}=<redacted>")
        else:
            safe_query_parts.append(f"{k}={v[0] if v else ''}")
    safe_query = "&".join(safe_query_parts)
    safe_path_for_logs = path_only + (("?" + safe_query) if safe_query else "")
    return path_only, overrides, safe_path_for_logs


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


def _redacted_headers(headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in {"authorization", "cookie", "x-api-key", "x-ipp-token"}:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _op_name(operation_id: int) -> str:
    return {
        IPP_OP_PRINT_JOB: "Print-Job",
        IPP_OP_VALIDATE_JOB: "Validate-Job",
        IPP_OP_CREATE_JOB: "Create-Job",
        IPP_OP_SEND_DOCUMENT: "Send-Document",
        IPP_OP_GET_PRINTER_ATTRIBUTES: "Get-Printer-Attributes",
    }.get(operation_id, f"op-0x{operation_id:04x}")


def _read_exact(rfile, n: int) -> bytes:
    data = rfile.read(n)
    if data is None:
        return b""
    return data


def _read_chunked_body(rfile, max_bytes: int) -> bytes:
    body = bytearray()
    while True:
        # chunk-size line (hex) optionally followed by extensions
        line = rfile.readline(65536)
        if not line:
            break
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
            break
        if len(body) + chunk_size > max_bytes:
            raise ValueError("Chunked body exceeds limit")
        body += _read_exact(rfile, chunk_size)
        # consume CRLF
        _ = rfile.readline(3)
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
IPP_OP_GET_PRINTER_ATTRIBUTES = 0x000B


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


def build_get_printer_attributes_response(host_header: str, ipp_path: str) -> bytes:
    # Prefer an explicit port if provided in Host.
    host = host_header or "127.0.0.1"
    printer_uri = f"ipp://{host}{ipp_path}"

    attrs = bytearray()
    attrs += bytes([TAG_OPERATION_ATTRIBUTES])
    attrs += _ipp_attr_str(VT_CHARSET, "attributes-charset", "utf-8")
    attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "attributes-natural-language", "en")

    attrs += bytes([TAG_PRINTER_ATTRIBUTES])
    attrs += _ipp_attr_str(VT_URI, "printer-uri-supported", printer_uri)
    attrs += _ipp_attr_str(VT_KEYWORD, "uri-authentication-supported", "none")
    attrs += _ipp_attr_str(VT_KEYWORD, "uri-security-supported", "none")
    attrs += _ipp_attr_str(VT_NAME_WITHOUT_LANGUAGE, "printer-name", "ipp-to-png")
    attrs += _ipp_attr_str(VT_TEXT_WITHOUT_LANGUAGE, "printer-make-and-model", "ipp-to-png")
    attrs += _ipp_attr_str(VT_KEYWORD, "ipp-versions-supported", "1.1")
    attrs += _ipp_attr_i32_set(
        VT_ENUM,
        "operations-supported",
        [
            IPP_OP_PRINT_JOB,
            IPP_OP_VALIDATE_JOB,
            IPP_OP_CREATE_JOB,
            IPP_OP_SEND_DOCUMENT,
            IPP_OP_GET_PRINTER_ATTRIBUTES,
        ],
    )
    attrs += _ipp_attr_str(VT_CHARSET, "charset-configured", "utf-8")
    attrs += _ipp_attr_str(VT_CHARSET, "charset-supported", "utf-8")
    attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "natural-language-configured", "en")
    attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "generated-natural-language-supported", "en")
    attrs += _ipp_attr_bool("printer-is-accepting-jobs", True)
    attrs += _ipp_attr_i32(VT_ENUM, "printer-state", 3)  # idle
    attrs += _ipp_attr_str(VT_KEYWORD, "printer-state-reasons", "none")
    attrs += _ipp_attr_i32(VT_INTEGER, "queued-job-count", 0)
    attrs += _ipp_attr_str(VT_MIME_MEDIA_TYPE, "document-format-default", "application/pdf")
    attrs += _ipp_attr_str(VT_MIME_MEDIA_TYPE, "document-format-supported", "application/pdf")
    attrs += _ipp_attr_str(VT_KEYWORD, "compression-supported", "none")

    # Tell clients (notably macOS/CUPS) that this printer supports color.
    # Without these, macOS may default the print pipeline/preview to B/W.
    attrs += _ipp_attr_bool("color-supported", True)
    attrs += _ipp_attr_str_set(VT_KEYWORD, "print-color-mode-supported", ["auto", "color", "monochrome"])
    attrs += _ipp_attr_str(VT_KEYWORD, "print-color-mode-default", "auto")
    # Older/alternate attribute name still used by some clients.
    attrs += _ipp_attr_str_set(VT_KEYWORD, "output-mode-supported", ["auto", "color", "monochrome"])
    attrs += _ipp_attr_str(VT_KEYWORD, "output-mode-default", "auto")

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

        # capture a few common fields if present
        # names are bytes; values may not be utf-8, so decode carefully
        name_str = name.decode("utf-8", errors="ignore")
        if name_str in {"job-name", "document-format", "printer-uri", "requesting-user-name", "job-uri"}:
            meta[name_str] = value.decode("utf-8", errors="ignore")

        if name_str == "job-id" and len(value) == 4:
            try:
                meta[name_str] = str(struct.unpack(">i", value)[0])
            except Exception:
                pass

    document = raw[pos:]
    return meta, document


def render_pdf_to_pngs(pdf_bytes: bytes, dpi: int) -> Tuple[int, Dict[int, bytes]]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    total = doc.page_count
    pages: Dict[int, bytes] = {}
    for index in range(total):
        page = doc.load_page(index)
        pix = page.get_pixmap(dpi=dpi, alpha=False)
        pages[index + 1] = pix.tobytes("png")
    doc.close()
    return total, pages


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
    job_id: str,
    meta: Dict[str, str],
    total_pages: int,
    png_pages: Dict[int, bytes],
) -> None:
    logger.info("Upload enabled: POSTing first PNG to %s", endpoint)
    headers = {}
    if auth_header and auth_value:
        headers[auth_header] = auth_value

    # Single request, only the first page PNG.
    if not png_pages:
        raise ValueError("No PNG pages to POST")

    page_num = 1 if 1 in png_pages else sorted(png_pages.keys())[0]
    png_bytes = png_pages[page_num]
    logger.debug("POST payload: job_id=%s page=%s total_pages=%s png_bytes=%d", job_id, page_num, total_pages, len(png_bytes))

    data = {}
    if include_meta_fields:
        data = {
            "job_id": job_id,
            "request_id": meta.get("request_id", ""),
            "page": str(page_num),
            "total_pages": str(total_pages),
            "document_format": meta.get("document-format", ""),
            "job_name": meta.get("job-name", ""),
            "printer_uri": meta.get("printer-uri", ""),
            "user": meta.get("requesting-user-name", ""),
        }
    files = {
        (file_field or "file"): (
            f"{job_id}_p{page_num}.png",
            png_bytes,
            "image/png",
        )
    }
    try:
        resp = requests.post(endpoint, data=data, files=files, headers=headers, timeout=timeout_seconds)
        logger.info("POST response: status=%s", resp.status_code)
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
    except Exception:
        # Never crash the server thread on upload failures.
        logger.exception("Upload failed")


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

        # Cache per-client overrides when present. macOS may later omit them.
        client_ip = (self.client_address[0] if self.client_address else "") or ""
        user_agent = (self.headers.get("User-Agent") or "").strip()
        client_key = f"{client_ip}|{user_agent}"
        try:
            self.server.register_client_overrides(client_key, overrides)  # type: ignore[attr-defined]
        except Exception:
            logger.exception("Failed to register client overrides")

        # IMPORTANT: do not fall back to .env values here.
        # The per-request values (e.g. from a waitlist-generated printer URL) are the source of truth.
        effective_paper_id = (overrides.get("paper_id") or "").strip()
        effective_auth_value = (overrides.get("auth_value") or "").strip()

        # If not provided on this request, reuse the last overrides seen for this client.
        if not effective_paper_id or not effective_auth_value:
            try:
                cached = self.server.get_client_overrides(client_key)  # type: ignore[attr-defined]
            except Exception:
                cached = {}
                logger.exception("Failed to fetch client overrides")
            if not effective_paper_id:
                effective_paper_id = (cached.get("paper_id") or "").strip()
            if not effective_auth_value:
                effective_auth_value = (cached.get("auth_value") or "").strip()
        effective_endpoint = _resolve_endpoint_template(config.get("POST_ENDPOINT") or "", effective_paper_id)
        post_enabled = bool(effective_endpoint)

        if post_enabled and not effective_paper_id:
            logger.warning("Upload disabled for this request: missing paper_id (path=%s)", safe_path_for_logs)
            post_enabled = False

        shared = config.get("IPP_SHARED_TOKEN")
        if shared:
            token = self.headers.get("X-IPP-Token")
            if token != shared:
                logger.warning("Unauthorized: missing/invalid X-IPP-Token")
                self.send_error(401)
                return

        # Some clients (incl. macOS printing stack) use Expect: 100-continue.
        if (self.headers.get("Expect") or "").lower() == "100-continue":
            logger.debug("Sending 100-continue")
            self.send_response_only(100)
            self.end_headers()

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
        logger.info(
            "IPP request: op=%s request_id=%s job_name=%s document_format=%s document_bytes=%d",
            _op_name(operation_id),
            request_id,
            meta.get("job-name", ""),
            meta.get("document-format", ""),
            len(document),
        )

        # macOS probes printers with Get-Printer-Attributes before it will add them.
        if operation_id == IPP_OP_GET_PRINTER_ATTRIBUTES:
            logger.debug("Handling Get-Printer-Attributes")
            attr_bytes = build_get_printer_attributes_response(self.headers.get("Host", ""), config["IPP_PATH"])
            response = build_ipp_response_with_version(vmaj, vmin, 0x0000, request_id, attr_bytes)
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
            attrs = bytearray()
            attrs += bytes([TAG_OPERATION_ATTRIBUTES])
            attrs += _ipp_attr_str(VT_CHARSET, "attributes-charset", "utf-8")
            attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "attributes-natural-language", "en")
            response = build_ipp_response_with_version(vmaj, vmin, 0x0000, request_id, bytes(attrs))
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
            now = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_{job_id_int}_{job_uuid}"
            spool_dir.mkdir(parents=True, exist_ok=True)

            logger.info("Spooling Create-Job job-id=%s to %s", job_id_int, spool_dir)
            (spool_dir / "request.ipp").write_bytes(raw)
            (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
            self.server.register_job(job_id_int, spool_dir)  # type: ignore[attr-defined]
            # Persist any per-request overrides so Send-Document can reuse them.
            # macOS may not preserve query params/path segments on the follow-up request.
            try:
                self.server.register_job_overrides(job_id_int, overrides)  # type: ignore[attr-defined]
            except Exception:
                logger.exception("Failed to register job overrides")

            attrs = bytearray()
            attrs += bytes([TAG_OPERATION_ATTRIBUTES])
            attrs += _ipp_attr_str(VT_CHARSET, "attributes-charset", "utf-8")
            attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "attributes-natural-language", "en")
            attrs += bytes([0x02])  # job-attributes-tag
            attrs += _ipp_attr_i32(VT_INTEGER, "job-id", job_id_int)
            attrs += _ipp_attr_str(
                VT_URI,
                "job-uri",
                f"ipp://{self.headers.get('Host','127.0.0.1')}{config['IPP_PATH']}/job/{job_id_int}",
            )
            attrs += _ipp_attr_i32(VT_ENUM, "job-state", 3)  # pending
            attrs += _ipp_attr_str(VT_KEYWORD, "job-state-reasons", "none")

            response = build_ipp_response_with_version(vmaj, vmin, 0x0000, request_id, bytes(attrs))
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

            job_id_str = meta.get("job-id", "")
            job_id_int = int(job_id_str) if job_id_str.isdigit() else 0

            # Resolve overrides for this job.
            # If the HTTP path doesn't carry query params anymore (common on macOS), reuse Create-Job overrides.
            if job_id_int and (not effective_paper_id or not effective_auth_value):
                try:
                    job_overrides = self.server.get_job_overrides(job_id_int)  # type: ignore[attr-defined]
                except Exception:
                    job_overrides = {}
                    logger.exception("Failed to fetch job overrides")
                if not effective_paper_id:
                    effective_paper_id = (job_overrides.get("paper_id") or "").strip()
                if not effective_auth_value:
                    effective_auth_value = (job_overrides.get("auth_value") or "").strip()

            # Recompute endpoint/post_enabled now that we may have effective_paper_id.
            effective_endpoint = _resolve_endpoint_template(config.get("POST_ENDPOINT") or "", effective_paper_id)
            post_enabled = bool(effective_endpoint)

            # If paper_id is missing, the PaperlessPaper uploadSingleImage endpoint will be invalid.
            if post_enabled and not effective_paper_id:
                logger.warning("Upload disabled for this job: missing paper_id (path=%s)", safe_path_for_logs)
                post_enabled = False
            spool_dir = self.server.get_job_spool_dir(job_id_int) if job_id_int else None  # type: ignore[attr-defined]
            if spool_dir is None:
                job_uuid = uuid.uuid4().hex
                now = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_send_{job_uuid}"
                spool_dir.mkdir(parents=True, exist_ok=True)

            logger.info("Spooling Send-Document job-id=%s to %s", job_id_int or "(unknown)", spool_dir)
            (spool_dir / "request.ipp").write_bytes(raw)
            (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
            (spool_dir / "document.bin").write_bytes(document)

            if not document.startswith(b"%PDF"):
                logger.warning("Unsupported document payload (first bytes=%s)", document[:12])
                self.send_error(415, "Only PDF payloads are supported right now")
                return

            try:
                total, pages = render_pdf_to_pngs(document, dpi=config["IPP_RENDER_DPI"])
                for page_num, png_bytes in pages.items():
                    (spool_dir / f"page_{page_num:04d}.png").write_bytes(png_bytes)

                if pages:
                    first_page_num = 1 if 1 in pages else sorted(pages.keys())[0]
                    temp_dir = config.get("IPP_TEMP_DIR", "./temp")
                    temp_job_id = str(job_id_int) if job_id_int else "send"
                    store_first_png_in_temp(temp_dir, temp_job_id, first_page_num, pages[first_page_num])
                    logger.info(
                        "Wrote first PNG to %s",
                        (Path(temp_dir) / f"{temp_job_id}_p{first_page_num}.png").resolve(),
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
                            "include_meta_fields": bool(config.get("POST_INCLUDE_META_FIELDS", True)),
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

            except Exception as e:
                logger.exception("Render failed")
                self.send_error(500, f"Render failed: {e}")
                return

            attrs = bytearray()
            attrs += bytes([TAG_OPERATION_ATTRIBUTES])
            attrs += _ipp_attr_str(VT_CHARSET, "attributes-charset", "utf-8")
            attrs += _ipp_attr_str(VT_NATURAL_LANGUAGE, "attributes-natural-language", "en")
            response = build_ipp_response_with_version(vmaj, vmin, 0x0000, request_id, bytes(attrs))
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
        job_id = uuid.uuid4().hex
        now = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        spool_dir = Path(config["IPP_SPOOL_DIR"]).resolve() / f"{now}_{job_id}"
        spool_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Spooling job %s to %s", job_id, spool_dir)

        (spool_dir / "request.ipp").write_bytes(raw)
        (spool_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        (spool_dir / "document.bin").write_bytes(document)

        # Render (PDF-only for now)
        if not document.startswith(b"%PDF"):
            logger.warning("Unsupported document payload (first bytes=%s)", document[:12])
            self.send_error(415, "Only PDF payloads are supported right now")
            return

        try:
            total, pages = render_pdf_to_pngs(document, dpi=config["IPP_RENDER_DPI"])
            for page_num, png_bytes in pages.items():
                (spool_dir / f"page_{page_num:04d}.png").write_bytes(png_bytes)

            # Also store the first page PNG into /temp (or configured temp dir)
            if pages:
                first_page_num = 1 if 1 in pages else sorted(pages.keys())[0]
                temp_dir = config.get("IPP_TEMP_DIR", "./temp")
                store_first_png_in_temp(temp_dir, job_id, first_page_num, pages[first_page_num])
                logger.info("Wrote first PNG to %s", (Path(temp_dir) / f"{job_id}_p{first_page_num}.png").resolve())

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
                        "include_meta_fields": bool(config.get("POST_INCLUDE_META_FIELDS", True)),
                        "job_id": job_id,
                        "meta": meta,
                        "total_pages": total,
                        "png_pages": pages,
                    },
                    daemon=True,
                )
                thread.start()
            else:
                logger.info("Upload disabled (POST_ENDPOINT empty); skipping POST")

        except Exception as e:
            logger.exception("Render/POST failed")
            self.send_error(500, f"Render/POST failed: {e}")
            return

        # Minimal IPP success response
        # version 1.1, status successful-ok (0x0000), same request-id
        response = build_ipp_response_with_version(vmaj, vmin, 0x0000, request_id, b"")

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
        # keep default logging (stderr), but include client ip
        super().log_message(format, *args)


class IppServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self._job_lock = threading.Lock()
        self._next_job_id = 1
        self._jobs: Dict[int, Path] = {}
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

    def register_job_overrides(self, job_id: int, overrides: Dict[str, str]) -> None:
        # Store only the specific override keys we care about.
        paper_id = (overrides.get("paper_id") or "").strip()
        auth_value = (overrides.get("auth_value") or "").strip()
        with self._job_lock:
            self._job_overrides[job_id] = {"paper_id": paper_id, "auth_value": auth_value}

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
        "IPP_TEMP_DIR": _env_str("IPP_TEMP_DIR", "./temp"),
        "IPP_SHARED_TOKEN": os.getenv("IPP_SHARED_TOKEN") or "",
        "PAPER_ID": os.getenv("PAPER_ID") or "",
        "POST_ENDPOINT": _env_str("POST_ENDPOINT", ""),
        "POST_AUTH_HEADER": os.getenv("POST_AUTH_HEADER") or "",
        "POST_AUTH_VALUE": os.getenv("POST_AUTH_VALUE") or "",
        "POST_TIMEOUT_SECONDS": _env_int("POST_TIMEOUT_SECONDS", 30),
        "POST_FILE_FIELD": _env_str("POST_FILE_FIELD", "file"),
        "POST_INCLUDE_META_FIELDS": _env_bool("POST_INCLUDE_META_FIELDS", True),
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
    server.serve_forever()


if __name__ == "__main__":
    main()
