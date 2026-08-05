import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import fitz

import server


class RoutingTests(unittest.TestCase):
    def test_path_overrides_are_extracted_and_token_is_redacted(self):
        path, overrides, safe_path = server._split_ipp_path_and_overrides(
            "/ipp/print/paper-123/secret-token", "/ipp/print"
        )

        self.assertEqual(path, "/ipp/print/paper-123/secret-token")
        self.assertEqual(overrides, {"paper_id": "paper-123", "auth_value": "secret-token"})
        self.assertEqual(safe_path, "/ipp/print/paper-123/<redacted>")
        self.assertEqual(
            server._redact_http_request_line(
                "POST /ipp/print/paper-123/secret-token HTTP/1.1",
                "/ipp/print",
            ),
            "POST /ipp/print/paper-123/<redacted> HTTP/1.1",
        )

    def test_windows_base_path_recovers_full_forwarded_ipps_uri(self):
        headers = {
            "Host": "paperlesspaper-print:8631",
            "X-Forwarded-Host": "print.paperlesspaper.de",
            "X-Forwarded-Proto": "https",
        }

        uri = server._external_ipp_uri(
            headers,
            "/ipp/print",
            "/ipp/print",
            "ipps://print.paperlesspaper.de/ipp/print/paper-123/secret-token",
        )

        self.assertEqual(
            uri,
            "ipps://print.paperlesspaper.de/ipp/print/paper-123/secret-token",
        )
        self.assertEqual(
            server._overrides_from_ipp_uri(uri, "/ipp/print"),
            {"paper_id": "paper-123", "auth_value": "secret-token"},
        )


class IppParsingTests(unittest.TestCase):
    def test_parser_preserves_printer_uri_and_requested_attributes(self):
        printer_uri = "ipps://print.example/ipp/print/paper-123/secret-token"
        raw = bytearray(b"\x02\x00")
        raw += struct.pack(">H", server.IPP_OP_GET_PRINTER_ATTRIBUTES)
        raw += struct.pack(">I", 1234)
        raw += bytes([server.TAG_OPERATION_ATTRIBUTES])
        raw += server._ipp_attr_str(server.VT_CHARSET, "attributes-charset", "utf-8")
        raw += server._ipp_attr_str(
            server.VT_NATURAL_LANGUAGE,
            "attributes-natural-language",
            "en",
        )
        raw += server._ipp_attr_str(server.VT_URI, "printer-uri", printer_uri)
        raw += server._ipp_attr_str(
            server.VT_KEYWORD,
            "requested-attributes",
            "printer-uri-supported",
        )
        raw += server._ipp_attr_str(
            server.VT_KEYWORD,
            "requested-attributes",
            "document-format-supported",
        )
        raw += bytes([server.TAG_END_OF_ATTRIBUTES])

        meta, document = server.parse_ipp_request(bytes(raw))

        self.assertEqual(document, b"")
        self.assertEqual(meta["printer-uri"], printer_uri)
        self.assertEqual(
            meta["requested-attributes"],
            "printer-uri-supported,document-format-supported",
        )
        self.assertEqual(
            meta["_operation-attribute-names"].split(",")[:2],
            ["attributes-charset", "attributes-natural-language"],
        )

    def test_ipps_capabilities_are_driverless_and_keep_full_uri(self):
        uri = "ipps://print.example/ipp/print/paper-123/secret-token"

        response = server.build_get_printer_attributes_response(
            "print.example",
            "/ipp/print/paper-123/secret-token",
            scheme="ipps",
            printer_uri=uri,
        )

        self.assertIn(uri.encode(), response)
        self.assertIn(b"uri-security-supported", response)
        self.assertIn(b"tls", response)
        self.assertIn(b"application/pdf", response)
        self.assertIn(b"image/jpeg", response)
        self.assertIn(b"ipp-versions-supported", response)
        self.assertIn(b"media-col-database", response)


class RenderingTests(unittest.TestCase):
    def test_pwg_raster_round_trip_when_cups_filters_are_available(self):
        cupsfilter = shutil.which("cupsfilter")
        converter = server._pwg_raster_converter_command()
        if not cupsfilter or not converter:
            self.skipTest("CUPS PWG Raster filters are not installed")

        document = fitz.open()
        page = document.new_page(width=595, height=842)
        page.insert_text((72, 72), "paperlesspaper PWG Raster test")
        pdf_bytes = document.tobytes()
        document.close()

        with tempfile.TemporaryDirectory(prefix="paperlesspaper-pwg-test-") as temp_dir:
            pdf_path = Path(temp_dir) / "source.pdf"
            pdf_path.write_bytes(pdf_bytes)
            result = subprocess.run(
                [cupsfilter, "-m", "image/pwg-raster", "-P", "/dev/null", str(pdf_path)],
                capture_output=True,
                check=False,
            )

        if result.returncode != 0:
            self.fail(result.stderr.decode("utf-8", errors="replace"))
        self.assertTrue(result.stdout.startswith((b"RaS2", b"RaS3", b"RaS4")))

        total, pages = server.render_pwg_raster_to_pngs(result.stdout, dpi=150)

        self.assertEqual(total, 1)
        self.assertTrue(pages[1].startswith(b"\x89PNG\r\n\x1a\n"))


if __name__ == "__main__":
    unittest.main()
