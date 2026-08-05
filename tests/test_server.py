import io
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import fitz
from PIL import Image

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

    def test_windows_https_discovery_is_advertised_as_full_ipps_uri(self):
        headers = {
            "Host": "paperlesspaper-print:8631",
            "X-Forwarded-Host": "print.paperlesspaper.de",
            "X-Forwarded-Proto": "https",
        }

        uri = server._external_ipp_uri(
            headers,
            "/ipp/print",
            "/ipp/print",
            "https://print.paperlesspaper.de/ipp/print/paper-123/secret-token",
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

    def test_advertises_both_named_open_paper_media_sizes(self):
        profile = server._parse_target_profiles(
            '{"paper-123":{"width":800,"height":480}}'
        )["paper-123"]

        response = server.build_get_printer_attributes_response(
            "print.example",
            "/ipp/print/paper-123/secret-token",
            scheme="ipps",
            target_profile=profile,
            render_dpi=150,
        )

        self.assertIn(b"custom_open-paper-l-13.3-inch_270.93x203.20mm", response)
        self.assertIn(b"custom_openpaper-7-7.3-inch_135.47x81.28mm", response)
        self.assertIn(b"Open Paper L (13.3 inch)", response)
        self.assertIn(b"OpenPaper 7 (7.3 inch)", response)
        self.assertIn(struct.pack(">i", 27093), response)
        self.assertIn(struct.pack(">i", 20320), response)
        self.assertIn(struct.pack(">i", 13547), response)
        self.assertIn(struct.pack(">i", 8128), response)
        self.assertNotIn(b"iso_a4_210x297mm", response)

        small_media, _ = server._target_media_definition(
            server._selectable_target_profiles(profile)[0],
            150,
        )
        self.assertIn(
            server._ipp_attr_str(server.VT_KEYWORD, "media-default", small_media),
            response,
        )

    def test_media_col_selection_drives_exact_target_profile(self):
        profiles = server._selectable_target_profiles()
        small_profile = next(profile for profile in profiles if profile["width"] == 800)
        small_media, small_size = server._target_media_definition(small_profile, 150)

        raw = bytearray(b"\x02\x00")
        raw += struct.pack(">H", server.IPP_OP_PRINT_JOB)
        raw += struct.pack(">I", 4321)
        raw += bytes([server.TAG_OPERATION_ATTRIBUTES])
        raw += server._ipp_attr_str(server.VT_CHARSET, "attributes-charset", "utf-8")
        raw += server._ipp_attr_str(
            server.VT_NATURAL_LANGUAGE,
            "attributes-natural-language",
            "en",
        )
        raw += server._ipp_attr_str(
            server.VT_URI,
            "printer-uri",
            "ipps://print.example/ipp/print/paper-123/secret-token",
        )
        raw += bytes([0x02])
        raw += server._ipp_collection(
            "media-col",
            [
                ("media-size", server.VT_BEGIN_COLLECTION, small_size),
                ("media-key", server.VT_KEYWORD, small_media),
                ("media-size-name", server.VT_KEYWORD, small_media),
            ],
        )
        raw += bytes([server.TAG_END_OF_ATTRIBUTES])
        raw += b"%PDF-test"

        meta, document = server.parse_ipp_request(bytes(raw))
        selected = server._target_profile_for_job(meta, 150)

        self.assertEqual(meta["media-key"], small_media)
        self.assertEqual(meta["media-size-name"], small_media)
        self.assertEqual(meta["media-x-dimension"], "13547")
        self.assertEqual(meta["media-y-dimension"], "8128")
        self.assertEqual((selected["width"], selected["height"]), (800, 480))
        self.assertEqual(document, b"%PDF-test")

        restored = server._stored_job_context(
            {"paper_id": "paper-123", **server._media_job_context(meta)}
        )

        self.assertEqual(restored["paper_id"], "paper-123")
        self.assertEqual(restored["media-size-name"], small_media)
        self.assertEqual(restored["media-x-dimension"], "13547")


class TargetProfileTests(unittest.TestCase):
    def test_profiles_are_validated_and_support_a_fallback(self):
        profiles = server._parse_target_profiles(
            """{
                "paper-large": {"width": 1600, "height": 1200},
                "*": {
                    "width": 800,
                    "height": 480,
                    "fit": "cover",
                    "auto_rotate": false,
                    "background": "#eeeeee"
                }
            }"""
        )

        large = server._target_profile_for_paper_id(profiles, "paper-large")
        fallback = server._target_profile_for_paper_id(profiles, "unknown-paper")

        self.assertEqual((large["width"], large["height"]), (1600, 1200))
        self.assertEqual(large["fit"], "contain")
        self.assertTrue(large["auto_rotate"])
        self.assertEqual((fallback["width"], fallback["height"]), (800, 480))
        self.assertEqual(fallback["fit"], "cover")

    def test_invalid_profiles_fail_fast(self):
        invalid_profiles = [
            '[]',
            '{"paper":{"width":0,"height":480}}',
            '{"paper":{"width":800,"height":480,"fit":"unknown"}}',
            '{"paper":{"width":800,"height":480,"auto_rotate":"yes"}}',
        ]
        for raw in invalid_profiles:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                server._parse_target_profiles(raw)


class RenderingTests(unittest.TestCase):
    @staticmethod
    def _png(width, height, color):
        output = io.BytesIO()
        Image.new("RGB", (width, height), color).save(output, format="PNG")
        return output.getvalue()

    def test_contain_produces_exact_canvas_with_centered_background(self):
        profile = {
            "width": 800,
            "height": 480,
            "fit": "contain",
            "auto_rotate": True,
            "background": "#ffffff",
        }

        result = server.fit_png_to_target(self._png(400, 400, "#ff0000"), profile)

        with Image.open(io.BytesIO(result)) as image:
            self.assertEqual(image.size, (800, 480))
            self.assertEqual(image.getpixel((0, 0)), (255, 255, 255))
            self.assertEqual(image.getpixel((400, 240)), (255, 0, 0))

    def test_auto_rotate_uses_the_target_orientation(self):
        profile = {
            "width": 800,
            "height": 480,
            "fit": "contain",
            "auto_rotate": True,
            "background": "#ffffff",
        }

        result = server.fit_png_to_target(self._png(480, 800, "#00ff00"), profile)

        with Image.open(io.BytesIO(result)) as image:
            self.assertEqual(image.size, (800, 480))
            self.assertEqual(image.getpixel((0, 0)), (0, 255, 0))
            self.assertEqual(image.getpixel((799, 479)), (0, 255, 0))

    def test_cover_and_stretch_produce_both_supported_device_sizes(self):
        source = self._png(640, 480, "#0000ff")
        for width, height, fit in [(1600, 1200, "cover"), (800, 480, "stretch")]:
            with self.subTest(width=width, height=height, fit=fit):
                profile = {
                    "width": width,
                    "height": height,
                    "fit": fit,
                    "auto_rotate": True,
                    "background": "#ffffff",
                }
                result = server.fit_png_to_target(source, profile)
                with Image.open(io.BytesIO(result)) as image:
                    self.assertEqual(image.size, (width, height))

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
