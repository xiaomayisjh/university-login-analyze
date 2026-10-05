import base64
from io import BytesIO
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests
from PIL import Image

from captcha_solver.captcha_solver import CaptchaSolver, HybridCaptchaSolver

solver_module = importlib.import_module("captcha_solver.captcha_solver")


class FakeResponse:
    def __init__(self, status_code=200, body=None, json_error=None):
        self.status_code = status_code
        self._body = {} if body is None else body
        self.json_error = json_error
        self.headers = {}

    def json(self):
        if self.json_error:
            raise self.json_error
        return self._body


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse(body={"result": "A7K9"})
        self.error = error
        self.calls = []
        self.closed = False

    def post(self, url, *, json, headers, timeout, allow_redirects):
        self.calls.append(
            {
                "url": url,
                "json": json,
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        if self.error:
            raise self.error
        return self.response

    def close(self):
        self.closed = True


class CaptchaSolverApiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp_path = Path(temp.name)
        self.env_file = self.temp_path / ".env"
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        env_path = patch.object(solver_module, "_ENV_FILE", self.env_file, create=True)
        env_path.start()
        self.addCleanup(env_path.stop)

    def make_solver(self, response=None, error=None, **kwargs):
        session = FakeSession(response, error)
        solver = CaptchaSolver(api_key="ac_test-key", session=session, **kwargs)
        return solver, session

    def test_ocr_uses_anticap_v1_api_and_returns_trimmed_result(self):
        solver, session = self.make_solver(
            FakeResponse(body={"result": " A7K9\n", "meta": {"request_id": "ocr-123", "status": "ok"}}),
            api_base_url="https://anticap.example/api/v1/",
            timeout=37,
        )
        self.assertEqual(solver.solve_image_captcha(image_data=b"captcha-bytes"), "A7K9")
        self.assertEqual(len(session.calls), 1)
        call = session.calls[0]
        self.assertEqual(call["url"], "https://anticap.example/api/v1/ocr")
        self.assertEqual(call["json"], {"img_base64": base64.b64encode(b"captcha-bytes").decode("ascii")})
        self.assertEqual(call["headers"]["Authorization"], "Bearer ac_test-key")
        self.assertEqual(call["timeout"], 37)
        self.assertFalse(call["allow_redirects"])
        self.assertEqual(solver.last_meta["request_id"], "ocr-123")

    def test_gif_captcha_is_transcoded_to_api_supported_png(self):
        buffer = BytesIO()
        Image.new("RGB", (3, 2), (240, 80, 40)).save(buffer, format="GIF")
        solver, session = self.make_solver()

        solver.solve_image_captcha(image_data=buffer.getvalue())

        uploaded = base64.b64decode(session.calls[0]["json"]["img_base64"])
        with Image.open(BytesIO(uploaded)) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.size, (3, 2))

    def test_ocr_reads_an_image_path(self):
        image_path = self.temp_path / "captcha.png"
        image_path.write_bytes(b"image-from-path")
        solver, session = self.make_solver()
        self.assertEqual(solver.solve_image_captcha(image_path=image_path), "A7K9")
        self.assertEqual(session.calls[0]["json"]["img_base64"], base64.b64encode(b"image-from-path").decode("ascii"))

    def test_image_to_base64_preserves_legacy_helper(self):
        solver, session = self.make_solver()
        self.assertEqual(solver.image_to_base64(image_data=bytearray(b"123")), "MTIz")
        self.assertEqual(session.calls, [])

    def test_invalid_image_inputs_fail_before_network_request(self):
        for kwargs in ({}, {"image_data": b""}, {"image_data": "not-bytes"}):
            with self.subTest(kwargs=kwargs):
                solver, session = self.make_solver()
                with self.assertRaises((TypeError, ValueError)):
                    solver.solve_image_captcha(**kwargs)
                self.assertEqual(session.calls, [])

    def test_oversize_image_fails_before_network_request(self):
        solver, session = self.make_solver()
        with self.assertRaisesRegex(ValueError, "5 MiB"):
            solver.solve_image_captcha(image_data=b"x" * (5 * 1024 * 1024 + 1))
        self.assertEqual(session.calls, [])

    def test_memoryview_limit_uses_byte_count_not_element_count(self):
        solver, session = self.make_solver()
        # A wide-element view has fewer elements than bytes, but the same
        # encoded upload size as its original byte buffer.
        image = memoryview(bytearray(5 * 1024 * 1024 + 2)).cast("H")
        with self.assertRaisesRegex(ValueError, "5 MiB"):
            solver.solve_image_captcha(image_data=image)
        self.assertEqual(session.calls, [])

    def test_non_contiguous_memoryview_can_be_base64_encoded(self):
        solver, session = self.make_solver()
        self.assertEqual(solver.image_to_base64(image_data=memoryview(b"a1b2c3")[::2]), "YWJj")
        self.assertEqual(session.calls, [])

    def test_slider_maps_legacy_arguments_to_anticap_payload(self):
        solver, session = self.make_solver(FakeResponse(body={"result": {"target": [12, 8, 44, 40]}}))
        result = solver.solve_slide_captcha(bg_image_data=b"target-image", slide_image_data=b"background-image")
        self.assertEqual(result, {"x": 12, "target": [12, 8, 44, 40]})
        self.assertEqual(session.calls[0]["url"], "https://anticap.314521.xyz/api/v1/slider/match")
        self.assertEqual(
            session.calls[0]["json"],
            {
                "target_base64": base64.b64encode(b"target-image").decode("ascii"),
                "background_base64": base64.b64encode(b"background-image").decode("ascii"),
            },
        )

    def test_slider_reads_legacy_image_paths(self):
        target = self.temp_path / "target.png"
        background = self.temp_path / "background.png"
        target.write_bytes(b"target")
        background.write_bytes(b"background")
        solver, session = self.make_solver(FakeResponse(body={"result": {"target": [0, 1, 20, 21]}}))
        self.assertEqual(solver.solve_slide_captcha(target, background)["x"], 0)
        self.assertEqual(session.calls[0]["json"]["target_base64"], base64.b64encode(b"target").decode("ascii"))

    def test_single_image_slider_is_rejected_without_fallback(self):
        solver, session = self.make_solver()
        with self.assertRaisesRegex(ValueError, "target.*background"):
            solver.solve_slide_captcha(full_image_data=b"single-image")
        self.assertEqual(session.calls, [])

    def test_incomplete_slider_inputs_are_rejected_without_request(self):
        solver, session = self.make_solver()
        with self.assertRaises(ValueError):
            solver.solve_slide_captcha(bg_image_data=b"only-target")
        self.assertEqual(session.calls, [])

    def test_null_empty_and_no_match_ocr_raise_explicit_errors(self):
        for body in (
            {"result": None},
            {"result": ""},
            {"result": " \n"},
            {"result": "abc", "meta": {"status": "no_match"}},
        ):
            with self.subTest(body=body):
                solver, session = self.make_solver(FakeResponse(body=body))
                with self.assertRaisesRegex(RuntimeError, "NO_MATCH"):
                    solver.solve_image_captcha(image_data=b"image")
                self.assertEqual(len(session.calls), 1)

    def test_invalid_ocr_result_type_raises_contract_error(self):
        solver, _ = self.make_solver(FakeResponse(body={"result": {"text": "abc"}}))
        with self.assertRaisesRegex(RuntimeError, "INVALID_RESPONSE"):
            solver.solve_image_captcha(image_data=b"image")

    def test_invalid_or_unmatched_slider_results_are_rejected(self):
        for target in (None, [], [0, 0, 0, 0], [1, 2], [-1, 2, 5, 8], [3, 4, 2, 9], [True, 2, 4, 8], [1.5, 2, 4, 8]):
            with self.subTest(target=target):
                result = None if target is None else {"target": target}
                solver, _ = self.make_solver(FakeResponse(body={"result": result}))
                with self.assertRaises(RuntimeError):
                    solver.solve_slide_captcha(bg_image_data=b"target", slide_image_data=b"background")

    def test_api_errors_preserve_code_status_and_request_id(self):
        for status, code in ((401, "UNAUTHORIZED"), (422, "INVALID_INPUT"), (429, "ENGINE_BUSY"), (503, "ENGINE_NOT_READY"), (504, "INFERENCE_TIMEOUT")):
            with self.subTest(status=status):
                body = {"error": {"code": code, "message": "service error"}, "request_id": "req-123"}
                solver, session = self.make_solver(FakeResponse(status, body))
                with self.assertRaises(RuntimeError) as caught:
                    solver.solve_image_captcha(image_data=b"image")
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.status_code, status)
                self.assertEqual(caught.exception.request_id, "req-123")
                self.assertIn(code, str(caught.exception))
                self.assertEqual(len(session.calls), 1)

    def test_api_error_messages_redact_api_key(self):
        body = {"error": {"code": "UNAUTHORIZED", "message": "bad token ac_test-key"}}
        solver, _ = self.make_solver(FakeResponse(401, body))
        with self.assertRaises(RuntimeError) as caught:
            solver.solve_image_captcha(image_data=b"image")
        self.assertNotIn("ac_test-key", str(caught.exception))

    def test_invalid_json_and_missing_result_are_rejected(self):
        for response in (FakeResponse(json_error=ValueError("invalid JSON")), FakeResponse(body=[]), FakeResponse(body={"data": "abc"})):
            with self.subTest(response=response):
                solver, session = self.make_solver(response)
                with self.assertRaisesRegex(RuntimeError, "INVALID_RESPONSE"):
                    solver.solve_image_captcha(image_data=b"image")
                self.assertEqual(len(session.calls), 1)

    def test_transport_errors_are_wrapped_without_secret_or_fallback(self):
        for error in (requests.Timeout("timeout ac_test-key"), requests.ConnectionError("failed ac_test-key")):
            with self.subTest(error=type(error).__name__):
                solver, session = self.make_solver(error=error)
                with self.assertRaisesRegex(RuntimeError, "NETWORK_ERROR") as caught:
                    solver.solve_image_captcha(image_data=b"image")
                self.assertNotIn("ac_test-key", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(len(session.calls), 1)

    def test_project_env_is_loaded_independent_of_current_directory(self):
        self.env_file.write_text("ANTICAP_API_KEY=ac_file-key\nANTICAP_API_BASE_URL=https://file.example\nANTICAP_TIMEOUT=45\n", encoding="utf-8")
        session = FakeSession()
        with patch("os.getcwd", return_value=str(self.temp_path / "elsewhere")):
            solver = CaptchaSolver(session=session)
            solver.solve_image_captcha(image_data=b"image")
        call = session.calls[0]
        self.assertEqual(call["headers"]["Authorization"], "Bearer ac_file-key")
        self.assertEqual(call["url"], "https://file.example/api/v1/ocr")
        self.assertEqual(call["timeout"], 45)
        self.assertNotIn("ANTICAP_API_KEY", os.environ)

    def test_environment_overrides_project_env(self):
        self.env_file.write_text("ANTICAP_API_KEY=ac_file-key\nANTICAP_API_BASE_URL=https://file.example\n", encoding="utf-8")
        os.environ.update(ANTICAP_API_KEY="ac_env-key", ANTICAP_API_BASE_URL="https://env.example", ANTICAP_TIMEOUT="23")
        session = FakeSession()
        solver = CaptchaSolver(session=session)
        solver.solve_image_captcha(image_data=b"image")
        self.assertEqual(session.calls[0]["headers"]["Authorization"], "Bearer ac_env-key")
        self.assertEqual(session.calls[0]["url"], "https://env.example/api/v1/ocr")
        self.assertEqual(session.calls[0]["timeout"], 23)

    def test_explicit_configuration_overrides_environment(self):
        os.environ.update(ANTICAP_API_KEY="ac_env-key", ANTICAP_API_BASE_URL="https://env.example", ANTICAP_TIMEOUT="23")
        solver, session = self.make_solver(api_base_url="https://explicit.example", timeout=18)
        solver.solve_image_captcha(image_data=b"image")
        self.assertEqual(session.calls[0]["headers"]["Authorization"], "Bearer ac_test-key")
        self.assertEqual(session.calls[0]["url"], "https://explicit.example/api/v1/ocr")
        self.assertEqual(session.calls[0]["timeout"], 18)

    def test_missing_api_key_is_rejected_before_network_call(self):
        for key in (None, "", "  "):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeError, "ANTICAP_API_KEY"):
                    CaptchaSolver(api_key=key)

    def test_invalid_api_base_url_is_rejected(self):
        for url in ("", "anticap.example", "ftp://example", "https://user:password@example", "https://example?token=abc", "https://example/#frag", "https://example:bad"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    self.make_solver(api_base_url=url)

    def test_base_urls_accept_service_root_or_api_v1_prefix(self):
        for url in ("https://example", "https://example/", "https://example/api/v1", "https://example/api/v1/"):
            with self.subTest(url=url):
                solver, session = self.make_solver(api_base_url=url)
                solver.solve_image_captcha(image_data=b"image")
                self.assertEqual(session.calls[0]["url"], "https://example/api/v1/ocr")

    def test_invalid_timeouts_are_rejected(self):
        for timeout in (0, -1, "bad", float("nan"), float("inf"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    self.make_solver(timeout=timeout)

    def test_hybrid_legacy_selectors_always_use_only_anticap_api(self):
        os.environ["CAPTCHA_ENABLE_LLM"] = "1"
        for primary in ("server", "modelscope", "anticap"):
            with self.subTest(primary=primary):
                session = FakeSession()
                solver = HybridCaptchaSolver(primary=primary, fallback=True, api_key="ac_test-key", session=session)
                self.assertEqual(solver.solve_image_captcha(image_data=b"image"), "A7K9")
                self.assertEqual(session.calls[0]["url"], "https://anticap.314521.xyz/api/v1/ocr")

    def test_anticap_solver_legacy_name_uses_remote_api(self):
        session = FakeSession()
        solver = solver_module.AntiCAPSolver(show_banner=False, api_key="ac_test-key", session=session)
        self.assertEqual(solver.solve_image_captcha(image_data=b"image"), "A7K9")
        self.assertEqual(session.calls[0]["url"], "https://anticap.314521.xyz/api/v1/ocr")

    def test_package_exports_both_legacy_import_styles(self):
        package = importlib.import_module("captcha_solver")
        self.assertIs(package.CaptchaSolver, CaptchaSolver)
        self.assertIs(package.HybridCaptchaSolver, HybridCaptchaSolver)

    def test_close_preserves_caller_owned_session(self):
        solver, session = self.make_solver()
        solver.close()
        self.assertFalse(session.closed)

    def test_context_manager_closes_client_owned_session(self):
        session = FakeSession()
        with patch.object(solver_module.requests, "Session", return_value=session):
            with CaptchaSolver(api_key="ac_test-key") as solver:
                self.assertEqual(solver.solve_image_captcha(image_data=b"image"), "A7K9")
        self.assertTrue(session.closed)


if __name__ == "__main__":
    unittest.main()
