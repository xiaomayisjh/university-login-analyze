"""Shared captcha client: every recognition request uses AntiCAP API v1."""

import base64
import math
import os
from pathlib import Path
from urllib.parse import urlsplit

import requests
from dotenv import dotenv_values


DEFAULT_API_BASE_URL = "https://anticap.314521.xyz"
DEFAULT_TIMEOUT = 90
MAX_IMAGE_BYTES = 5 * 1024 * 1024
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class CaptchaSolverError(RuntimeError):
    """Recognition failure with machine-readable service diagnostics."""

    def __init__(self, code, message, status_code=None, request_id=None):
        self.code = code
        self.status_code = status_code
        self.request_id = request_id
        details = code
        if status_code is not None:
            details += " HTTP {}".format(status_code)
        if request_id:
            details += " request_id={}".format(request_id)
        super().__init__("AntiCAP [{}]: {}".format(details, message))


def _read_image_bytes(image_path=None, image_data=None):
    if image_path:
        with open(image_path, "rb") as image:
            # Bound the read before encoding, including oversized files.
            data = image.read(MAX_IMAGE_BYTES + 1)
    elif image_data is not None:
        if not isinstance(image_data, (bytes, bytearray, memoryview)):
            raise TypeError("image_data must be bytes, bytearray or memoryview")
        data = image_data
    else:
        raise ValueError("Provide image_path or image_data")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size == 0:
        raise ValueError("Captcha image is empty")
    if size > MAX_IMAGE_BYTES:
        raise ValueError("Captcha image exceeds the 5 MiB API limit")
    return bytes(data)


def _image_to_base64(image_path=None, image_data=None):
    return base64.b64encode(_read_image_bytes(image_path, image_data)).decode("ascii")


def _normalize_api_base_url(value):
    if not isinstance(value, str):
        raise ValueError("ANTICAP_API_BASE_URL must be an HTTP(S) service URL")
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in value)
    ):
        raise ValueError("ANTICAP_API_BASE_URL must be an HTTP(S) service URL without credentials, query or fragment")
    # Force validation of a supplied port before any credential-bearing call.
    _ = parsed.port
    if not value.endswith("/api/v1"):
        value += "/api/v1"
    return value


class CaptchaSolver:
    """Remote-only AntiCAP client with the existing login-script interfaces.

    Configuration precedence: explicit arguments, process environment, then
    project-root .env. No local model, old OCR server or LLM fallback is used.
    """

    def __init__(self, api_key=None, api_base_url=None, timeout=None, session=None):
        settings = dotenv_values(_ENV_FILE, interpolate=False) if _ENV_FILE.is_file() else {}

        def setting(name, explicit, default=None):
            if explicit is not None:
                return explicit
            return os.environ.get(name, settings.get(name, default))

        key = setting("ANTICAP_API_KEY", api_key)
        if not isinstance(key, str) or not key.strip():
            raise CaptchaSolverError("CONFIGURATION_ERROR", "Set ANTICAP_API_KEY in the project .env or process environment")
        self._api_key = key.strip()
        self.api_base_url = _normalize_api_base_url(setting("ANTICAP_API_BASE_URL", api_base_url, DEFAULT_API_BASE_URL))
        timeout_value = setting("ANTICAP_TIMEOUT", timeout, DEFAULT_TIMEOUT)
        try:
            self.timeout = float(timeout_value)
        except (TypeError, ValueError):
            raise ValueError("ANTICAP_TIMEOUT must be a positive, finite number of seconds") from None
        if isinstance(timeout_value, bool) or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("ANTICAP_TIMEOUT must be a positive, finite number of seconds")
        self._owns_session = session is None
        self.session = requests.Session() if session is None else session
        self.last_meta = {}

    def image_to_base64(self, image_path=None, image_data=None):
        return _image_to_base64(image_path, image_data)

    def _error(self, code, message, status_code=None, request_id=None):
        # Neither server diagnostics nor HTTP exception strings should leak keys.
        def redact(value):
            return str(value).replace(self._api_key, "[REDACTED]")

        return CaptchaSolverError(
            redact(code),
            redact(message),
            status_code=status_code,
            request_id=redact(request_id) if request_id else None,
        )

    def _request(self, endpoint, payload):
        self.last_meta = {}
        try:
            response = self.session.post(
                self.api_base_url + "/" + endpoint,
                json=payload,
                headers={
                    "Authorization": "Bearer " + self._api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise self._error("NETWORK_ERROR", "Request failed ({})".format(type(exc).__name__)) from None

        status = response.status_code
        request_id = response.headers.get("X-Request-ID")
        try:
            body = response.json()
        except ValueError:
            code = "INVALID_RESPONSE" if 200 <= status < 300 else "HTTP_ERROR"
            raise self._error(code, "Service returned a non-JSON response", status, request_id) from None
        if not isinstance(body, dict):
            raise self._error("INVALID_RESPONSE", "Expected a JSON object", status, request_id)
        if not 200 <= status < 300 or "error" in body:
            error = body.get("error")
            error = error if isinstance(error, dict) else {}
            raise self._error(
                error.get("code") or "HTTP_ERROR",
                error.get("message") or "Service rejected the request",
                status,
                body.get("request_id") or request_id,
            )
        if "result" not in body:
            raise self._error("INVALID_RESPONSE", "Response is missing result", status, request_id)
        meta = body.get("meta", {})
        if not isinstance(meta, dict):
            raise self._error("INVALID_RESPONSE", "Response meta must be an object", status, request_id)
        self.last_meta = dict(meta)
        if meta.get("status") == "no_match":
            raise self._error("NO_MATCH", "Captcha was not recognized", status, meta.get("request_id") or request_id)
        return body["result"]

    def solve_image_captcha(self, image_path=None, image_data=None):
        """Return OCR text, preserving case and removing outer whitespace."""
        result = self._request("ocr", {"img_base64": _image_to_base64(image_path, image_data)})
        if result is None or (isinstance(result, str) and not result.strip()):
            raise self._error("NO_MATCH", "OCR returned no text", request_id=self.last_meta.get("request_id"))
        if not isinstance(result, str):
            raise self._error("INVALID_RESPONSE", "OCR result must be a string", request_id=self.last_meta.get("request_id"))
        return result.strip()

    def solve_slide_captcha(self, bg_image_path=None, slide_image_path=None,
                            bg_image_data=None, slide_image_data=None, full_image_data=None):
        """Return {"x": x1, "target": [x1, y1, x2, y2]} in original pixels.

        Historical argument names are intentionally preserved: bg_image_* is
        the small slider/target image; slide_image_* is the large background.
        AntiCAP requires both images; a single full_image_data is insufficient.
        Site-specific scaling from match position to drag distance stays in the
        calling script, including WHU's canvas-width conversion.
        """
        has_target = bool(bg_image_path) or bg_image_data is not None
        has_background = bool(slide_image_path) or slide_image_data is not None
        if not has_target or not has_background:
            raise ValueError("AntiCAP slider/match requires both target and background images, not only full_image_data")
        payload = {
            "target_base64": _image_to_base64(bg_image_path, bg_image_data),
            "background_base64": _image_to_base64(slide_image_path, slide_image_data),
        }
        result = self._request("slider/match", payload)
        if result is None:
            raise self._error("NO_MATCH", "Slider returned no match", request_id=self.last_meta.get("request_id"))
        target = result.get("target") if isinstance(result, dict) else None
        if target == [0, 0, 0, 0]:
            raise self._error("NO_MATCH", "Slider returned a zero match box", request_id=self.last_meta.get("request_id"))
        if (
            not isinstance(target, list)
            or len(target) != 4
            or any(type(coordinate) is not int or coordinate < 0 for coordinate in target)
            or target[2] <= target[0]
            or target[3] <= target[1]
        ):
            raise self._error("INVALID_RESPONSE", "Slider result must contain a valid four-integer target box", request_id=self.last_meta.get("request_id"))
        return {"x": target[0], "target": target}

    def close(self):
        if self._owns_session:
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class AntiCAPSolver(CaptchaSolver):
    """Compatibility name; now calls the API instead of loading local models."""

    def __init__(self, show_banner=False, **kwargs):
        super().__init__(**kwargs)


class HybridCaptchaSolver(CaptchaSolver):
    """Compatibility entry point; all legacy selectors now use AntiCAP API.

    primary and fallback are accepted for existing callers but never enable
    another provider, including when CAPTCHA_ENABLE_LLM is set.
    """

    def __init__(self, primary="anticap", fallback=False, **kwargs):
        self.primary = primary
        self.fallback = fallback
        super().__init__(**kwargs)
