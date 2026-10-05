# -*- coding: utf-8 -*-
"""Pure HTTP client for the HUST CAS password login flow.

The HUST page uses a standard CAS form, but the browser JavaScript first
obtains a short-lived RSA public key and encrypts the account and password
separately into ``ul`` and ``pl``.  This module reproduces that request flow
without a browser runtime.
"""

from __future__ import annotations

import base64
import random
import re
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Callable, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from PIL import Image, ImageFilter, ImageOps


BASE_URL = "https://pass.hust.edu.cn"
LOGIN_URL = f"{BASE_URL}/cas/login"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 20


def enhance_hust_captcha(image_data: bytes, *, scale: int = 3, threshold: int = 210) -> bytes:
    """Merge HUST's animated captcha frames and return an OCR-ready PNG.

    HUST currently labels a four-frame GIF as ``image/jpeg``.  The visible
    characters persist across frames while interference moves, so a majority
    mask retains strokes present in at least half the frames and discards
    frame-local noise.  Pillow is used instead of a browser or native CV
    runtime, keeping the protocol client portable in a headless environment.
    """
    if not isinstance(image_data, (bytes, bytearray, memoryview)):
        raise TypeError("image_data must be bytes-like")
    if scale < 1 or int(scale) != scale:
        raise ValueError("scale must be a positive integer")
    if not 0 <= threshold <= 255:
        raise ValueError("threshold must be between 0 and 255")

    try:
        source = Image.open(BytesIO(bytes(image_data)))  # type: ignore[reportUnreachable]
        try:
            frames = []
            for frame_index in range(getattr(source, "n_frames", 1)):
                source.seek(frame_index)
                frames.append(source.convert("L").copy())
        finally:
            source.close()
    except Exception as exc:
        raise ValueError("captcha data is not a readable image") from exc

    if not frames:
        raise ValueError("captcha image has no frames")

    if len(frames) == 1:
        merged = frames[0]
    else:
        width, height = frames[0].size
        required_frames = max(2, (len(frames) + 1) // 2)
        pixels = []
        for y in range(height):
            for x in range(width):
                dark_frames = sum(frame.getpixel((x, y)) < threshold for frame in frames)
                pixels.append(0 if dark_frames >= required_frames else 255)
        merged = Image.new("L", (width, height), 255)
        merged.putdata(pixels)

    # Normalize contrast, suppress isolated speckles, and enlarge thin glyphs
    # before sending the result to the shared OCR service.
    merged = ImageOps.autocontrast(merged, cutoff=1)
    merged = merged.filter(ImageFilter.MedianFilter(size=3))
    merged = merged.point(lambda pixel: 0 if pixel < threshold else 255, mode="L")
    if scale != 1:
        merged = merged.resize(
            (merged.width * scale, merged.height * scale),
            Image.Resampling.LANCZOS,
        )

    output = BytesIO()
    merged.save(output, format="PNG", optimize=True)
    return output.getvalue()


class LoginStatus(str, Enum):
    """Final state reported by the HUST login endpoint."""

    SUCCESS = "success"
    CAPTCHA_ERROR = "captcha_error"
    INVALID_CREDENTIALS = "invalid_credentials"
    SECOND_AUTH_REQUIRED = "second_auth_required"
    HTTP_ERROR = "http_error"
    UNKNOWN_ERROR = "unknown_error"


class HUSTLoginError(RuntimeError):
    """Raised when the HUST login protocol cannot be completed."""


@dataclass
class LoginPage:
    """CAS form data and URLs extracted from one login-page response."""

    url: str
    action: str
    fields: Dict[str, str]


CaptchaProvider = Callable[[bytes], str]


class HUSTLogin:
    """HTTP-only HUST CAS login client.

    ``captcha_code`` can be supplied for a manually obtained code.  When it
    is omitted, the shared project ``CaptchaSolver`` is loaded lazily and is
    used only when the server requests a captcha.  ``captcha_provider`` is a
    testable/custom alternative receiving the raw image bytes.
    """

    def __init__(
        self,
        username: str,
        password: str,
        *,
        login_url: str = LOGIN_URL,
        session: Optional[requests.Session] = None,
        captcha_code: Optional[str] = None,
        captcha_provider: Optional[CaptchaProvider] = None,
        captcha_solver=None,
        user_agent: str = DEFAULT_USER_AGENT,
        visitor_id: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = 3,
    ) -> None:
        if not username or not password:
            raise ValueError("username and password are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        self.username = username
        self.password = password
        self.login_url = login_url
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.captcha_code = captcha_code
        self.captcha_provider = captcha_provider
        self.captcha_solver = captcha_solver
        self.user_agent = user_agent
        self.visitor_id = visitor_id
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
            }
        )

        self.last_response = None
        self.last_location = ""
        self.last_message = ""
        self.last_status = LoginStatus.UNKNOWN_ERROR

    @staticmethod
    def _check_response(response, description: str) -> None:
        if not 200 <= response.status_code < 300:
            raise HUSTLoginError(
                f"{description} failed with HTTP {response.status_code}"
            )

    @staticmethod
    def _merge_query(url: str, extra_query: str) -> str:
        """Add missing query parameters, preserving action query parameters."""
        if not extra_query:
            return url
        parsed = urlsplit(url)
        current = parse_qsl(parsed.query, keep_blank_values=True)
        existing_names = {name for name, _ in current}
        extra = [item for item in parse_qsl(extra_query, keep_blank_values=True) if item[0] not in existing_names]
        if not extra:
            return url
        return urlunsplit(parsed._replace(query=urlencode(current + extra)))

    def _parse_login_page(self, response) -> LoginPage:
        self._check_response(response, "login page request")
        soup = BeautifulSoup(response.text, "html.parser")
        form = soup.find("form", id="loginForm") or soup.find("form")
        if form is None:
            raise HUSTLoginError("HUST login form was not found")

        page_url = response.url or self.login_url
        action = urljoin(page_url, form.get("action", ""))
        # Keep a caller-supplied CAS service when the server renders a queryless
        # form action.  This is useful for service-ticket based CAS clients.
        action = self._merge_query(action, urlsplit(self.login_url).query)

        fields: Dict[str, str] = {}
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if name:
                fields[name] = input_tag.get("value", "")

        for required in ("lt", "execution", "_eventId"):
            if required not in fields:
                raise HUSTLoginError(f"HUST login form is missing {required}")
        return LoginPage(url=page_url, action=action, fields=fields)

    def _get_login_page(self) -> LoginPage:
        response = self.session.get(self.login_url, timeout=self.timeout)
        return self._parse_login_page(response)

    def _get_public_key(self, page: LoginPage) -> RSA.RsaKey:
        rsa_url = urljoin(page.action, "rsa")
        response = self.session.post(
            rsa_url,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": BASE_URL,
                "Referer": page.url,
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=self.timeout,
        )
        self._check_response(response, "RSA key request")
        try:
            body = response.json()
            encoded_key = body["publicKey"]
            if not isinstance(encoded_key, str) or not encoded_key.strip():
                raise ValueError("publicKey is empty")
            key_bytes = base64.b64decode(encoded_key, validate=True)
            return RSA.import_key(key_bytes)
        except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:
            raise HUSTLoginError(f"invalid HUST RSA response: {exc}") from exc

    @staticmethod
    def _encrypt(value: str, public_key: RSA.RsaKey) -> str:
        encrypted = PKCS1_v1_5.new(public_key).encrypt(value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def _get_captcha(self, page_url: str) -> str:
        captcha_url = urljoin(page_url, f"code?{random.random()}")
        response = self.session.get(
            captcha_url,
            headers={
                "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                "Referer": page_url,
            },
            timeout=self.timeout,
        )
        self._check_response(response, "captcha request")
        prepared_image = enhance_hust_captcha(response.content)

        if self.captcha_provider is not None:
            code = self.captcha_provider(prepared_image)
        else:
            if self.captcha_solver is None:
                try:
                    from captcha_solver.captcha_solver import CaptchaSolver
                except ImportError as exc:
                    raise HUSTLoginError("CaptchaSolver is not available") from exc
                self.captcha_solver = CaptchaSolver()
            code = self.captcha_solver.solve_image_captcha(image_data=prepared_image)

        code = re.sub(r"\s+", "", code or "")
        if not code:
            raise HUSTLoginError("captcha provider returned an empty code")
        return code

    def _build_payload(self, page: LoginPage, public_key: RSA.RsaKey, captcha_code: str) -> Dict[str, str]:
        payload = dict(page.fields)
        payload.update(
            {
                "ua": self.user_agent,
                "visitorId": self.visitor_id,
                "rsa": "",
                "ul": self._encrypt(self.username, public_key),
                "pl": self._encrypt(self.password, public_key),
                "code": captcha_code,
                "phoneCode": payload.get("phoneCode", ""),
                "_eventId": payload.get("_eventId", "submit"),
            }
        )
        return payload

    @staticmethod
    def _extract_message(html: str) -> str:
        soup = BeautifulSoup(html or "", "html.parser")
        for selector in ("#errormsghide", "#errormsg", ".error", ".alert"):
            node = soup.select_one(selector)
            if node:
                text = node.get_text(" ", strip=True)
                if text:
                    return text
        text = soup.get_text(" ", strip=True)
        for marker in ("验证码", "密码", "账号", "认证", "二次"):
            if marker in text:
                start = max(0, text.find(marker) - 30)
                return text[start : start + 180]
        return text[:180]

    @staticmethod
    def _is_captcha_error(message: str) -> bool:
        lowered = message.lower()
        return "验证码" in message or "captcha" in lowered or "code error" in lowered

    @staticmethod
    def _is_invalid_credentials(message: str) -> bool:
        return any(
            marker in message
            for marker in (
                "密码错误",
                "用户名或密码",
                "账号不存在",
                "人员编号/学号不存在",
                "人员编号不存在",
                "学号不存在",
            )
        )

    @staticmethod
    def _is_second_auth(message: str, html: str) -> bool:
        text = f"{message} {html}".lower()
        return any(marker in text for marker in ("secondauth", "二次认证", "second auth", "短信验证"))

    def login(self) -> bool:
        """Execute the HUST CAS flow and return whether authentication succeeded."""
        page = self._get_login_page()
        current_captcha = self.captcha_code
        supplied_captcha = current_captcha is not None

        for attempt in range(1, self.max_attempts + 1):
            if not current_captcha:
                current_captcha = self._get_captcha(page.url)

            public_key = self._get_public_key(page)
            payload = self._build_payload(page, public_key, current_captcha)
            response = self.session.post(
                page.action,
                data=payload,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": BASE_URL,
                    "Referer": page.url,
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=False,
                timeout=self.timeout,
            )
            self.last_response = response
            self.last_location = response.headers.get("Location", "")

            if 300 <= response.status_code < 400 and self.last_location:
                self.last_status = LoginStatus.SUCCESS
                self.last_message = "login redirected"
                return True

            self.last_message = self._extract_message(response.text)
            if self._is_captcha_error(self.last_message):
                self.last_status = LoginStatus.CAPTCHA_ERROR
                if supplied_captcha or attempt >= self.max_attempts:
                    return False
                page = self._parse_login_page(response)
                current_captcha = None
                continue

            if self._is_second_auth(self.last_message, response.text):
                self.last_status = LoginStatus.SECOND_AUTH_REQUIRED
                return False

            if self._is_invalid_credentials(self.last_message):
                self.last_status = LoginStatus.INVALID_CREDENTIALS
                return False

            self.last_status = LoginStatus.HTTP_ERROR if response.status_code >= 400 else LoginStatus.UNKNOWN_ERROR
            return False

        self.last_status = LoginStatus.UNKNOWN_ERROR
        return False


if __name__ == "__main__":
    import os

    username = os.environ.get("HUST_USERNAME", "testuser123")
    password = os.environ.get("HUST_PASSWORD", "Test123pwd")
    client = HUSTLogin(username, password)
    print(f"[*] 尝试登录华中科技大学账号: {username}")
    try:
        success = client.login()
    except Exception as exc:
        print(f"[-] 登录流程异常: {exc}")
        raise SystemExit(1)
    if success:
        print(f"[+] 登录成功，重定向至: {client.last_location}")
    else:
        print(f"[-] 登录失败: {client.last_status.value}，{client.last_message}")
        raise SystemExit(1)
