# -*- coding: utf-8 -*-
"""
NWPU CAS auto login script.

The browser flow is:
1. GET /cas/login and parse the fm1 login block.
2. GET /cas/jwt/publicKey.
3. POST /cas/mfa/detect with "__RSA__" + RSA/PKCS#1 v1.5 password.
4. POST /cas/login with the same encrypted password, execution, and mfaState.
5. Solve /cas/captcha.jpg automatically if the returned page asks for captcha.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from html import unescape
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

try:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
except Exception as exc:  # pragma: no cover - dependency error is reported at runtime.
    RSA_IMPORT_ERROR = exc
    RSA = None
    PKCS1_v1_5 = None
else:
    RSA_IMPORT_ERROR = None


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from captcha_solver.captcha_solver import CaptchaSolver
except Exception:
    captcha_dir = os.path.join(CURRENT_DIR, "captcha_solver")
    if captcha_dir not in sys.path:
        sys.path.insert(0, captcha_dir)
    try:
        from captcha_solver import CaptchaSolver
    except Exception:
        CaptchaSolver = None


@dataclass
class LoginPage:
    url: str
    post_url: str
    fields: dict[str, str]
    captcha_required: bool
    error: str


@dataclass
class MFAResult:
    state: str
    need: bool
    raw: dict[str, Any]


class NWPULogin:
    BASE_URL = "https://uis.nwpu.edu.cn/cas/login"
    PUBLIC_KEY_URL = "https://uis.nwpu.edu.cn/cas/jwt/publicKey"
    MFA_DETECT_URL = "https://uis.nwpu.edu.cn/cas/mfa/detect"
    CAPTCHA_URL = "https://uis.nwpu.edu.cn/cas/captcha.jpg"
    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        username: str,
        password: str,
        *,
        verify_ssl: bool = False,
        timeout: int = 20,
        max_redirects: int = 10,
        fp_visitor_id: Optional[str] = None,
    ) -> None:
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.public_key: Optional[str] = None
        self.fp_visitor_id = fp_visitor_id or self.make_fp_visitor_id()

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.DEFAULT_UA,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

    def make_fp_visitor_id(self) -> str:
        seed = f"{self.DEFAULT_UA}|{self.username}|nwpu-cas"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    def fetch_login_page(self, url: Optional[str] = None) -> LoginPage:
        target = url or self.BASE_URL
        print(f"[*] GET {target}")
        response = self.session.get(
            target,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=True,
        )
        response.raise_for_status()
        page = self.parse_login_page(response.url, response.text)
        print(f"[+] login page: {page.url}")
        print(f"[+] execution length: {len(page.fields.get('execution', ''))}")
        if page.captcha_required:
            print("[*] captcha is required by the current page")
        if page.error:
            print(f"[-] page error: {page.error}")
        return page

    def parse_login_page(self, page_url: str, html: str) -> LoginPage:
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find(id="fm1")
        if not form:
            form = soup.find("form", attrs={"action": re.compile(r"login")})
        if not form:
            raise RuntimeError("fm1 login form not found")

        fields: dict[str, str] = {}
        for item in form.select("input[name]"):
            name = item.get("name", "")
            input_type = (item.get("type") or "").lower()
            if not name or input_type in {"button", "reset"}:
                continue
            if input_type == "checkbox" and not item.has_attr("checked"):
                continue
            fields[name] = item.get("value", "")

        if not fields.get("execution"):
            raise RuntimeError("execution token not found")

        action = form.get("action") or self.BASE_URL
        post_url = urljoin(page_url, action)
        captcha_required = self.detect_captcha(form, html)

        return LoginPage(
            url=page_url,
            post_url=post_url,
            fields=fields,
            captcha_required=captcha_required,
            error=self.extract_error(html),
        )

    def detect_captcha(self, form: BeautifulSoup, html: str) -> bool:
        if form.select_one('input[name="captcha"], #captcha, #captcha_img, img[src*="captcha"]'):
            return True
        markers = [
            'name="captcha"',
            "id=\"captcha\"",
            "id=\"captcha_img\"",
            "/cas/captcha.jpg",
        ]
        has_error_or_field = any(marker in html for marker in markers[:3])
        return has_error_or_field and "/cas/captcha.jpg" in html

    def fetch_public_key(self) -> str:
        if self.public_key:
            return self.public_key
        print(f"[*] GET {self.PUBLIC_KEY_URL}")
        response = self.session.get(
            self.PUBLIC_KEY_URL,
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers={"Referer": self.BASE_URL, "Accept": "text/plain,*/*;q=0.8"},
        )
        response.raise_for_status()
        public_key = response.text.strip()
        if "BEGIN PUBLIC KEY" not in public_key:
            raise RuntimeError("unexpected public key response")
        self.public_key = public_key
        print(f"[+] public key length: {len(public_key)}")
        return public_key

    def encrypt_password(self, password: Optional[str] = None) -> str:
        if RSA is None or PKCS1_v1_5 is None:
            raise RuntimeError(f"pycryptodome is required for RSA encryption: {RSA_IMPORT_ERROR}")
        plaintext = self.password if password is None else password
        if plaintext.startswith("__RSA__"):
            return plaintext

        key = RSA.import_key(self.fetch_public_key())
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(plaintext.encode("utf-8"))
        return "__RSA__" + base64.b64encode(encrypted).decode("ascii")

    def detect_mfa(self) -> MFAResult:
        encrypted_password = self.encrypt_password()
        print(f"[*] POST {self.MFA_DETECT_URL}")
        response = self.session.post(
            self.MFA_DETECT_URL,
            data={"username": self.username, "password": encrypted_password},
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers={
                "Referer": self.BASE_URL,
                "Origin": "https://uis.nwpu.edu.cn",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            },
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid MFA JSON response: {response.text[:200]}") from exc

        if payload.get("code") != 0:
            raise RuntimeError(f"MFA detect failed: {payload}")
        data = payload.get("data") or {}
        state = str(data.get("state") or "")
        need = bool(data.get("need"))
        print(f"[+] mfa state: {state or '<empty>'}, need={need}")
        return MFAResult(state=state, need=need, raw=payload)

    def solve_captcha(self) -> str:
        if CaptchaSolver is None:
            raise RuntimeError("captcha_solver module is unavailable")

        captcha_url = self.CAPTCHA_URL + f"?r={int(time.time() * 1000)}"
        print(f"[*] GET captcha image: {captcha_url}")
        response = self.session.get(
            captcha_url,
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers={
                "Referer": self.BASE_URL,
                "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            },
        )
        response.raise_for_status()
        result = CaptchaSolver().solve_image_captcha(image_data=response.content)
        result = str(result or "").strip()
        if not result:
            raise RuntimeError("captcha solver returned empty result")
        print(f"[+] captcha recognized: {result}")
        return result

    def build_login_data(self, page: LoginPage, mfa_state: str, captcha_text: Optional[str]) -> dict[str, str]:
        data = dict(page.fields)
        data.update(
            {
                "username": self.username,
                "password": self.encrypt_password(),
                "currentMenu": "1",
                "mfaState": mfa_state,
                "_eventId": "submit",
                "geolocation": data.get("geolocation", ""),
                "fpVisitorId": self.fp_visitor_id,
                "submit": "One moment please...",
            }
        )
        data.pop("button", None)
        if captcha_text is not None:
            data["captcha"] = captcha_text
        return data

    def submit_login(
        self,
        page: LoginPage,
        mfa_state: str,
        captcha_text: Optional[str],
    ) -> requests.Response:
        data = self.build_login_data(page, mfa_state, captcha_text)
        parsed = urlparse(page.post_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        print(f"[*] POST {page.post_url}")
        return self.session.post(
            page.post_url,
            data=data,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=False,
            headers={
                "Origin": origin,
                "Referer": page.url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8"
                ),
            },
        )

    def follow_redirects(self, response: requests.Response) -> requests.Response:
        current = response
        for _ in range(self.max_redirects):
            if not current.is_redirect:
                return current
            location = current.headers.get("Location")
            if not location:
                return current
            next_url = urljoin(current.url, location)
            print(f"[>] redirect: {current.status_code} -> {next_url}")
            current = self.session.get(
                next_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
                headers={"Referer": current.url},
            )
        raise RuntimeError("too many redirects")

    def extract_error(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        messages: list[str] = []

        alert_selectors = [
            "#loginError1 el-alert[title]",
            "#loginError2 el-alert[title]",
            "el-alert[type='error'][title]",
            "[role='alert'][title]",
        ]
        for node in soup.select(", ".join(alert_selectors)):
            title = node.get("title", "")
            if title and title not in messages:
                messages.append(title.strip())

        for selector in ["#msg", ".errors", ".alert-danger", ".error"]:
            for node in soup.select(selector):
                text = " ".join(node.get_text(" ", strip=True).split())
                if text and text not in messages:
                    messages.append(text)

        for match in re.finditer(r"errors\s*=\s*(\[[^\]]+\])", html):
            try:
                errors = json.loads(match.group(1))
            except Exception:
                continue
            for item in errors:
                text = str(item).strip()
                if text and text not in messages:
                    messages.append(text)

        if messages:
            return " | ".join(messages[:3])

        body_text = " ".join(soup.get_text(" ", strip=True).split())
        known_markers = [
            "Invalid credentials.",
            "Authentication failure",
            "captcha",
            "verification code",
        ]
        for marker in known_markers:
            pos = body_text.lower().find(marker.lower())
            if pos >= 0:
                return unescape(body_text[max(0, pos - 40) : pos + 160])
        return ""

    def login(self, max_attempts: int = 3) -> bool:
        page = self.fetch_login_page()
        mfa = self.detect_mfa()
        if mfa.need:
            print("[-] MFA challenge is required. State was obtained, but no second-factor approval is available.")
            return False

        for attempt in range(1, max_attempts + 1):
            print(f"[*] login attempt {attempt}/{max_attempts}")
            captcha_text = self.solve_captcha() if page.captcha_required else None
            response = self.submit_login(page, mfa.state, captcha_text)
            print(f"[*] response status: {response.status_code}")

            if response.is_redirect:
                final_response = self.follow_redirects(response)
                print(f"[+] login accepted, final status: {final_response.status_code}")
                print(f"[+] final url: {final_response.url}")
                return True

            message = self.extract_error(response.text)
            if message:
                print(f"[-] login failed: {message}")

            if response.status_code in {200, 401, 403}:
                try:
                    page = self.parse_login_page(response.url, response.text)
                except Exception:
                    return False
                if page.captcha_required and attempt < max_attempts:
                    print("[*] server requested captcha, retrying")
                    continue
                return False

            print(f"[-] unexpected response status: {response.status_code}")
            return False

        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NWPU CAS auto login via HTTP requests")
    parser.add_argument("--username", default="testuser123@test.com", help="login username")
    parser.add_argument("--password", default="Test123pwd", help="login password")
    parser.add_argument("--max-attempts", type=int, default=3, help="max captcha retry attempts")
    parser.add_argument("--fp-visitor-id", default=None, help="optional FingerprintJS visitor id value")
    parser.add_argument("--verify-ssl", action="store_true", help="enable TLS certificate verification")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = NWPULogin(
        args.username,
        args.password,
        verify_ssl=args.verify_ssl,
        fp_visitor_id=args.fp_visitor_id,
    )
    try:
        success = client.login(max_attempts=args.max_attempts)
    except Exception as exc:
        print(f"[-] login flow error: {exc}")
        return 1

    if success:
        print("[+] login flow completed")
        return 0
    print("[-] login flow ended without success")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
