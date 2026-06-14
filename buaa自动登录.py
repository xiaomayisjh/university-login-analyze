# -*- coding: utf-8 -*-
"""
BUAA WebVPN/CAS auto login script.

It reproduces the browser login flow with HTTP requests only:
1. Open https://d.buaa.edu.cn/ and follow the WebVPN redirect.
2. Parse the CAS login form and one-time execution token.
3. Solve captcha when the server exposes config.captcha.id.
4. Submit the login form and follow redirects.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTCHA_DIR = os.path.join(CURRENT_DIR, "captcha_solver")
if CAPTCHA_DIR not in sys.path:
    sys.path.insert(0, CAPTCHA_DIR)

try:
    from captcha_solver import CaptchaSolver
except Exception:
    CaptchaSolver = None


@dataclass
class LoginPage:
    url: str
    post_url: str
    fields: dict[str, str]
    captcha_id: Optional[str]
    error: str


class BUAAAutoLogin:
    ENTRY_URL = "https://d.buaa.edu.cn/"
    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/149.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        username: str,
        password: str,
        *,
        verify_ssl: bool = False,
        timeout: int = 20,
        max_redirects: int = 10,
    ) -> None:
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.DEFAULT_UA,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8"
                ),
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

    def fetch_login_page(self, url: Optional[str] = None) -> LoginPage:
        target = url or self.ENTRY_URL
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
        if page.captcha_id:
            print(f"[*] captcha required, id={page.captcha_id}")
        return page

    def parse_login_page(self, page_url: str, html: str) -> LoginPage:
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form", id="loginForm") or soup.find("form")
        if not form:
            raise RuntimeError("login form not found")

        fields: dict[str, str] = {}
        for item in form.select("input[name]"):
            name = item.get("name", "")
            if name:
                fields[name] = item.get("value", "")

        if not fields.get("execution"):
            raise RuntimeError("execution token not found")

        action = form.get("action") or "login"
        post_url = urljoin(page_url, action)
        return LoginPage(
            url=page_url,
            post_url=post_url,
            fields=fields,
            captcha_id=self.extract_captcha_id(html, soup),
            error=self.extract_error(html),
        )

    def extract_captcha_id(self, html: str, soup: BeautifulSoup) -> Optional[str]:
        for img in soup.select('img[src*="captchaId="], img[src*="/captcha"]'):
            src = img.get("src", "")
            match = re.search(r"captchaId=([^&\"'>\s]+)", src)
            if match:
                return match.group(1)

        patterns = [
            r"config\.captcha\s*=\s*\{[^}]*?\bid\s*:\s*['\"]([^'\"]+)['\"]",
            r"config\.captcha\s*=\s*\{[^}]*?['\"]id['\"]\s*:\s*['\"]([^'\"]+)['\"]",
            r"\bcaptchaId['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",
            r"captcha\?captchaId=([^&\"'<>\\\s]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)

        if "config.captcha" in html and "captchaId" in html:
            match = re.search(r"\bid\s*[:=]\s*['\"]([^'\"]+)['\"]", html)
            if match:
                return match.group(1)
        return None

    def extract_error(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        selectors = [
            "#errorDiv p",
            "#errorDiv",
            "#errPassword",
            "#errSmsToken",
            ".alert-danger",
            ".item-validate",
        ]
        messages: list[str] = []
        for selector in selectors:
            for node in soup.select(selector):
                text = " ".join(node.get_text(" ", strip=True).split())
                if text and text not in messages:
                    messages.append(text)

        if messages:
            return " | ".join(messages[:3])

        body_text = " ".join(soup.get_text(" ", strip=True).split())
        known_errors = [
            "用户名或密码错误",
            "认证信息无效",
            "验证码",
            "Invalid credentials",
            "Unauthorized",
        ]
        for marker in known_errors:
            if marker in body_text:
                start = max(body_text.find(marker) - 20, 0)
                return body_text[start : start + 120]
        return body_text[:160]

    def make_app_root(self, page_url: str) -> str:
        parsed = urlparse(page_url)
        match = re.match(r"^/(https?|http)/([^/]+)/", parsed.path)
        if match:
            prefix = match.group(0).lstrip("/")
            return f"{parsed.scheme}://{parsed.netloc}/{prefix}"
        return f"{parsed.scheme}://{parsed.netloc}/"

    def solve_captcha(self, page: LoginPage) -> Optional[str]:
        if not page.captcha_id:
            return None
        if CaptchaSolver is None:
            print("[-] captcha_solver module is unavailable")
            return None

        captcha_url = (
            self.make_app_root(page.url)
            + "captcha?captchaId="
            + quote(page.captcha_id, safe="")
            + f"&t={int(time.time() * 1000)}"
        )
        print(f"[*] GET captcha image: {captcha_url}")
        response = self.session.get(
            captcha_url,
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers={"Referer": page.url, "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"},
        )
        response.raise_for_status()

        solver = CaptchaSolver()
        result = solver.solve_image_captcha(image_data=response.content)
        if not result:
            print("[-] captcha solver returned empty result")
            return None
        result = str(result).strip().lower()
        print(f"[+] captcha recognized: {result}")
        return result

    def build_login_data(self, page: LoginPage, captcha_text: Optional[str]) -> dict[str, str]:
        data = dict(page.fields)
        data.update(
            {
                "username": self.username,
                "password": self.password,
                "submit": data.get("submit") or "登录",
                "type": "username_password",
                "_eventId": data.get("_eventId") or "submit",
            }
        )
        if captcha_text:
            data["captcha"] = captcha_text.strip().lower()
        return data

    def submit_login(self, page: LoginPage, captcha_text: Optional[str]) -> requests.Response:
        parsed = urlparse(page.post_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        data = self.build_login_data(page, captcha_text)
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

    def login(self, max_attempts: int = 3) -> bool:
        page = self.fetch_login_page()

        for attempt in range(1, max_attempts + 1):
            print(f"[*] login attempt {attempt}/{max_attempts}")
            captcha_text = self.solve_captcha(page) if page.captcha_id else None
            if page.captcha_id and not captcha_text:
                return False

            response = self.submit_login(page, captcha_text)
            print(f"[*] response status: {response.status_code}")

            if response.is_redirect:
                final_response = self.follow_redirects(response)
                print(f"[+] accepted by CAS, final status: {final_response.status_code}")
                print(f"[+] final url: {final_response.url}")
                return True

            message = self.extract_error(response.text)
            if message:
                print(f"[-] login failed: {message}")

            if response.status_code in (200, 401, 403):
                try:
                    next_page = self.parse_login_page(response.url, response.text)
                except Exception:
                    return False
                if next_page.captcha_id and attempt < max_attempts:
                    page = next_page
                    print("[*] server requested captcha, retrying with captcha")
                    continue
                return False

            print(f"[-] unexpected status: {response.status_code}")
            return False

        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BUAA WebVPN/CAS auto login via HTTP requests")
    parser.add_argument("--username", default="testuser123@test.com", help="login username")
    parser.add_argument("--password", default="Test123pwd", help="login password")
    parser.add_argument("--max-attempts", type=int, default=3, help="max captcha retry attempts")
    parser.add_argument("--verify-ssl", action="store_true", help="enable TLS certificate verification")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = BUAAAutoLogin(
        args.username,
        args.password,
        verify_ssl=args.verify_ssl,
    )
    success = client.login(max_attempts=args.max_attempts)
    if success:
        print("[+] login flow completed")
        return 0
    print("[-] login flow ended without success")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
