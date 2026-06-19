#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import random
import re
import sys
from dataclasses import dataclass
from html import unescape
from urllib.parse import urljoin

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

BASE_URL = "https://mail.hit.edu.cn"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36"
)

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha_solver"))
try:
    from captcha_solver import CaptchaSolver
except Exception:
    CaptchaSolver = None


@dataclass
class LoginContext:
    login_url: str
    sid: str
    domain: str
    domains: list[str]
    need_verify_code: bool = False
    result_code: str = ""
    error_message: str = ""


class HITMailLogin:
    def __init__(self, username: str, password: str, timeout: int = 25):
        self.username = username.strip()
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.ua = DEFAULT_UA

    def _html_headers(self):
        return {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
        }

    def _ajax_headers(self):
        return {
            "User-Agent": self.ua,
            "Accept": "text/x-json",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": BASE_URL + "/",
            "Origin": BASE_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

    def _post_headers(self):
        return {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/",
            "Upgrade-Insecure-Requests": "1",
        }

    @staticmethod
    def _search(pattern: str, text: str, default: str = "") -> str:
        m = re.search(pattern, text, re.S)
        return unescape(m.group(1).strip()) if m else default

    def _parse_context(self, html: str) -> LoginContext:
        form_tag = self._search(r'(<form[^>]*class="[^"]*j-login-form[^"]*"[^>]*>)', html)
        if not form_tag:
            form_tag = self._search(r'(<form[^>]*action="/coremail/index\.jsp\?cus=1(?:&amp;|&)sid=[^"]+"[^>]*>)', html)
        action = self._search(r'action="([^"]+)"', form_tag)
        if not action:
            raise RuntimeError("未找到 Coremail 登录表单 action")

        login_url = urljoin(BASE_URL, action.replace("&amp;", "&"))
        sid = self._search(r'[?&]sid=([^&#]+)', login_url)
        if not sid:
            sid = self._search(r"tempSession:\s*'([^']+)'", html)
        if not sid:
            raise RuntimeError("未找到登录 sid")

        domains = re.findall(r'data-domain="([^"]+)"', html)
        primary_domain = self._search(r'primaryDomain:\s*"([^"]+)"', html)
        form_domain = self._search(r'name="domain"[^>]*value="([^"]*)"', html)
        domain = form_domain or primary_domain or (domains[0] if domains else "hit.edu.cn")

        code = self._search(r"loginResultCode:\s*'([^']+)'", html)
        error = self._search(r"error_other:\s*'([^']+)'", html)
        if not error:
            error = self._search(r'<p[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</p>', html)
            error = re.sub(r"\s+", " ", error).strip()
        need_verify = bool(re.search(r"needVerifyCode:\s*true", html) or re.search(r"FA_[A-Z_]*VERIFY_CODE", html))

        return LoginContext(
            login_url=login_url,
            sid=sid,
            domain=domain,
            domains=domains,
            need_verify_code=need_verify,
            result_code=code,
            error_message=error,
        )

    def _get_login_context(self) -> tuple[LoginContext, str]:
        res = self.session.get(BASE_URL + "/", headers=self._html_headers(), timeout=self.timeout)
        res.encoding = "utf-8"
        res.raise_for_status()
        return self._parse_context(res.text), res.text

    def _get_password_key(self, sid: str) -> dict:
        url = f"{BASE_URL}/coremail/s/json?sid={sid}&func=user%3AgetPasswordKey"
        res = self.session.post(url, headers=self._ajax_headers(), data="", timeout=self.timeout)
        res.raise_for_status()
        data = res.json()
        if data.get("code") != "S_OK":
            raise RuntimeError(f"获取动态公钥失败: {data}")
        key = data.get("var", {}).get("key", {})
        if key.get("type") != "RSA" or not key.get("n") or not key.get("e"):
            raise RuntimeError(f"动态公钥格式异常: {data}")
        return key

    @staticmethod
    def _rsa_encrypt_hex(text: str, modulus_hex: str, exponent_hex: str) -> str:
        public_key = RSA.construct((int(modulus_hex, 16), int(exponent_hex, 16)))
        cipher = PKCS1_v1_5.new(public_key)
        return cipher.encrypt(text.encode("utf-8")).hex()

    def _domain_for_username(self, ctx: LoginContext) -> str:
        if "@" in self.username:
            suffix = self.username.rsplit("@", 1)[1].lower()
            for item in ctx.domains:
                if item.lower() == suffix:
                    return item
        return ctx.domain

    def _device_payload(self) -> str:
        return json.dumps(
            {
                "uuid": "webmail_windows",
                "imie": "webmail_windows",
                "friendlyName": "chrome 149",
                "model": "windows",
                "os": "windows",
                "osLanguage": "zh-CN",
                "deviceType": "Webmail",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _build_payload(self, ctx: LoginContext, encrypted_password: str, verify_code: str = "") -> list[tuple[str, str]]:
        payload = [
            ("locale", "zh_CN"),
            ("nodetect", "false"),
            ("destURL", ""),
            ("supportLoginDevice", "true"),
            ("accessToken", ""),
            ("timestamp", ""),
            ("signature", ""),
            ("nonce", ""),
            ("device", self._device_payload()),
            ("supportDynamicPwd", "true"),
            ("supportBind2FA", "true"),
            ("authorizeDevice", ""),
            ("loginType", ""),
            ("uid", self.username),
            ("domain", self._domain_for_username(ctx)),
            ("password", encrypted_password),
        ]
        if verify_code:
            payload.append(("verifyCode", verify_code))
        payload.extend([
            ("face", "auto"),
            ("faceName", "自动选择"),
            ("action:login", ""),
        ])
        return payload

    def _solve_verify_code(self, sid: str) -> str:
        if CaptchaSolver is None:
            raise RuntimeError("当前登录要求图片验证码，但 captcha_solver 模块不可用")
        url = f"{BASE_URL}/coremail/displayVerifyCode.jsp"
        res = self.session.get(
            url,
            headers=self._html_headers(),
            params={"sid": sid, "category": "login", "rand": random.random()},
            timeout=self.timeout,
        )
        res.raise_for_status()
        ctype = res.headers.get("content-type", "")
        if "image" not in ctype.lower():
            raise RuntimeError(f"验证码图片获取失败: HTTP {res.status_code}, Content-Type={ctype}")
        code = CaptchaSolver().solve_image_captcha(image_data=res.content)
        return str(code).strip()

    def _submit_once(self, ctx: LoginContext, verify_code: str = "") -> tuple[requests.Response, LoginContext]:
        key = self._get_password_key(ctx.sid)
        encrypted = self._rsa_encrypt_hex(self.password, key["n"], key["e"])
        payload = self._build_payload(ctx, encrypted, verify_code)
        res = self.session.post(
            ctx.login_url,
            headers=self._post_headers(),
            data=payload,
            timeout=self.timeout,
            allow_redirects=True,
        )
        res.encoding = "utf-8"
        next_ctx = self._parse_context(res.text) if "j-login-form" in res.text or "loginResultCode" in res.text else ctx
        return res, next_ctx

    @staticmethod
    def _is_success(res: requests.Response, ctx: LoginContext) -> bool:
        text = res.text or ""
        if ctx.result_code and ctx.result_code not in {"S_OK", "SUCCEEDED"}:
            return False
        if "j-login-form" in text and "loginResultCode" in text:
            return False
        if "/coremail/index.jsp" not in res.url or "Coremail" in text and "mail.jsp" in text:
            return True
        return False

    def login(self, max_verify_retry: int = 2) -> bool:
        ctx, _ = self._get_login_context()
        print(f"[*] 平台: 哈尔滨工业大学 Coremail 邮箱")
        print(f"[*] 登录入口: {ctx.login_url}")
        print(f"[*] sid: {ctx.sid}")

        verify_code = ""
        for attempt in range(max_verify_retry + 1):
            if ctx.need_verify_code and not verify_code:
                print("[*] 服务端要求图片验证码，开始识别")
                verify_code = self._solve_verify_code(ctx.sid)
                print(f"[*] 验证码识别结果: {verify_code}")

            res, ctx = self._submit_once(ctx, verify_code)
            print(f"[*] 登录请求状态: HTTP {res.status_code}, URL={res.url}")

            if self._is_success(res, ctx):
                print("[+] 登录成功")
                return True

            message = ctx.error_message or ctx.result_code or "登录失败"
            print(f"[-] 服务端返回: {message}")

            if ctx.need_verify_code and attempt < max_verify_retry:
                verify_code = ""
                continue
            return False
        return False


def main():
    parser = argparse.ArgumentParser(description="哈尔滨工业大学 Coremail 邮箱自动登录")
    parser.add_argument("-u", "--username", default="testuser123@test.com", help="邮箱账号")
    parser.add_argument("-p", "--password", default="Test123pwd", help="邮箱密码")
    parser.add_argument("--timeout", type=int, default=25, help="请求超时时间")
    args = parser.parse_args()

    ok = HITMailLogin(args.username, args.password, args.timeout).login()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()