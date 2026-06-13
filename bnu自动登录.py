# -*- coding: utf-8 -*-
import os
import random
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


try:
    from captcha_solver.captcha_solver import CaptchaSolver
except Exception:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha_solver"))
    from captcha_solver import CaptchaSolver


class BNULogin:
    ENTRY_URL = "https://onevpn.bnu.edu.cn/"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.solver = CaptchaSolver()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
        })

    @staticmethod
    def _get_key_bytes(key):
        chunks = []
        for index in range(len(key) // 4):
            chunks.append(BNULogin._str_to_bt(key[index * 4:index * 4 + 4]))
        if len(key) % 4:
            chunks.append(BNULogin._str_to_bt(key[(len(key) // 4) * 4:]))
        return chunks

    @staticmethod
    def _str_to_bt(value):
        bits = [0] * 64
        for i, ch in enumerate(value[:4]):
            code_point = ord(ch)
            for j in range(16):
                divider = 1
                for _ in range(15, j, -1):
                    divider *= 2
                bits[16 * i + j] = int(code_point / divider) % 2
        return bits

    @staticmethod
    def _bt64_to_hex(byte_data):
        table = {
            "0000": "0", "0001": "1", "0010": "2", "0011": "3",
            "0100": "4", "0101": "5", "0110": "6", "0111": "7",
            "1000": "8", "1001": "9", "1010": "A", "1011": "B",
            "1100": "C", "1101": "D", "1110": "E", "1111": "F",
        }
        output = ""
        for i in range(16):
            output += table["".join(str(byte_data[i * 4 + j]) for j in range(4))]
        return output

    @staticmethod
    def _xor(left, right):
        return [a ^ b for a, b in zip(left, right)]

    @staticmethod
    def _init_permute(original_data):
        output = [0] * 64
        for i, odd, even in zip(range(4), range(1, 8, 2), range(0, 8, 2)):
            k = 0
            for j in range(7, -1, -1):
                output[i * 8 + k] = original_data[j * 8 + odd]
                output[i * 8 + k + 32] = original_data[j * 8 + even]
                k += 1
        return output

    @staticmethod
    def _expand_permute(right_data):
        output = [0] * 48
        for i in range(8):
            output[i * 6 + 0] = right_data[31] if i == 0 else right_data[i * 4 - 1]
            output[i * 6 + 1] = right_data[i * 4 + 0]
            output[i * 6 + 2] = right_data[i * 4 + 1]
            output[i * 6 + 3] = right_data[i * 4 + 2]
            output[i * 6 + 4] = right_data[i * 4 + 3]
            output[i * 6 + 5] = right_data[0] if i == 7 else right_data[i * 4 + 4]
        return output

    @staticmethod
    def _s_box_permute(expand_byte):
        boxes = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
        ]
        output = [0] * 32
        for m in range(8):
            row = expand_byte[m * 6] * 2 + expand_byte[m * 6 + 5]
            col = (expand_byte[m * 6 + 1] * 8 + expand_byte[m * 6 + 2] * 4 +
                   expand_byte[m * 6 + 3] * 2 + expand_byte[m * 6 + 4])
            binary = format(boxes[m][row][col], "04b")
            for index, bit in enumerate(binary):
                output[m * 4 + index] = int(bit)
        return output

    @staticmethod
    def _p_permute(s_box_byte):
        indexes = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
                   1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
        return [s_box_byte[i] for i in indexes]

    @staticmethod
    def _finally_permute(end_byte):
        indexes = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
                   37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
                   35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
                   33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]
        return [end_byte[i] for i in indexes]

    @staticmethod
    def _generate_keys(key_byte):
        key = [0] * 56
        keys = [[0] * 48 for _ in range(16)]
        for i in range(7):
            k = 7
            for j in range(8):
                key[i * 8 + j] = key_byte[8 * k + i]
                k -= 1
        loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        indexes = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
                   25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
                   50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
        for i in range(16):
            for _ in range(loop[i]):
                temp_left = key[0]
                temp_right = key[28]
                for k in range(27):
                    key[k] = key[k + 1]
                    key[28 + k] = key[29 + k]
                key[27] = temp_left
                key[55] = temp_right
            keys[i] = [key[index] for index in indexes]
        return keys

    @staticmethod
    def _enc(data_byte, key_byte):
        keys = BNULogin._generate_keys(key_byte)
        ip_byte = BNULogin._init_permute(data_byte)
        ip_left = ip_byte[:32]
        ip_right = ip_byte[32:]
        for i in range(16):
            temp_left = ip_left[:]
            ip_left = ip_right[:]
            temp_right = BNULogin._xor(
                BNULogin._p_permute(
                    BNULogin._s_box_permute(
                        BNULogin._xor(BNULogin._expand_permute(ip_right), keys[i])
                    )
                ),
                temp_left,
            )
            ip_right = temp_right[:]
        return BNULogin._finally_permute(ip_right + ip_left)

    @classmethod
    def str_enc(cls, data, first_key="1", second_key="2", third_key="3"):
        first_key_bt = cls._get_key_bytes(first_key)
        second_key_bt = cls._get_key_bytes(second_key)
        third_key_bt = cls._get_key_bytes(third_key)
        encrypted = ""
        chunks = [data[i:i + 4] for i in range(0, len(data), 4)]
        for chunk in chunks:
            block = cls._str_to_bt(chunk)
            for key in first_key_bt:
                block = cls._enc(block, key)
            for key in second_key_bt:
                block = cls._enc(block, key)
            for key in third_key_bt:
                block = cls._enc(block, key)
            encrypted += cls._bt64_to_hex(block)
        return encrypted

    def _headers(self, page_url, accept="*/*"):
        parsed = urlparse(page_url)
        return {
            "Accept": accept,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": f"{parsed.scheme}://{parsed.netloc}",
            "Referer": page_url,
            "User-Agent": self.session.headers["User-Agent"],
        }

    def _extract_login_page(self):
        print("[*] Fetching BNU WebVPN login page...")
        response = self.session.get(self.ENTRY_URL, allow_redirects=True, timeout=20)
        response.raise_for_status()
        response.encoding = response.apparent_encoding or "utf-8"

        soup = BeautifulSoup(response.text, "html.parser")
        form = soup.find("form", id="loginForm") or soup.find("form")
        if not form:
            raise RuntimeError("loginForm not found")

        action = urljoin(response.url, form.get("action", ""))
        lt_input = form.find("input", {"name": "lt"})
        execution_input = form.find("input", {"name": "execution"})
        device_input = form.find("input", {"name": "device"})
        code_open_input = soup.find("input", {"ref": "codeOpen"})

        if not lt_input or not execution_input:
            raise RuntimeError("lt or execution not found")

        data = {
            "page_url": response.url,
            "action": action,
            "lt": lt_input.get("value", ""),
            "execution": execution_input.get("value", ""),
            "device": device_input.get("value", "") if device_input else "",
            "code_open": (code_open_input.get("value", "").lower() == "true") if code_open_input else False,
        }
        print(f"[+] Login page: {data['page_url']}")
        print(f"[+] lt: {data['lt']}")
        print(f"[+] execution: {data['execution']}")
        return data

    def _get_captcha(self, page_url):
        captcha_url = urljoin(page_url, f"code?{random.random()}")
        print("[*] Fetching captcha image...")
        response = self.session.get(
            captcha_url,
            headers=self._headers(page_url, accept="image/avif,image/webp,image/apng,image/*,*/*;q=0.8"),
            timeout=15,
        )
        response.raise_for_status()
        text = self.solver.solve_image_captcha(image_data=response.content)
        text = re.sub(r"\s+", "", text or "")
        print(f"[+] Captcha recognized: {text}")
        return text

    def _second_auth(self, page, captcha_text):
        rsa_value = self.str_enc(self.username + self.password + page["lt"])
        payload = {
            "method": "check",
            "captcha": captcha_text if captcha_text else "null",
            "ul": str(len(self.username)),
            "pl": str(len(self.password)),
            "rsa": rsa_value,
            "random": str(random.random()),
        }
        url = urljoin(page["page_url"], "secondAuth")
        headers = self._headers(page["page_url"], accept="application/json, text/plain, */*")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        print("[*] Sending secondAuth check...")
        response = self.session.post(url, data=payload, headers=headers, timeout=20)
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            raise RuntimeError(f"secondAuth returned non-JSON response: {response.text[:200]}")

        print(f"[*] secondAuth response: {data}")
        return data, rsa_value

    @staticmethod
    def _needs_captcha(second_auth_data):
        if second_auth_data.get("result") == "true":
            return False
        failure_times = second_auth_data.get("failureTimes")
        if isinstance(failure_times, bool):
            return failure_times
        if isinstance(failure_times, str):
            return failure_times.lower() == "true" or failure_times.isdigit()
        return bool(failure_times)

    def _submit_login_form(self, page, rsa_value, captcha_text):
        payload = {
            "rsa": rsa_value,
            "ul": str(len(self.username)),
            "pl": str(len(self.password)),
            "lt": page["lt"],
            "execution": page["execution"],
            "choosenumber": "",
            "device": page["device"],
            "_eventId": "submit",
        }
        if captcha_text:
            payload["code"] = captcha_text

        headers = self._headers(
            page["page_url"],
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests": "1",
        })

        print("[*] Submitting CAS login form...")
        response = self.session.post(
            page["action"],
            data=payload,
            headers=headers,
            allow_redirects=False,
            timeout=20,
        )
        print(f"[*] Login response status: {response.status_code}")
        return response

    def _follow_redirects(self, response, max_steps=8):
        current = response
        for _ in range(max_steps):
            if current.status_code not in (301, 302, 303, 307, 308):
                break
            location = current.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current.url, location)
            print(f"[*] Redirect: {next_url}")
            current = self.session.get(next_url, allow_redirects=False, timeout=20)
        return current

    @staticmethod
    def _extract_message(html):
        soup = BeautifulSoup(html, "html.parser")
        candidates = []
        for selector in [".error", ".tips", ".message", ".alert", "[ref=errorMsg]"]:
            for node in soup.select(selector):
                text = node.get_text(" ", strip=True)
                if text and text not in candidates:
                    candidates.append(text)
        body_text = soup.get_text("\n", strip=True)
        for marker in ["账户不存在", "用户名", "密码", "验证码", "二次认证", "认证失败"]:
            if marker in body_text:
                line = next((line.strip() for line in body_text.splitlines() if marker in line), "")
                if line and line not in candidates:
                    candidates.append(line)
        return " | ".join(candidates[:3]) or body_text[:200]

    def login(self):
        page = self._extract_login_page()
        captcha_text = None

        for attempt in range(1, 4):
            if page["code_open"] and not captcha_text:
                captcha_text = self._get_captcha(page["page_url"])

            second_auth_data, rsa_value = self._second_auth(page, captcha_text)
            if second_auth_data.get("result") == "true":
                info = second_auth_data.get("info")
                if info and info != "noAuth":
                    print(f"[-] Server requires second factor: {info}")
                    return False
                break

            error = second_auth_data.get("error") or second_auth_data.get("msg") or "secondAuth failed"
            print(f"[-] secondAuth rejected attempt {attempt}: {error}")
            if self._needs_captcha(second_auth_data) and attempt < 3:
                captcha_text = self._get_captcha(page["page_url"])
                continue
            return False
        else:
            return False

        response = self._submit_login_form(page, rsa_value, captcha_text)
        final_response = self._follow_redirects(response)

        if response.status_code in (301, 302, 303, 307, 308):
            print("[+] Login form accepted redirect.")
            print(f"[+] Final URL: {final_response.url}")
            return True

        message = self._extract_message(response.text)
        if "账户不存在" in message or "密码" in message or "认证失败" in message:
            print(f"[-] Login failed: {message}")
            return False

        if "统一身份认证" not in response.text and "loginForm" not in response.text:
            print("[+] Login may have succeeded.")
            print(f"[+] Final URL: {final_response.url}")
            return True

        print(f"[-] Login failed or stayed on login page: {message}")
        return False


def main():
    username = "testuser123@test.com"
    password = "Test123pwd"

    print("=" * 60)
    print("BNU WebVPN auto login")
    print("=" * 60)
    print(f"[*] Username: {username}")
    print("[*] Password: **********")

    client = BNULogin(username, password)
    success = client.login()

    print("=" * 60)
    print("[+] Login flow finished" if success else "[-] Login flow ended without success")
    print("=" * 60)


if __name__ == "__main__":
    main()
