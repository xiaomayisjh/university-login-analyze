import requests
import re
import os
import subprocess
import time
from captcha_solver.captcha_solver import CaptchaSolver
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class XJTULogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.base_url = "https://login.xjtu.edu.cn/cas/login"
        self.pubkey_url = "https://login.xjtu.edu.cn/cas/jwt/publicKey"
        self.captcha_url = "https://login.xjtu.edu.cn/cas/captcha.jpg"
        self.solver = CaptchaSolver()
        self.fp_id = "e14b2d1c68f6b6e7a2b2e8a1a1c1d1e1"

    def get_execution(self):
        resp = self.session.get(self.base_url)
        html = resp.text
        match = re.search(r'name="execution" value="([^"]+)"', html)
        if match:
            return match.group(1)
        return None

    def get_public_key(self):
        resp = self.session.get(self.pubkey_url)
        return resp.text.strip()

    def encrypt_password(self, password, public_key):
        js_code = f"""
const crypto = require('crypto');
const password = "{password}";
const publicKey = `{public_key}`;

function encrypt(text, pubKey) {{
    const buffer = Buffer.from(text);
    const encrypted = crypto.publicEncrypt({{
        key: pubKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }}, buffer);
    return encrypted.toString('base64');
}}

console.log("__RSA__" + encrypt(password, publicKey));
"""
        with open("temp_encrypt.js", "w", encoding="utf-8") as f:
            f.write(js_code)
        
        result = subprocess.run(["node", "temp_encrypt.js"], capture_output=True, text=True)
        if os.path.exists("temp_encrypt.js"):
            os.remove("temp_encrypt.js")
        return result.stdout.strip()

    def mfa_detect(self, encrypted_password):
        url = "https://login.xjtu.edu.cn/cas/mfa/detect"
        data = {
            "username": self.username,
            "password": encrypted_password,
            "fpVisitorId": self.fp_id
        }
        headers = {
            "Referer": self.base_url,
            "X-Requested-With": "XMLHttpRequest"
        }
        try:
            resp = self.session.post(url, data=data, headers=headers)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("code") == 0:
                    return result["data"].get("state", "")
        except:
            pass
        return ""

    def solve_captcha(self):
        r = int(time.time() * 1000)
        resp = self.session.get(f"{self.captcha_url}?r={r}")
        if resp.status_code == 200:
            print("[*] 正在识别验证码...")
            try:
                result = self.solver.solve_image_captcha(image_data=resp.content)
                print(f"[*] 验证码识别结果: {result}")
                return result
            except Exception as e:
                print(f"[!] 验证码识别失败: {e}")
                return ""
        return ""

    def login(self):
        print(f"[*] 尝试登录用户: {self.username}")
        
        execution = self.get_execution()
        if not execution:
            print("[!] 无法获取execution参数")
            return False

        public_key = self.get_public_key()
        encrypted_password = self.encrypt_password(self.password, public_key)
        
        # 模拟浏览器行为：先调用mfa/detect
        mfa_state = self.mfa_detect(encrypted_password)
        
        payload = {
            "username": self.username,
            "password": encrypted_password,
            "captcha": "",
            "currentMenu": "1",
            "failN": "0",
            "mfaState": mfa_state,
            "execution": execution,
            "_eventId": "submit",
            "fpVisitorId": self.fp_id
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.base_url
        }

        resp = self.session.post(self.base_url, data=payload, headers=headers, allow_redirects=False)
        
        if resp.status_code == 302:
            print("[+] 登录成功！(检测到302跳转)")
            return True
        
        # 提取失败原因
        error_msg = self.extract_error(resp.text)
        
        if "验证码" in resp.text or "captcha" in resp.text.lower():
            print("[*] 需要验证码，重试中...")
            captcha_code = self.solve_captcha()
            # 重新获取execution
            execution = self.get_execution()
            payload["captcha"] = captcha_code
            payload["execution"] = execution
            payload["failN"] = "1"
            
            resp = self.session.post(self.base_url, data=payload, headers=headers, allow_redirects=False)
            if resp.status_code == 302:
                print("[+] 登录成功！(检测到302跳转)")
                return True
            else:
                error_msg = self.extract_error(resp.text)
                print(f"[!] 登录失败: {error_msg}")
                return False
        else:
            print(f"[!] 登录失败: {error_msg}")
            return False

    def extract_error(self, html):
        error_match = re.search(r'id="msg"[^>]*>([^<]+)</span>', html)
        if error_match:
            return error_match.group(1).strip()
        error_match = re.search(r'<div class="error_msg">([^<]+)</div>', html)
        if error_match:
            return error_match.group(1).strip()
        return "未知错误 (可能是账号密码错误或环境受限)"

if __name__ == "__main__":
    # 使用用户提供的测试信息
    tester = XJTULogin("testuser123", "Test123pwd")
    tester.login()
