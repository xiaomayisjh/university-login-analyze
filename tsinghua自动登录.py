
import requests
import execjs
import time
import re
import os
import sys
from captcha_solver.captcha_solver import CaptchaSolver

# 配置信息
LOGIN_URL = "https://id.tsinghua.edu.cn/f/login"
AUTH_URL = "https://id.tsinghua.edu.cn/security_check"
CAPTCHA_URL = "https://id.tsinghua.edu.cn/captcha.jpg"
CHECK_CAPTCHA_URL = "https://id.tsinghua.edu.cn/do/off/ui/auth/login/captcha/{}/check"

class TsinghuaLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": LOGIN_URL,
            "Origin": "https://id.tsinghua.edu.cn"
        })
        self.solver = CaptchaSolver()
        self._load_crypto()

    def _load_crypto(self):
        """从网络加载并准备SM2加密环境"""
        js_url = "https://id.tsinghua.edu.cn/v2/dist/doubleauth/sm2Util.js"
        try:
            js_resp = self.session.get(js_url, timeout=10)
            js_resp.raise_for_status()
            js_code = js_resp.text
            self.ctx = execjs.compile(js_code + "\nfunction encrypt(p, k) { return sm2Util.doEncryptStr(p, k); }")
        except Exception as e:
            print(f"[-] 无法从网络加载加密库: {e}")
            sys.exit(1)


    def get_login_params(self):
        """获取登录页面的初始参数，如PublicKey和Fingerprint"""
        resp = self.session.get(LOGIN_URL)
        # 提取PublicKey
        match_pub = re.search(r'id="sm2publicKey">(.*?)</div>', resp.text)
        pub_key = match_pub.group(1) if match_pub else ""
        
        # 模拟 JS 中的 Fingerprint (通常是一个 32 位 hex)
        # 由于我们无法直接运行原站复杂的 fingerprintUtil.js，这里使用一个固定的或捕获到的常用值
        fingerprint = "c5c55a1ccbf7d580b4389e1f515ebcca" 
        
        return pub_key, fingerprint

    def handle_captcha(self):
        """获取并识别验证码"""
        print("[+] 正在获取验证码...")
        t = int(time.time() * 1000)
        img_resp = self.session.get(f"{CAPTCHA_URL}?t={t}")
        
        try:
            code = self.solver.solve_image_captcha(image_data=img_resp.content)
            print(f"[+] 验证码识别结果: {code}")
            
            # 清华有一个验证码预校验接口
            check_url = CHECK_CAPTCHA_URL.format(code)
            check_resp = self.session.post(check_url)
            if "success" in check_resp.text:
                print("[+] 验证码预校验成功")
                return code
            else:
                print("[-] 验证码预校验失败，重试...")
                return self.handle_captcha()
        except Exception as e:
            print(f"[-] 验证码处理出错: {e}")
            return ""

    def login(self):
        print(f"[*] 开始尝试登录清华大学账号: {self.username}")
        
        # 1. 获取页面参数
        pub_key, finger_print = self.get_login_params()
        if not pub_key:
            print("[-] 无法获取SM2公钥，登录失败")
            return
        
        # 2. 加密密码
        encrypted_pwd = self.ctx.call("encrypt", self.password, pub_key)
        
        # 3. 构造请求 Payload
        payload = {
            "username": self.username,
            "password": encrypted_pwd,
            "fingerPrint": finger_print,
            "fingerGenPrint": "",
            "fingerGenPrint3": "",
            "deviceName": "windows,Chrome/120.0.0.0",
            "i_captcha": "" # 初始默认空
        }
        
        # 尝试第一次登录（通常清华第一次不需要验证码，除非IP被标记或多次失败）
        resp = self.session.post(AUTH_URL, data=payload, allow_redirects=False)
        
        # 如果返回 302 且 Location 是 /f/login，说明可能失败或需要验证码
        if resp.status_code == 302 and "/f/login" in resp.headers.get("Location", ""):
            print("[!] 第一次登录尝试被重定向，检查是否需要验证码...")
            # 重新获取登录页看是否有错误提示或验证码触发
            check_page = self.session.get(LOGIN_URL)
            if "i_captcha" in check_page.text:
                print("[+] 检测到需要验证码")
                captcha_code = self.handle_captcha()
                payload["i_captcha"] = captcha_code
                resp = self.session.post(AUTH_URL, data=payload, allow_redirects=False)
        
        # 结果判断
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if "auth_error" in location or "login" in location:
                print("[-] 登录失败: 用户名或密码错误，或认证中心拒绝。")
            else:
                print(f"[+] 登录可能成功，重定向至: {location}")
        elif resp.status_code == 200:
            if "认证失败" in resp.text or "用户名或密码错误" in resp.text:
                print("[-] 登录失败: 页面提示认证错误")
            else:
                print("[+] 登录可能成功 (200 OK)")
        else:
            print(f"[-] 异常响应码: {resp.status_code}")

if __name__ == "__main__":
    # 使用用户提供的测试信息
    USER = "testuser123"
    PWD = "Test123pwd"
    
    bot = TsinghuaLogin(USER, PWD)
    bot.login()
