import requests
import time
import urllib3
import re
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from captcha_solver.captcha_solver import CaptchaSolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ZJUWebVPNLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        })
        self.base_url = "https://webvpn.zju.edu.cn"
        self.solver = CaptchaSolver()

    def _text_right_append(self, text):
        segment_byte_size = 16
        text_bytes = text.encode('utf-8')
        if len(text_bytes) % segment_byte_size == 0:
            return text_bytes
        append_length = segment_byte_size - (len(text_bytes) % segment_byte_size)
        return text_bytes + b'0' * append_length

    def encrypt_password(self, text, key="wrdvpnisawesome!", iv="wrdvpnisawesome!"):
        text_length = len(text.encode('utf-8'))
        padded_text = self._text_right_append(text)
        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)
        encrypt_bytes = cipher.encrypt(padded_text)
        return iv_bytes.hex() + encrypt_bytes.hex()[:text_length * 2]

    def login(self):
        print(f"[*] 开始准备登录 ZJU WebVPN: {self.username}")
        
        # 获取登录页面
        print("[*] 正在获取登录页面数据...")
        try:
            res = self.session.get(f"{self.base_url}/login", verify=False, timeout=10)
            res.raise_for_status()
        except Exception as e:
            print(f"[-] 获取登录页面失败: {e}")
            return False
            
        soup = BeautifulSoup(res.text, 'html.parser')
        
        csrf_input = soup.find('input', {'name': '_csrf'})
        captcha_id_input = soup.find('input', {'name': 'captcha_id'})
        
        if not csrf_input:
            print("[-] 未能找到 _csrf, 页面结构可能已更改或访问受限")
            return False
            
        csrf_token = csrf_input.get('value', '').strip()
        captcha_id = captcha_id_input.get('value', '').strip() if captcha_id_input else ''
        
        print(f"[*] 解析到 csrf: {csrf_token}, captcha_id: {captcha_id}")
        
        payload = {
            '_csrf': csrf_token,
            'auth_type': 'local',
            'username': self.username,
            'sms_code': '',
            'password': self.encrypt_password(self.password),
            'captcha': '',
            'needCaptcha': 'false',
            'captcha_id': captcha_id
        }
        
        # 尝试多次登录以处理可能出现的验证码
        for attempt in range(1, 4):
            print(f"\n[*] 尝试登录 (第 {attempt} 次)")
            
            # 检查是否需要验证码或者上一轮失败是因为验证码
            if payload['needCaptcha'] == 'true' and captcha_id:
                print(f"[*] 检测到需要验证码，开始获取...")
                timestamp = int(time.time() * 1000)
                captcha_url = f"{self.base_url}/captcha/{captcha_id}.png?reload={timestamp}"
                try:
                    captcha_res = self.session.get(captcha_url, verify=False, timeout=10)
                    if captcha_res.status_code == 200:
                        print("[*] 获取验证码图片成功，开始识别...")
                        captcha_code = self.solver.solve_image_captcha(image_data=captcha_res.content)
                        print(f"[+] 验证码识别结果: {captcha_code}")
                        payload['captcha'] = captcha_code
                    else:
                        print(f"[-] 获取验证码图片失败, status code: {captcha_res.status_code}")
                except Exception as e:
                    print(f"[-] 验证码处理失败: {e}")
            
            print("[*] 发送登录请求...")
            try:
                login_res = self.session.post(f"{self.base_url}/do-login", data=payload, verify=False, timeout=10)
                result = login_res.json()
            except Exception as e:
                print(f"[-] 登录请求失败: {e}")
                return False
                
            print(f"[*] 登录响应: {result}")
            
            if result.get('success'):
                print(f"[+] 登录成功! 重定向 URL: {result.get('url')}")
                # 跟踪重定向
                if result.get('url'):
                    print("[*] 正在跟随重定向...")
                    redirect_url = result.get('url')
                    if not redirect_url.startswith('http'):
                        redirect_url = self.base_url + redirect_url
                    final_res = self.session.get(redirect_url, verify=False)
                    print(f"[*] 重定向完成, 当前URL: {final_res.url}")
                return True
            else:
                err_code = result.get('error', '')
                err_msg = result.get('message', '')
                print(f"[-] 登录失败: {err_code} - {err_msg}")
                
                if err_code == "CAPTCHA_FAILED":
                    payload['needCaptcha'] = 'true'
                    print("[-] 验证码错误，准备重试")
                elif err_code == "INVALID_ACCOUNT":
                    print("[-] 用户名或密码错误，停止尝试")
                    break
                elif err_code == "NEED_TWO_STEP" or err_code == "NEED_TWO_STEP_TOTP":
                    print("[-] 需要双重认证或手机验证码，脚本默认不支持双因子自动完成，请手动介入")
                    return False
                elif err_code == "NEED_CONFIRM":
                    print("[*] 账号已在其他地方登录，脚本尝试自动确认继续登录...")
                    confirm_res = self.session.post(f"{self.base_url}/do-confirm-login", verify=False)
                    confirm_result = confirm_res.json()
                    print(f"[*] 强制登录返回: {confirm_result}")
                    if confirm_result.get('success'):
                        print("[+] 强制登录成功!")
                        return True
                    else:
                        print("[-] 强制登录失败")
                        return False
                else:
                    print("[-] 其他原因退出登录")
                    break

        print("[-] 登录流程结束，未成功。")
        return False

if __name__ == "__main__":
    login_system = ZJUWebVPNLogin("testuser123@test.com", "Test123pwd")
    login_system.login()

