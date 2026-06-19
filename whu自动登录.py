# whu自动登录.py
import requests
from bs4 import BeautifulSoup
import random
import base64
import re
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys
import os
import json
import hashlib
from PIL import Image
from io import BytesIO

# 引入已编写在项目下captcha_solver的验证码识别模块
sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
try:
    from captcha_solver import CaptchaSolver
except ImportError:
    CaptchaSolver = None

class WHULogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive'
        }
        self.login_url = 'https://cas.whu.edu.cn/authserver/login'
        self.chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'

    def _rds(self, length):
        return ''.join(random.choice(self.chars) for _ in range(length))

    def _encrypt_password(self, pwd, salt):
        data = (self._rds(64) + pwd).encode('utf-8')
        key = salt.encode('utf-8')
        iv = self._rds(16).encode('utf-8')

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(ciphertext).decode('utf-8')

    def _ajax_headers(self):
        headers = self.headers.copy()
        headers.update({
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': self.login_url,
            'X-Requested-With': 'XMLHttpRequest',
        })
        return headers

    def _form_payload(self, form):
        data = {}
        for input_tag in form.select('input'):
            name = input_tag.get('name')
            if not name:
                continue
            input_type = (input_tag.get('type') or '').lower()
            if input_type in ('button', 'submit', 'reset', 'file'):
                continue
            if input_type in ('checkbox', 'radio') and not input_tag.has_attr('checked'):
                continue
            data[name] = input_tag.get('value', '')
        return data

    def _extract_var(self, html, name, default=''):
        match = re.search(rf'var\s+{re.escape(name)}\s*=\s*[\"\']([^\"\']*)[\"\']', html)
        return match.group(1) if match else default

    def _warm_up_browser_state(self):
        ajax_headers = self._ajax_headers()
        try:
            self.session.get('https://cas.whu.edu.cn/authserver/tenant/info', headers=ajax_headers, timeout=10)
            fp_seed = '|'.join([
                'Chrome',
                'Windows',
                self.username,
                self.session.cookies.get('JSESSIONID', ''),
                self.session.cookies.get('route', ''),
            ])
            bfp = hashlib.md5(fp_seed.encode('utf-8')).hexdigest().upper()
            self.session.get(
                'https://cas.whu.edu.cn/authserver/bfp/info',
                headers=ajax_headers,
                params={'bfp': bfp, '_': int(time.time() * 1000)},
                timeout=10,
            )
        except Exception:
            pass

    def _check_need_captcha(self):
        url = 'https://cas.whu.edu.cn/authserver/checkNeedCaptcha.htl'
        res = self.session.get(
            url,
            headers=self._ajax_headers(),
            params={'username': self.username},
            timeout=10,
        )
        try:
            return bool(res.json().get('isNeed'))
        except Exception:
            return 'true' in res.text.lower()

    def _captcha_distance(self, distance_res):
        if isinstance(distance_res, dict):
            if 'x' in distance_res:
                return float(distance_res['x'])
            if distance_res.get('target'):
                return float(distance_res['target'][0])
        return float(distance_res)

    def _make_tracks(self, distance):
        distance = max(1, int(distance))
        steps = max(8, min(28, distance // 6))
        tracks = [{'a': 0, 'b': 0, 'c': 0}]
        current = 0
        for i in range(1, steps):
            progress = i / steps
            eased = 1 - pow(1 - progress, 3)
            next_x = min(distance - 1, max(current + 1, int(distance * eased)))
            if next_x <= current:
                continue
            y = random.choice([-2, -1, 0, 1, 2])
            tracks.append({'a': next_x, 'b': y, 'c': random.randint(22, 58)})
            current = next_x
        tracks.append({'a': distance, 'b': random.choice([-1, 0, 1]), 'c': random.randint(35, 95)})
        return tracks

    def _verify_slider_captcha(self):
        if not CaptchaSolver:
            print('[-] 模块 CaptchaSolver 未正确导入，无法处理滑块验证。')
            return False

        print('[*] 发现【新版滑块验证码】，正在请求图片与识别...')
        ajax_headers = self._ajax_headers()
        try:
            self.session.get('https://cas.whu.edu.cn/authserver/common/toSliderCaptcha.htl', headers=ajax_headers, timeout=10)
            s_res = self.session.get(
                'https://cas.whu.edu.cn/authserver/common/openSliderCaptcha.htl',
                headers=ajax_headers,
                params={'_': int(time.time() * 1000)},
                timeout=15,
            ).json()
        except Exception as e:
            print(f'[-] 获取滑块图片失败: {e}')
            return False

        try:
            big_image = s_res.get('bigImage', '')
            small_image = s_res.get('smallImage', '')
            bg_data = base64.b64decode(big_image)
            slide_data = base64.b64decode(small_image)
            safe_secure = slide_data[-16:].decode('latin1')

            bg_img = Image.open(BytesIO(bg_data))
            natural_width = bg_img.width
            canvas_length = 280

            solver = CaptchaSolver()
            distance_res = solver.solve_slide_captcha(bg_image_data=slide_data, slide_image_data=bg_data)
            distance = self._captcha_distance(distance_res)
            move_length = int(distance * (canvas_length / natural_width))
            tracks = self._make_tracks(move_length)
            verify_body = {
                'canvasLength': canvas_length,
                'moveLength': move_length,
                'tracks': tracks,
            }
            sign_plain = json.dumps(verify_body, ensure_ascii=False, separators=(',', ':'))
            sign = self._encrypt_password(sign_plain, safe_secure)

            v_res = self.session.post(
                'https://cas.whu.edu.cn/authserver/common/verifySliderCaptcha.htl',
                headers=ajax_headers,
                data={'sign': sign},
                timeout=15,
            ).json()

            if v_res.get('errorCode') == 1:
                print(f'[+] 滑块验证通过！moveLength={move_length}')
                return True
            print(f'[-] 滑块校验失败: {v_res}')
            return False
        except Exception as e:
            print(f'[-] 滑块验证过程中报错: {e}')
            return False

    def _solve_image_captcha(self, data):
        if not CaptchaSolver:
            print('[-] 模块 CaptchaSolver 未正确导入，普通验证码无法验证。')
            return False

        try:
            c_res = self.session.get(
                'https://cas.whu.edu.cn/authserver/getCaptcha.htl',
                headers=self._ajax_headers(),
                params={'_': int(time.time() * 1000)},
                timeout=10,
            )
            solver = CaptchaSolver()
            c_text = solver.solve_image_captcha(image_data=c_res.content)
            print(f'[+] 验证码识别处理结果: {c_text}')
            data['captcha'] = c_text
            return True
        except Exception as e:
            print(f'[-] 验证码模块调用报错: {e}')
            return False

    def login(self):
        print(f"[*] 开始尝试以 {self.username} 登录 WHU...")
        print("[*] 正在打开新版登录界面获取表单与加密盐...")

        try:
            res = self.session.get(self.login_url, headers=self.headers, timeout=15)
            res.encoding = res.apparent_encoding
            soup = BeautifulSoup(res.text, 'html.parser')
        except Exception as e:
            print(f"[-] 网站访问失败: {e}")
            return False

        form = soup.select_one('#pwdFromId')
        if not form:
            print("[-] 未在页面中找到新版账号密码表单(pwdFromId)。")
            return False

        data = self._form_payload(form)
        salt_tag = form.select_one('#pwdEncryptSalt') or soup.select_one('#pwdEncryptSalt')
        salt = salt_tag.get('value', '') if salt_tag else ''
        if not salt:
            print("[-] 获取新版加密盐(pwdEncryptSalt)失败。")
            return False

        captcha_switch = self._extract_var(res.text, 'captchaSwitch', default='2')
        data.update({
            'username': self.username,
            'password': self._encrypt_password(self.password, salt),
            'cllt': 'userNameLogin',
            'dllt': data.get('dllt', 'generalLogin'),
            '_eventId': data.get('_eventId', 'submit'),
            'lt': data.get('lt', ''),
            'execution': data.get('execution', ''),
        })
        data.pop('passwordText', None)
        data.pop('rememberMe', None)

        print(f"[+] 成功提取新版参数 Salt: {salt}, Execution: {data.get('execution', '')}, captchaSwitch={captcha_switch}")
        self._warm_up_browser_state()

        try:
            need_captcha = self._check_need_captcha()
        except Exception as e:
            print(f"[-] 检测验证码需求失败: {e}")
            return False

        if need_captcha:
            if captcha_switch == '2':
                if not self._verify_slider_captcha():
                    return False
            else:
                if not self._solve_image_captcha(data):
                    return False

        print("[*] 正在发送新版登录认证POST请求包...")
        post_headers = self.headers.copy()
        post_headers.update({
            'Referer': self.login_url,
            'Origin': 'https://cas.whu.edu.cn',
        })
        try:
            res_post = self.session.post(self.login_url, data=data, headers=post_headers, allow_redirects=True, timeout=15)
            res_post.encoding = res_post.apparent_encoding
        except Exception as e:
            print(f"[-] 发送POST请求失败: {e}")
            return False

        if 'dingxiang-inc.com' in res_post.text or '/whu_captcha_check_002/' in res_post.text:
            print("[-] 触发了额外访问校验，当前会话需要先完成页面端验证。")
            return False

        soup_post = BeautifulSoup(res_post.text, 'html.parser')
        error_span = (
            soup_post.select_one('#usernameSpecificError')
            or soup_post.select_one('#passwordError')
            or soup_post.select_one('#showErrorTip')
            or soup_post.select_one('.auth_error')
        )
        if error_span and error_span.text.strip():
            print(f"[-] 登录失败, CAS返回错误: {error_span.text.strip()}")
            return False

        if "温馨提示" in res_post.text or "个人中心" in res_post.text or "cas.whu.edu.cn" not in res_post.url:
            print("[+] 登录成功！已成功转跳并获取身份凭证。")
            print(f"[*] 当前所处URL: {res_post.url}")
            return True

        print("[-] 登录并未按预期跳转，请确认账号密码信息，或检查是否有进一步的行为验证阻挡。")
        print(f"[*] 当前所处URL: {res_post.url}")
        return False

if __name__ == '__main__':
    whu_login = WHULogin('testuser1234@test.com', 'Test123pwd')
    whu_login.login()
