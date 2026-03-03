# whu自动登录.py
import requests
from bs4 import BeautifulSoup
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys
import os
import json
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
        """生成指定长度的随机字符串，用于构造加密向量和填充"""
        return ''.join(random.choice(self.chars) for _ in range(length))

    def _encrypt_password(self, pwd, salt):
        """
        使用提取出的盐(pwdDefaultEncryptSalt)和AES-CBC对密码进行混淆加密
        JS原逻辑: _gas(_rds(64)+password, salt, _rds(16)) -> Base64
        """
        data = (self._rds(64) + pwd).encode('utf-8')
        key = salt.encode('utf-8')
        iv = self._rds(16).encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(ciphertext).decode('utf-8')

    def login(self):
        print(f"[*] 开始尝试以 {self.username} 登录 WHU...")
        
        # 1. 访问登录页面，获取Cookie及表单参数
        print("[*] 正在打开登录界面获取Token与Salt流...")
        try:
            res = self.session.get(self.login_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
        except Exception as e:
            print(f"[-] 网站访问失败: {e}")
            return False

        # 2. 提取隐藏的必要表单项 (确保只抓取casLoginForm里的数据以防干扰)
        data = {}
        form = soup.select_one('#casLoginForm')
        if not form:
            print("[-] 未在页面中找到目标表单(casLoginForm)。请检查是否需要连接校园网或VPN。")
            return False

        for input_tag in form.select('input[type="hidden"]'):
            name = input_tag.get('name')
            if name:
                data[name] = input_tag.get('value', '')

        # 3. 提取AES加密参数与验证码需要检测
        # CAS 先检测是否需要滑块或普通验证码 needCaptcha.html
        need_captcha_url = f'https://cas.whu.edu.cn/authserver/needCaptcha.html?username={self.username}&pwdEncrypt2=pwdEncryptSalt'
        need_c_res = self.session.get(need_captcha_url, headers=self.headers).text
        
        salt_tag = soup.select_one('#pwdDefaultEncryptSalt')
        salt = salt_tag['value'] if getattr(salt_tag, 'attrs', None) and 'value' in salt_tag.attrs else ''
        
        # update salt if provided via needCaptcha: "true::::some_salt"
        if "::::" in need_c_res:
            salt = need_c_res.split("::::")[1].strip()

        if not salt:
            print("[-] 获取加密盐失败。")
            return False
            
        print(f"[+] 成功提取加密参数 Salt: {salt}, Execution: {data.get('execution', '')}")

        # 4. 构造基础登录请求包
        data['username'] = self.username
        data['password'] = self._encrypt_password(self.password, salt)
        
        is_slider_captcha = soup.select_one('#isSliderCaptcha')
        is_slider_captcha = True if is_slider_captcha and is_slider_captcha.get('value') == 'true' else False

        # 5. 自动识别人机验证码(如果要)
        if "true" in need_c_res:
            if is_slider_captcha:
                print("[*] 发现【滑块验证码】机制，正在请求图片与识别...")
                slider_url = 'https://cas.whu.edu.cn/authserver/sliderCaptcha.do'
                s_res = self.session.post(slider_url, headers=self.headers).json()
                
                bg_data = base64.b64decode(s_res.get('bigImage', ''))
                slide_data = base64.b64decode(s_res.get('smallImage', ''))
                
                try:
                    img = Image.open(BytesIO(bg_data))
                    natural_width = img.width
                    
                    if CaptchaSolver:
                        solver = CaptchaSolver()
                        # 注意大小滑块反了的处理：滑块识别时需要 bg_image_data 为小图，slide_image_data 为大图 传递入内部
                        distance_res = solver.solve_slide_captcha(bg_image_data=slide_data, slide_image_data=bg_data)
                        
                        if isinstance(distance_res, dict):
                            distance = float(distance_res.get('x', distance_res.get('target', [0])[0]))
                        else:
                            distance = float(distance_res)
                            
                        # 进行针对280px画布的比例缩放运算
                        canvas_length = 280
                        scaled_distance = int(distance * (canvas_length / natural_width))
                        
                        # 验证滑块
                        v_url = 'https://cas.whu.edu.cn/authserver/verifySliderImageCode.do'
                        v_res = self.session.post(v_url, headers=self.headers, data={
                            'canvasLength': canvas_length,
                            'moveLength': scaled_distance
                        }).json()
                        
                        if v_res.get('code') == 0:
                            print(f"[+] 滑块验证通过！(Sign: {v_res.get('sign','')})")
                            data['sign'] = v_res.get('sign')
                        else:
                            print(f"[-] 滑块校验失败: {v_res}")
                    else:
                        print("[-] 模块 CaptchaSolver 未正确导入，滑块无法验证被略过。")
                except Exception as e:
                    print(f"[-] 滑块验证过程中报错: {e}")
            else:
                captcha_img = soup.select_one('#captchaImg')
                if captcha_img and captcha_img.get('src'):
                    print("[*] 发现常规图片验证码(CaptchaImg)机制，正在尝试识别...")
                    src = captcha_img.get('src')
                    c_url = 'https://cas.whu.edu.cn' + src if src.startswith('/') else 'https://cas.whu.edu.cn/authserver/' + src
                    c_res = self.session.get(c_url, headers=self.headers)
                    if CaptchaSolver:
                        try:
                            solver = CaptchaSolver()
                            c_text = solver.solve_image_captcha(image_data=c_res.content)
                            print(f"[+] 验证码识别处理结果: {c_text}")
                            data['captchaResponse'] = c_text
                        except Exception as e:
                            print(f"[-] 验证码模块调用报错: {e}")
                            data['captchaResponse'] = 'ABCD'
                    else:
                        print("[-] 模块 CaptchaSolver 未正确导入。")
                        data['captchaResponse'] = 'ABCD'

        # 6. 发送登录请求包 (有可能会产生转跳/重定向)
        print("[*] 正在发送登录认证POST请求包...")
        try:
            res_post = self.session.post(self.login_url, data=data, headers=self.headers, allow_redirects=True, timeout=15)
        except Exception as e:
            print(f"[-] 发送POST请求失败: {e}")
            return False

        # 7. 解析返回结果与可能遇到的转跳
        if 'dingxiang-inc.com' in res_post.text or '/whu_captcha_check_002/' in res_post.text:
            print("[-] 触发了网关防御设施：顶象(DingXiang)访问风控拦截。当前IP需完成顶象验证方可继续传递登录请求。")
            return False

        soup_post = BeautifulSoup(res_post.text, 'html.parser')
        
        error_span = soup_post.select_one('#usernameSpecificError') or soup_post.select_one('#passwordError') or soup_post.select_one('.auth_error')
        if error_span and error_span.text.strip():
            print(f"[-] 登录失败, CAS返回错误: {error_span.text.strip()}")
            return False
            
        auth_error = soup_post.find('span', id='showErrorTip')
        if auth_error and auth_error.text.strip():
            print(f"[-] 认证失败提示: {auth_error.text.strip()}")
            return False

        if "温馨提示" in res_post.text or "个人中心" in res_post.text or "cas.whu.edu.cn" not in res_post.url:
            print("[+] 登录成功！已成功转跳并获取身份凭证。")
            print(f"[*] 当前所处URL: {res_post.url}")
            return True
        else:
            print("[-] 登录并未按预期跳转，请确认账号密码信息，或检查是否有进一步的行为验证阻挡。")
            return False

if __name__ == '__main__':
    whu_login = WHULogin('testuser1234@test.com', 'Test123pwd')
    whu_login.login()
