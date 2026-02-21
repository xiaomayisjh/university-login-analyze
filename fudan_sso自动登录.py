import requests
from bs4 import BeautifulSoup
import base64
import urllib3
import time
import sys
import os

# 忽略SSL警告
urllib3.disable_warnings()

# 尝试导入已经写好的验证码模块
# 假设 captcha_solver 是当前目录下的一个包，且可以使用 CaptchaSolver 类
try:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from captcha_solver.captcha_solver import CaptchaSolver
except ImportError:
    CaptchaSolver = None

class FudanSSOLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.login_url = "https://sso.fdsm.fudan.edu.cn/login"
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        })

    def _encrypt_password(self, clean_pwd):
        """
        根据前端 js/login.js 的逻辑加密密码：
        var e = window.btoa(fm.password.value + 'fdsm2022');
        """
        salt = 'fdsm2022'
        salted_pwd = clean_pwd + salt
        return base64.b64encode(salted_pwd.encode('utf-8')).decode('utf-8')

    def do_login(self):
        print("[*] 开始尝试复旦管院 SSO 自动登录...")
        
        # 1. 访问登录页面以获取隐藏的表单字段，特别是 execution 等防止重放的令牌
        try:
            print("[*] 正在获取页面及执行令牌(execution)...")
            res = self.session.get(self.login_url, verify=False, timeout=10)
            res.raise_for_status()
        except Exception as e:
            print(f"[-] 获取登录页失败: {e}")
            return False

        soup = BeautifulSoup(res.text, 'html.parser')
        form = soup.find('form', id='fm1')
        if not form:
            print("[-] 未在页面中找到邮箱/密码登录表单 (ID: fm1)")
            return False

        # 2. 提取所有提交所需的表单参数
        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if not input_name:
                continue
            input_value = input_tag.get('value', '')
            data[input_name] = input_value

        # 检查是否需要验证码 (根据前端分析，当前 showCaptcha 默认返回空，若后续开启可在此处对接)
        # 前端的验证逻辑回调： { ret: 0, ticket: '', randstr: '' }
        # 若需要验证码会改变 captchaTicket 和 captchaRandom 的值
        need_captcha = False 
        # 此处判断逻辑可根据实际后端限制动态演变。若后续有图形验证码，也可直接调用模块：
        if need_captcha and CaptchaSolver:
            print("[*] 检测到验证码，准备调用识别模块...")
            try:
                # 若页面上有特定验证码图片元素可通过 get 获取后识别
                # captcha_img_res = self.session.get("CAPTCHA_IMAGE_URL")
                solver = CaptchaSolver()
                # captcha_result = solver.solve_image_captcha(image_data=captcha_img_res.content)
                # data['captchaTicket'] = captcha_result['ticket']
                # data['captchaRandom'] = captcha_result['randstr']
                pass
            except Exception as e:
                print(f"[-] 验证码处理失败: {e}")
                return False

        # 3. 填充账号与密码
        data['username'] = self.username
        data['password'] = self._encrypt_password(self.password)
        
        # 模拟部分前端重置行为
        if 'useMobile' in data:
            data['useMobile'] = 'false'
        if 'isWechat' in data:
            data['isWechat'] = 'false'

        print(f"[*] 使用用户名: {self.username} 准备发送请求")
        print(f"[*] 密码经过算法 (btoa) 加密后的值: {data['password']}")

        # 4. 发起登录请求
        try:
            print("[*] 正在发送登录 POST 请求...")
            post_res = self.session.post(
                self.login_url, 
                data=data, 
                verify=False, 
                allow_redirects=False, # 防止被302直接重定向到其他页面而拿不到请求头，用于精确分析
                timeout=10
            )

            if post_res.status_code == 302:
                # 302重定向证明登录成功并且派发了 TGT 或跳转到 service 提供服务
                service_url = post_res.headers.get('Location')
                print(f"[+] 登录成功！重定向目标: {service_url}")
                return True
            elif post_res.status_code == 401:
                print("[-] 登录失败: 用户名或密码错误 (HTTP 401 Unauthorized)")
                return False
            elif post_res.status_code == 200:
                # 有的CAS系统在密码错误时返回200并附带错误提示
                print("[-] 登录失败: 服务器返回了错误提示页面。需检查票据或验证码是否被强制唤起")
                return False
            else:
                print(f"[-] 登录异常，返回状态码: {post_res.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] 登录请求出错: {e}")
            return False

if __name__ == "__main__":
    # 使用用户提供的测试账号
    USERNAME = "testuser123"
    PASSWORD = "Test123pwd"
    
    login_client = FudanSSOLogin(USERNAME, PASSWORD)
    login_client.do_login()
