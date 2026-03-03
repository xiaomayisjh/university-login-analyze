import base64
import requests
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import sys
import os
import json

# 将 captcha_solver 的目录加入系统路径以便导入模块
sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
from captcha_solver import CaptchaSolver

def encrypt_password(password, public_key_str):
    """使用从服务器获取的 RSA 公钥对密码进行加密"""
    try:
        # 处理可能包含转义字符的换行
        public_key_str = public_key_str.replace('\\n', '\n')
        rsakey = RSA.importKey(public_key_str)
        cipher = PKCS1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(password.encode(encoding="utf-8"))).decode('utf-8')
        return cipher_text
    except Exception as e:
        print(f"遇到密码加密错误: {e}")
        return ""

def login_pku(username, password):
    """执行北京大学统一身份认证的自动登录流程"""
    print(f"开始尝试登录（北京大学）：{username}")
    
    # 建立会话对象并设置通用请求头
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    
    # 1. 访问 oauth 页面以初始化 session
    oauth_url = "https://iaaa.pku.edu.cn/iaaa/oauth.jsp?appID=portal2017&appName=%E5%8C%97%E4%BA%AC%E5%A4%A7%E5%AD%A6%E9%97%A8%E6%88%B7&redirectUrl=https://portal.pku.edu.cn/portal2017/login.jsp"
    try:
        session.get(oauth_url, timeout=10)
    except Exception as e:
        print(f"初始化会话失败: {e}")
        return False
    
    # 2. 获取 RSA 加密公钥
    pk_url = "https://iaaa.pku.edu.cn/iaaa/getPublicKey.do"
    try:
        pk_res = session.post(pk_url, data={"appID": "portal2017"}, timeout=10)
        pk_data = pk_res.json()
    except Exception as e:
        print(f"请求公钥接口失败: {e}")
        return False

    if pk_data.get("success"):
        public_key = pk_data.get("key")
        print("成功获取 RSA 公钥")
    else:
        print(f"获取公钥失败，服务器返回: {pk_data}")
        return False
        
    # 3. 对明文密码进行加密
    encrypted_pwd = encrypt_password(password, public_key)
    if not encrypted_pwd:
        return False
    print("成功对密码进行加密")
    
    # 4. 构造统一登录表单数据
    login_url = "https://iaaa.pku.edu.cn/iaaa/oauthlogin.do"
    login_data = {
        "appid": "portal2017",
        "userName": username,
        "password": encrypted_pwd,
        "randCode": "",
        "smsCode": "",
        "otpCode": "",
        "redirUrl": "https://portal.pku.edu.cn/portal2017/login.jsp"
    }
    
    # 5. 发起第一次尝试登录（无验证码）
    print("发起第一次登录请求（不带验证码）...")
    try:
        login_res = session.post(login_url, data=login_data, timeout=10)
        login_json = login_res.json()
    except Exception as e:
        print(f"第一次登录请求失败: {e}")
        return False
        
    print(f"第一次登录尝试返回: {json.dumps(login_json, ensure_ascii=False)}")
    
    # 如果直接登录成功
    if login_json.get("success"):
        print("登录成功！")
        return True
    
    # 6. 判断是否由于需要验证码等原因失败
    if login_json.get("showCode"):
        print("根据服务器返回，需要提供验证码。开始获取验证码（支持失败重试）...")
        
        max_retries = 3
        solver = CaptchaSolver()
        
        for attempt in range(max_retries):
            print(f"\n--- 第 {attempt + 1} 次尝试解析验证码并登录 ---")
            rand_num = random.random()
            captcha_url = f"https://iaaa.pku.edu.cn/iaaa/servlet/DrawServlet?Rand={rand_num}"
            try:
                captcha_res = session.get(captcha_url, timeout=10)
                captcha_data = captcha_res.content
            except Exception as e:
                print(f"获取验证码图片失败: {e}")
                continue
                
            try:
                print("正在通过 CaptchaSolver 识别验证码...")
                rand_code = solver.solve_image_captcha(image_data=captcha_data)
                print(f"验证码成功识别结果: {rand_code}")
            except Exception as e:
                print(f"未能成功识别验证码: {e}")
                continue
                
            # 将识别到的验证码补充到表单数据中
            login_data["randCode"] = rand_code
            
            print("发起带验证码的登录请求...")
            try:
                login_res2 = session.post(login_url, data=login_data, timeout=10)
                login_json2 = login_res2.json()
            except Exception as e:
                print(f"带验证码的登录请求失败: {e}")
                continue
                
            print(f"带验证码的登录尝试返回: {json.dumps(login_json2, ensure_ascii=False)}")
            
            if login_json2.get("success"):
                print("登录成功！")
                return True
            else:
                errors = login_json2.get("errors", {})
                code = errors.get('code')
                msg = errors.get('msg')
                print(f"登录失败，错误代码: {code}，信息: {msg}")
                
                # 如果错误信息提示验证码错误，则进入下一次重试
                if code == "E03" or "CAPTCHA" in msg:
                    print("检测到验证码错误，准备重试...")
                    continue
                else:
                    # 如果是账号密码错误等非验证码问题，直接返回
                    print("非验证码错误，终止重试。")
                    return False
                    
        print(f"验证码错误或服务异常达到 {max_retries} 次，登录流程终止。")
        return False
    else:
        errors = login_json.get("errors", {})
        print(f"无需验证码，但登录仍然失败。错误代码: {errors.get('code')}，信息: {errors.get('msg')}")
        return False

if __name__ == "__main__":
    # 使用测试信息进行执行尝试
    test_user = "testuser123@test.com"
    test_pwd = "Test123pwd"
    login_pku(test_user, test_pwd)
