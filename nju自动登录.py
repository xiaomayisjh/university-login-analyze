# -*- coding: utf-8 -*-
import requests
import re
import random
import string
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
from captcha_solver import HybridCaptchaSolver

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

def random_string(length):
    return ''.join(random.choice(AES_CHARS) for _ in range(length))

def encrypt_password(password, salt):
    if not salt:
        return password
    
    random_prefix = random_string(64)
    iv = random_string(16)
    
    data = random_prefix + password
    
    key_bytes = salt.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    data_bytes = data.encode('utf-8')
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_data = pad(data_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    
    return base64.b64encode(encrypted).decode('utf-8')

def get_page_params(session, login_url):
    try:
        resp = session.get(login_url, timeout=15)
        resp.encoding = 'utf-8'
        html_text = resp.text
        
        salt_match = re.search(r'id="pwdEncryptSalt"\s+value="([^"]*)"', html_text)
        execution_match = re.search(r'name="execution"\s+value="([^"]*)"', html_text)
        
        pwd_encrypt_salt = salt_match.group(1) if salt_match else ""
        execution = execution_match.group(1) if execution_match else ""
        
        return pwd_encrypt_salt, execution
    except Exception as e:
        print(f"[-] 获取页面参数失败: {e}")
        return None, None

def login_nju(username, password):
    print(f"开始尝试登录（南京大学）：{username}")
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive"
    })
    
    login_url = "https://authserver.nju.edu.cn/authserver/login"
    solver = HybridCaptchaSolver(primary='modelscope', fallback=True)
    max_retries = 5
    
    for attempt in range(max_retries):
        print(f"\n--- 第 {attempt + 1} 次尝试 ---")
        
        print("[*] 正在获取登录页面参数...")
        pwd_encrypt_salt, execution = get_page_params(session, login_url)
        
        if not pwd_encrypt_salt:
            print("[-] 未能获取密码加密盐值")
            continue
        
        print(f"[+] 成功获取加密盐值: {pwd_encrypt_salt}")
        print(f"[+] 成功获取execution: {execution[:50]}...")
        
        encrypted_password = encrypt_password(password, pwd_encrypt_salt)
        print("[+] 密码加密成功")
        
        captcha_url = f"https://authserver.nju.edu.cn/authserver/getCaptcha.htl?{int(random.random() * 10000000000)}"
        print("[*] 正在获取验证码...")
        try:
            captcha_resp = session.get(captcha_url, timeout=10)
            captcha_data = captcha_resp.content
        except Exception as e:
            print(f"[-] 获取验证码失败: {e}")
            continue
        
        try:
            print("[*] 正在识别验证码...")
            captcha_code = solver.solve_image_captcha(image_data=captcha_data)
            print(f"[+] 验证码识别结果: {captcha_code}")
        except Exception as e:
            print(f"[-] 验证码识别失败: {e}")
            continue
        
        login_data = {
            "username": username,
            "password": encrypted_password,
            "captcha": captcha_code,
            "_eventId": "submit",
            "cllt": "userNameLogin",
            "dllt": "generalLogin",
            "lt": "",
            "execution": execution
        }
        
        print("[*] 正在发送登录请求...")
        try:
            login_resp = session.post(login_url, data=login_data, allow_redirects=False, timeout=15)
        except Exception as e:
            print(f"[-] 登录请求失败: {e}")
            continue
        
        if login_resp.status_code == 302:
            location = login_resp.headers.get("Location", "")
            print(f"[+] 登录成功！重定向至: {location}")
            return True
        elif login_resp.status_code == 200:
            resp_text = login_resp.text
            
            if "验证码错误" in resp_text or "验证码不正确" in resp_text:
                print("[-] 验证码错误，准备重试...")
                continue
            elif "用户名或密码有误" in resp_text or "密码错误" in resp_text:
                print("[-] 用户名或密码错误！")
                return False
            elif "账号不存在" in resp_text:
                print("[-] 账号不存在！")
                return False
            else:
                if "登录成功" in resp_text or "welcome" in resp_text.lower():
                    print("[+] 登录成功！")
                    return True
                print(f"[-] 登录失败，未知原因。状态码: {login_resp.status_code}")
        else:
            resp_text = login_resp.text if hasattr(login_resp, 'text') else ""
            print(f"[-] 登录失败，HTTP状态码: {login_resp.status_code}")
            
            if "验证码错误" in resp_text or "验证码不正确" in resp_text:
                print("[-] 验证码错误，准备重试...")
                continue
            elif "用户名或密码有误" in resp_text or "密码错误" in resp_text:
                print("[-] 用户名或密码错误！")
                return False
            elif "账号不存在" in resp_text:
                print("[-] 账号不存在！")
                return False
    
    print(f"[-] 已达到最大重试次数 {max_retries}，登录失败")
    return False

if __name__ == "__main__":
    print("=" * 50)
    print("    南京大学统一身份认证自动登录脚本")
    print("=" * 50)
    
    test_user = "testuser123@test.com"
    test_pwd = "Test123pwd"
    
    print(f"[*] 测试账号: {test_user}")
    login_nju(test_user, test_pwd)
    print("=" * 50)
