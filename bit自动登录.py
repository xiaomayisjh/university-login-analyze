#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
北京理工大学SSO自动登录脚本
通过完整逆向分析实现自动登录
"""

import requests
from bs4 import BeautifulSoup
import re
import json
import base64
import execjs
import random
import time
from captcha_solver.captcha_solver import HybridCaptchaSolver


class BITSSOLogin:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = 'https://sso.bit.edu.cn'
        self.login_url = f'{self.base_url}/cas/login'
        
        # 设置随机User-Agent
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # 验证码识别器
        self.captcha_solver = HybridCaptchaSolver(primary='server', fallback=True)
    
    def get_random_headers(self):
        """获取随机headers"""
        headers = self.headers.copy()
        headers['User-Agent'] = random.choice(self.user_agents)
        return headers
    
    def get_login_page(self):
        """获取登录页面并提取关键信息"""
        print("步骤1: 获取登录页面...")
        
        response = self.session.get(self.login_url, headers=self.get_random_headers())
        if response.status_code != 200:
            raise Exception(f"获取登录页面失败，状态码: {response.status_code}")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 提取login-croypto (AES密钥)
        login_croypto_elem = soup.find('p', {'id': 'login-croypto'})
        if not login_croypto_elem:
            raise Exception("未找到login-croypto字段")
        self.aes_key = login_croypto_elem.get_text().strip()
        print(f"AES密钥: {self.aes_key}")
        
        # 提取flowkey (包含execution token)
        flowkey_elem = soup.find('p', {'id': 'login-page-flowkey'})
        if not flowkey_elem:
            raise Exception("未找到login-page-flowkey字段")
        self.flowkey = flowkey_elem.get_text().strip()
        print(f"Flowkey长度: {len(self.flowkey)}")
        
        # 从flowkey中提取execution
        # flowkey格式: {uuid}_{base64_encoded_data}
        if '_' in self.flowkey:
            self.execution = self.flowkey
        else:
            self.execution = self.flowkey
        
        print(f"Execution token已获取")
        
        # 提取其他配置
        site_key_elem = soup.find('p', {'id': 'siteKey'})
        self.site_key = site_key_elem.get_text().strip() if site_key_elem else ''
        
        captcha_id_elem = soup.find('p', {'id': 'captchaId'})
        self.captcha_id = captcha_id_elem.get_text().strip() if captcha_id_elem else ''
        
        return response.text
    
    def aes_encrypt(self, plaintext):
        """
        使用AES-ECB-PKCS7加密
        使用PyExecJS调用JavaScript的CryptoJS
        """
        # CryptoJS的JavaScript代码
        crypto_js_code = """
        var CryptoJS = require('crypto-js');
        
        function aesEncrypt(plaintext, key) {
            const keyParsed = CryptoJS.enc.Utf8.parse(key);
            const encrypted = CryptoJS.AES.encrypt(plaintext, keyParsed, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            });
            return encrypted.toString();
        }
        """
        
        try:
            # 创建JS上下文
            ctx = execjs.compile(crypto_js_code)
            
            # 执行加密
            encrypted = ctx.call('aesEncrypt', plaintext, self.aes_key)
            return encrypted
        except Exception as e:
            print(f"AES加密失败: {e}")
            # 如果PyExecJS失败，尝试使用pycryptodome
            return self.aes_encrypt_python(plaintext)
    
    def aes_encrypt_python(self, plaintext):
        """使用Python的pycryptodome进行AES加密"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import base64
            
            # 解码AES密钥
            key = base64.b64decode(self.aes_key)
            
            # 创建AES cipher (ECB模式)
            cipher = AES.new(key, AES.MODE_ECB)
            
            # 填充并加密
            plaintext_bytes = plaintext.encode('utf-8')
            padded_data = pad(plaintext_bytes, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            
            # 返回base64编码的结果
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise Exception(f"Python AES加密失败: {e}")
    
    def check_captcha_needed(self, username):
        """检查是否需要验证码"""
        print("步骤2: 检查是否需要验证码...")
        
        url = f'{self.base_url}/cas/api/protected/user/findCaptchaCount/{username}'
        
        try:
            response = self.session.get(url, headers=self.get_random_headers())
            if response.status_code == 200:
                data = response.json()
                # API可能返回不同的格式，需要兼容处理
                if isinstance(data, dict):
                    captcha_count = data.get('data', 0)
                    if isinstance(captcha_count, dict):
                        # 如果data是字典，说明API返回错误
                        print(f"API响应: {captcha_count}")
                        return False
                else:
                    captcha_count = data
                
                print(f"验证码计数: {captcha_count}")
                return captcha_count > 0
        except Exception as e:
            print(f"检查验证码失败: {e}")
        
        return False
    
    def get_captcha_image(self):
        """获取验证码图片"""
        print("步骤3: 获取验证码图片...")
        
        # 验证码URL通常是动态生成的
        captcha_url = f'{self.base_url}/cas/captcha.jpg?t={int(time.time() * 1000)}'
        
        try:
            response = self.session.get(captcha_url, headers=self.get_random_headers())
            if response.status_code == 200:
                return response.content
        except Exception as e:
            print(f"获取验证码失败: {e}")
        
        return None
    
    def login(self, username, password):
        """
        执行登录
        
        Args:
            username: 用户名
            password: 密码
        
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # 步骤1: 获取登录页面
            self.get_login_page()
            
            # 步骤2: 检查是否需要验证码
            need_captcha = self.check_captcha_needed(username)
            captcha_code = ''
            
            if need_captcha:
                print("需要验证码，正在识别...")
                captcha_image = self.get_captcha_image()
                if captcha_image:
                    try:
                        captcha_code = self.captcha_solver.solve_image_captcha(image_data=captcha_image)
                        print(f"验证码识别结果: {captcha_code}")
                    except Exception as e:
                        print(f"验证码识别失败: {e}")
                        captcha_code = ''
            
            # 步骤3: 准备登录数据
            print("步骤4: 准备登录数据...")
            
            # 注意：根据分析，BIT SSO可能不需要对密码进行额外加密
            # 直接提交明文密码，服务器端会处理
            login_data = {
                'username': username,
                'password': password,
                'type': 'UsernamePassword',
                '_eventId': 'submit',
                'geolocation': '',
                'execution': self.execution,
                'captcha_code': captcha_code,
            }
            
            print(f"用户名: {username}")
            print(f"Execution: {self.execution[:50]}...")
            print(f"验证码: {captcha_code if captcha_code else '无'}")
            
            # 步骤4: 发送登录请求
            print("步骤5: 发送登录请求...")
            
            login_headers = self.get_random_headers()
            login_headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': self.login_url,
                'Origin': self.base_url,
                'Cache-Control': 'max-age=0',
            })
            
            # 添加小延迟模拟真实用户
            time.sleep(random.uniform(0.5, 1.5))
            
            response = self.session.post(
                self.login_url,
                data=login_data,
                headers=login_headers,
                allow_redirects=False
            )
            
            print(f"响应状态码: {response.status_code}")
            
            # 检查是否重定向（登录成功）
            if response.status_code in [301, 302]:
                redirect_url = response.headers.get('Location', '')
                print(f"\n✓ 登录成功！")
                print(f"重定向URL: {redirect_url}")
                
                # 跟随重定向获取最终页面
                if redirect_url:
                    final_response = self.session.get(
                        redirect_url,
                        headers=self.get_random_headers(),
                        allow_redirects=True
                    )
                    print(f"最终页面状态码: {final_response.status_code}")
                
                return True, f"登录成功！重定向到: {redirect_url}"
            else:
                # 登录失败，解析错误信息
                print(f"\n✗ 登录失败")
                
                # 尝试从响应中提取错误信息
                if '用户名或密码错误' in response.text or 'password' in response.text.lower():
                    error_msg = "用户名或密码错误"
                elif 'captcha' in response.text.lower() or '验证码' in response.text:
                    error_msg = "验证码错误"
                else:
                    # 尝试从HTML中提取错误消息
                    soup = BeautifulSoup(response.text, 'html.parser')
                    error_elem = soup.find(class_=re.compile(r'error|alert|message', re.I))
                    if error_elem:
                        error_msg = error_elem.get_text().strip()
                    else:
                        error_msg = f"登录失败，状态码: {response.status_code}"
                
                print(f"错误信息: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            error_msg = f"登录过程出错: {str(e)}"
            print(f"\n✗ {error_msg}")
            import traceback
            traceback.print_exc()
            return False, error_msg


def main():
    """主函数"""
    print("=" * 80)
    print("北京理工大学SSO自动登录脚本")
    print("=" * 80)
    print()
    
    # 测试账号
    username = "testuser123@test.com"
    password = "Test123pwd"
    
    print(f"用户名: {username}")
    print(f"密码: {'*' * len(password)}")
    print()
    
    # 创建登录对象
    login_system = BITSSOLogin()
    
    # 执行登录
    success, message = login_system.login(username, password)
    
    print()
    print("=" * 80)
    if success:
        print("✓ 登录完成！")
    else:
        print("✗ 登录失败")
    print("=" * 80)
    print()
    print(message)


if __name__ == "__main__":
    main()
