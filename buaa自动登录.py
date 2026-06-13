"""
北京航空航天大学统一身份认证系统自动登录脚本
使用纯HTTP请求实现，无需浏览器自动化
"""

import requests
from bs4 import BeautifulSoup
import urllib3
import sys
import os
import random
import time

# 忽略SSL警告
urllib3.disable_warnings()

# 尝试导入验证码识别模块
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
    from captcha_solver import CaptchaSolver
    CAPTCHA_SOLVER_AVAILABLE = True
except ImportError:
    CAPTCHA_SOLVER_AVAILABLE = False
    print("[!] 警告: 验证码识别模块未找到，如需处理验证码请安装captcha_solver")


class BUAASSOLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.login_url = "https://sso.buaa.edu.cn/login"
        
        # 设置随机User-Agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def get_execution_token(self):
        """获取登录页面的execution token"""
        try:
            print("[*] 正在获取登录页面及执行令牌...")
            response = self.session.get(self.login_url, verify=False, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            execution_input = soup.find('input', {'name': 'execution'})
            
            if not execution_input:
                print("[-] 未找到execution字段，页面结构可能已改变")
                return None
            
            execution = execution_input.get('value')
            print(f"[+] 成功获取execution token: {execution[:50]}...")
            return execution
            
        except Exception as e:
            print(f"[-] 获取登录页面失败: {e}")
            return None

    def check_captcha_needed(self, response_text):
        """检查是否需要验证码"""
        soup = BeautifulSoup(response_text, 'html.parser')
        captcha_div = soup.find('div', id='captchaParent')
        
        if captcha_div and 'display: none' not in captcha_div.get('style', ''):
            print("[*] 检测到需要验证码")
            return True
        
        # 检查错误信息中是否提示需要验证码
        error_div = soup.find('div', id='errorDiv')
        if error_div:
            error_text = error_div.get_text().lower()
            if 'captcha' in error_text or '验证码' in error_text:
                print("[*] 错误信息提示需要验证码")
                return True
        
        return False

    def get_captcha_image(self, captcha_id):
        """获取验证码图片"""
        try:
            captcha_url = f"https://sso.buaa.edu.cn/captcha?captchaId={captcha_id}&t={int(time.time() * 1000)}"
            print(f"[*] 正在获取验证码图片...")
            
            response = self.session.get(captcha_url, verify=False, timeout=10)
            response.raise_for_status()
            
            return response.content
            
        except Exception as e:
            print(f"[-] 获取验证码图片失败: {e}")
            return None

    def solve_captcha(self, captcha_image_data, max_retries=3):
        """识别验证码"""
        if not CAPTCHA_SOLVER_AVAILABLE:
            print("[-] 验证码识别模块不可用")
            return None
        
        solver = CaptchaSolver()
        
        for attempt in range(max_retries):
            try:
                print(f"[*] 第{attempt + 1}次尝试识别验证码...")
                result = solver.solve_image_captcha(image_data=captcha_image_data)
                
                if result and len(result) > 0:
                    print(f"[+] 验证码识别成功: {result}")
                    return result
                else:
                    print(f"[-] 第{attempt + 1}次识别结果为空")
                    
            except Exception as e:
                print(f"[-] 第{attempt + 1}次识别失败: {e}")
                
            # 如果还有重试机会，重新获取验证码
            if attempt < max_retries - 1:
                print("[*] 重新获取验证码...")
                # 这里需要重新获取验证码图片，但captcha_id可能在之前的响应中
                # 简化处理：直接重试
                time.sleep(1)
        
        print("[-] 验证码识别达到最大重试次数")
        return None

    def do_login(self):
        """执行登录流程"""
        print("=" * 60)
        print("北京航空航天大学统一身份认证系统自动登录")
        print("=" * 60)
        print(f"[*] 用户名: {self.username}")
        print()
        
        # 步骤1: 获取execution token
        execution = self.get_execution_token()
        if not execution:
            return False
        
        # 步骤2: 构造登录数据
        login_data = {
            'username': self.username,
            'password': self.password,
            'type': 'username_password',
            'execution': execution,
            '_eventId': 'submit',
            'submit': 'LOGIN'
        }
        
        # 更新请求头
        self.session.headers.update({
            'Referer': self.login_url,
            'Origin': 'https://sso.buaa.edu.cn',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # 步骤3: 发送登录请求
        print("\n[*] 正在发送登录请求...")
        try:
            response = self.session.post(
                self.login_url,
                data=login_data,
                verify=False,
                allow_redirects=False,  # 不自动跟随重定向
                timeout=10
            )
            
            print(f"[*] 响应状态码: {response.status_code}")
            
            # 步骤4: 判断登录结果
            if response.status_code == 302:
                # 302重定向表示登录成功
                redirect_url = response.headers.get('Location', '')
                print(f"\n[+] 登录成功！")
                print(f"[+] 重定向URL: {redirect_url}")
                
                # 如果需要，可以跟随重定向
                if redirect_url:
                    follow_response = self.session.get(
                        redirect_url,
                        verify=False,
                        timeout=10
                    )
                    print(f"[+] 最终页面标题: {BeautifulSoup(follow_response.text, 'html.parser').title}")
                
                return True
                
            elif response.status_code == 401:
                # 401表示认证失败
                print(f"\n[-] 登录失败: 用户名或密码错误 (HTTP 401)")
                
                # 检查是否需要验证码
                if self.check_captcha_needed(response.text):
                    print("[*] 检测到需要验证码，但当前版本暂不支持自动处理")
                    print("[*] 建议: 稍后重试或使用正确的账号密码")
                
                return False
                
            elif response.status_code == 200:
                # 200可能是登录页面重新加载，显示错误信息
                soup = BeautifulSoup(response.text, 'html.parser')
                error_div = soup.find('div', id='errorDiv')
                
                if error_div:
                    error_msg = error_div.get_text().strip()
                    print(f"\n[-] 登录失败: {error_msg}")
                else:
                    print(f"\n[-] 登录失败: 服务器返回了登录页面")
                
                # 检查是否需要验证码
                if self.check_captcha_needed(response.text):
                    print("[*] 检测到需要验证码")
                    # 这里可以实现验证码处理逻辑
                    # 但由于测试账号会返回401，实际使用时可能需要调整
                
                return False
                
            else:
                print(f"\n[-] 登录异常，返回状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"\n[-] 登录请求出错: {e}")
            return False


def main():
    """主函数"""
    # 使用测试账号
    USERNAME = "testuser123@test.com"
    PASSWORD = "Test123pwd"
    
    print(f"[*] 使用测试账号进行登录尝试...\n")
    
    # 创建登录实例并执行登录
    login_client = BUAASSOLogin(USERNAME, PASSWORD)
    success = login_client.do_login()
    
    print("\n" + "=" * 60)
    if success:
        print("[+] 登录流程完成")
    else:
        print("[-] 登录流程结束（预期失败，因为使用的是测试账号）")
    print("=" * 60)
    
    return success


if __name__ == "__main__":
    main()
