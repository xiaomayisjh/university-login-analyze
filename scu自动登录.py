import os
import sys
import re
import hashlib
import requests

# 动态添加 captcha_solver 到系统路径以便于导入验证码识别模块
sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
try:
    from captcha_solver import CaptchaSolver
except ImportError as e:
    print(f"[-] 导入验证码模块失败: {e}")
    sys.exit(1)

def hex_md5_js(s, ver=None):
    """
    还原目标网站 JS 的 md5 逻辑:
    如果 ver 不是 '1.8'，会在字符串末尾拼接一个盐值 '{Urp602019}' 再计算 md5。
    否则直接对原字符串计算 md5。
    """
    if ver == '1.8':
        return hashlib.md5(s.encode('utf-8')).hexdigest()
    else:
        return hashlib.md5((s + '{Urp602019}').encode('utf-8')).hexdigest()

def scu_auto_login(username, password):
    """
    完成四川大学教务系统自动登录流程：
    1. 访问登录主页获取会话级 tokenValue。
    2. 加载图像验证码并利用本地 CaptchaSolver 识别。
    3. Python 还原特定的密码 MD5 拼串逻辑。
    4. 带有必要的参数发起最终的登录请求。
    """
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    })

    login_url = 'http://zhjw.scu.edu.cn/login'
    login_action_url = 'http://zhjw.scu.edu.cn/j_spring_security_check'
    captcha_url = 'http://zhjw.scu.edu.cn/img/captcha.jpg'

    print(f"[*] 正在访问登录页面: {login_url}")
    try:
        r_login_page = session.get(login_url, timeout=10)
    except Exception as e:
        print(f"[-] 访问登录页面失败: {e}")
        return False, session

    # 1. 提取 tokenValue (隐藏域防止重放)
    token_match = re.search(r'name="tokenValue" value="([^"]+)"', r_login_page.text)
    if not token_match:
        print("[-] 无法获取 tokenValue")
        return False, session
        
    token_value = token_match.group(1)
    print(f"[+] 成功获取 tokenValue: {token_value}")

    # 2. 获取验证码图片
    print(f"[*] 正在获取验证码图片...")
    try:
        r_captcha = session.get(captcha_url, timeout=10)
        captcha_image_data = r_captcha.content
    except Exception as e:
        print(f"[-] 获取验证码图片失败: {e}")
        return False, session

    # 使用 captcha_solver 模块识别验证码
    print(f"[*] 正在识别验证码...")
    solver = CaptchaSolver()
    try:
        captcha_text = solver.solve_image_captcha(image_data=captcha_image_data)
        print(f"[+] 验证码识别结果: {captcha_text}")
    except Exception as e:
        print(f"[-] 验证码识别出错: {e}")
        return False, session

    # 3. 处理密码加盐加密逻辑
    # 前端抓得执行逻辑: hex_md5(hex_md5($('#input_password').val()), '1.8') + '*' + hex_md5(hex_md5($('#input_password').val(), '1.8'), '1.8')
    part1 = hex_md5_js(hex_md5_js(password), '1.8')
    part2 = hex_md5_js(hex_md5_js(password, '1.8'), '1.8')
    final_password = f'{part1}*{part2}'

    data = {
        'lang': 'zh',
        'tokenValue': token_value,
        'j_username': username,
        'j_password': final_password,
        'j_captcha': captcha_text
    }

    # 4. 发起登录请求
    print(f"[*] 正在发送登录请求...")
    try:
        # 不自动重定向，通过返回头部中的 Location 检查登录状态
        r_login = session.post(login_action_url, data=data, timeout=10, allow_redirects=False)
        
        if r_login.status_code in [301, 302, 303]:
            redirect_url = r_login.headers.get('Location', '')
            if 'errorCode' in redirect_url or 'login' in redirect_url:
                error_match = re.search(r'errorCode=([^&]+)', redirect_url)
                error_code = error_match.group(1) if error_match else "未知错误"
                print(f"[-] 登录失败，状态码: {error_code} (例如 badCredentials代表账号/密码错误, badCaptcha代表验证码错误)")
                return False, session
            else:
                print(f"[+] 登录成功！网站重定向至: {redirect_url}")
                return True, session
        else:
            if "/logout" in r_login.text or "退出" in r_login.text or "注销" in r_login.text:
                print("[+] 登录成功！页面包含登出相关的标识符。")
                return True, session
            else:
                print("[-] 无法判断是否登录成功。")
                return False, session
                
    except Exception as e:
        print(f"[-] 登录请求出错: {e}")
        return False, session

if __name__ == '__main__':
    username = 'testuser123'
    password = 'Test123pwd'
    print(f"[*] 开始对 '{username}' 进行自动化登录尝试...")
    success, s = scu_auto_login(username, password)
    if success:
        print("[*] 后续可以复用 session 发送其他请求了！")
