import os
import sys
import hashlib
import requests
import json
import urllib3

# 禁用 requests 的不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 动态添加 captcha_solver 到系统路径以便于导入验证码识别模块
sys.path.append(os.path.join(os.path.dirname(__file__), 'captcha_solver'))
try:
    from captcha_solver import CaptchaSolver
except ImportError as e:
    print(f"[-] 导入验证码模块失败: {e}")
    sys.exit(1)

def md5(s):
    """计算字符串的 md5 值"""
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def nau_auto_login(username, password):
    """
    完成南京审计大学教务系统(https://jwc.nau.edu.cn/)自动登录流程：
    1. 访问验证码接口获取验证码图片，并获得ASP.NET_SessionId cookie。
    2. 利用本地 CaptchaSolver 识别验证码。
    3. 根据前端JS逻辑生成加密登录参数(para)。
    4. 发送登录POST请求并解析返回结果。
    """
    session = requests.Session()
    # 根据分析，请求需要加上常见的 Header 防护
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://jwc.nau.edu.cn',
        'Referer': 'https://jwc.nau.edu.cn/'
    })

    main_url = 'https://jwc.nau.edu.cn/'
    login_action_url = 'https://jwc.nau.edu.cn/NauEventHandle.ashx?class=LoginHandle&meth=DoLogin'
    captcha_url = 'https://jwc.nau.edu.cn/NauEventHandle.ashx?class=CheckCodeHandle&meth=CreateCheckCodeImage'

    # 1. 初始化访问以建立会话(可选，但推荐)
    print(f"[*] 正在访问主页: {main_url}")
    try:
        session.get(main_url, verify=False, timeout=10)
    except Exception as e:
        print(f"[-] 访问主页失败: {e}")
        return False, session

    # 2. 获取验证码图片
    print(f"[*] 正在获取验证码图片...")
    import random
    import time
    # 模拟前端添加随机数防缓存
    r_val = random.random()
    current_time = int(time.time() * 1000)
    full_captcha_url = f"{captcha_url}&r={r_val}&_={current_time}"
    
    try:
        r_captcha = session.get(full_captcha_url, verify=False, timeout=10)
        captcha_image_data = r_captcha.content
        if not captcha_image_data:
            print("[-] 获取到的验证码图片数据为空")
            return False, session
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

    # 3. 构造请求参数 para
    # JS 逻辑: username;md5(password);captcha;md5(username + password + captcha);term_id
    # term_id在页面代码中可能是动态的或者写死的学期号，在当前分析中为 "202520261"
    # 我们也可以将其写死或者通过抓取主页获取，这里先写死为 "202520261"
    term_id = "202520261"
    
    md5_pwd = md5(password)
    md5_combined = md5(username + password + captcha_text)
    
    para = f"{username};{md5_pwd};{captcha_text};{md5_combined};{term_id}"
    
    data = {
        'para': para
    }

    # 4. 发起登录请求
    print(f"[*] 正在发送登录请求...")
    try:
        r_login = session.post(login_action_url, data=data, verify=False, timeout=10)
        
        if r_login.status_code == 200:
            try:
                result = r_login.json()
                if result.get("Success") == "1":
                    print(f"[+] 登录成功！服务器返回消息: {result.get('Message', '无')}, 后续可能的跳转路径: {result.get('RedirectPath', '')}")
                    return True, session
                else:
                    print(f"[-] 登录失败，服务器返回消息: {result.get('Message', '未知原因')}")
                    return False, session
            except json.JSONDecodeError:
                print(f"[-] 解析返回数据失败，返回内容为: {r_login.text}")
                return False, session
        else:
            print(f"[-] 登录请求返回状态码错误: {r_login.status_code}")
            return False, session
                
    except Exception as e:
        print(f"[-] 登录请求出错: {e}")
        return False, session

if __name__ == '__main__':
    username = 'testuser123'
    password = 'Test123pwd'
    print(f"[*] 开始对 '{username}' 进行自动化登录尝试(南京审计大学教务系统)...")
    success, s = nau_auto_login(username, password)
    if success:
        print("[*] 后续可以复用 session 发送其他请求了！")
