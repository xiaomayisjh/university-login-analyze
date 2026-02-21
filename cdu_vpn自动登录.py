import os
import sys
import requests
import urllib3
import rsa
import hashlib
import xml.etree.ElementTree as ET

# 把captcha_solver加到sys.path中
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha_solver"))
from captcha_solver import CaptchaSolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_rsa_key(session_obj, base_url):
    resp = session_obj.get(f"{base_url}/public/psw_config", timeout=10)
    root = ET.fromstring(resp.text)
    
    rsa_exp_str = root.findtext('RSA_ENCRYPT_EXP', '65537')
    rsa_key_str = root.findtext('RSA_ENCRYPT_KEY')
    csrf_code = root.findtext('CSRF_RAND_CODE', '')
    use_rand_code = root.findtext('USE_RAND_CODE', '0')
    
    return int(rsa_key_str, 16), int(rsa_exp_str), csrf_code, use_rand_code

def solve_captcha(session_obj, base_url):
    print("Capturing captcha image...")
    resp = session_obj.get(f"{base_url}/por/rand_code.csp", timeout=10)
    solver = CaptchaSolver()
    result = solver.solve_image_captcha(image_data=resp.content)
    print(f"Captcha recognized: {result}")
    return result

def login(username, password):
    base_url = "https://vpn.cdu.edu.cn"
    session = requests.Session()
    session.verify = False
    
    # 模拟浏览器行为
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*"
    })
    
    print("1. Initializing session...")
    session.get(f"{base_url}/por/login_psw.csp?tpl=portlogin", timeout=10)
    
    print("2. Fetching encryption configuration...")
    n, e, csrf_code, use_rand_code = get_rsa_key(session, base_url)
    pub_key = rsa.PublicKey(n, e)
    
    # Encrypt password
    plaintext = f"{password}_{csrf_code}".encode('utf-8')
    crypto = rsa.encrypt(plaintext, pub_key)
    encrypted_pw = crypto.hex()
    
    # 对齐加密串长度
    if len(encrypted_pw) < 256 and n.bit_length() <= 1024:
        encrypted_pw = encrypted_pw.zfill(256)
    elif len(encrypted_pw) < 512 and n.bit_length() > 1024:
        encrypted_pw = encrypted_pw.zfill(512)
        
    # 获取并识别验证码
    captcha_text = solve_captcha(session, base_url)
    svpn_rand_code = hashlib.md5(captcha_text.encode('utf-8')).hexdigest()
        
    data = {
        'svpn_name': username,
        'svpn_password': encrypted_pw,
        'svpn_rand_code': svpn_rand_code,
        'svpn_req_randcode': csrf_code
    }
    
    print("3. Sending login request...")
    login_url = f"{base_url}/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1"
    
    session.cookies.set("privacy", "1", domain="vpn.cdu.edu.cn")

    res = session.post(login_url, data=data, timeout=10)
    
    success = False
    msg = ""
    try:
        root = ET.fromstring(res.text)
        result_code = root.findtext('Result', '-1')
        err_msg = root.findtext('Message', '')
        if result_code == '1':
            success = True
            msg = "Login Success!"
        else:
            msg = f"Login Failed! Code: {result_code}, Message: {err_msg}"
    except Exception as e:
        msg = f"Failed to parse response: {res.text}"

    print(msg)
    return success, session

if __name__ == "__main__":
    login("testuser123", "Test123pwd")
