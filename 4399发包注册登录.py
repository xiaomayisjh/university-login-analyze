# -*- coding: utf-8 -*-
"""
4399 发包版自动注册 + 登录脚本（逆向 JS 路线）

核心逆向点：
1) 登录前先调用 `/_c=login&_a=checkUser` 获取动态 key
2) 密码按前端逻辑加密：DES-ECB(key, encodeURIComponent(password))，零填充，输出 0xhex
3) 登录时额外请求 `/webStatic/?_a=getSystime` 作为 systime 参数
4) 注册时同样使用 checkUser 返回 key，加密 login_password/relogin_pwd，并带 encrypt=1 发包
"""

import argparse
import json
import random
import re
import string
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

import requests
from Crypto.Cipher import DES


ROOT = "http://web.4399.com/"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class Account:
    username: str
    password: str
    qq: str
    real_name: str
    id_card: str


class Web4399PacketClient:
    def __init__(self, timeout: int = 12):
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update(
            {
                "User-Agent": UA,
                "Accept": "*/*",
                "Referer": "http://web.4399.com/user/?_a=login",
                "X-Requested-With": "XMLHttpRequest",
            }
        )

    @staticmethod
    def _jsonp_name() -> str:
        return f"jQuery{random.randint(10**16, 10**17-1)}_{int(time.time()*1000)}"

    @staticmethod
    def _ts() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _parse_jsonp(text: str):
        text = text.strip()
        m = re.match(r"^[^(]*\((.*)\)\s*;?\s*$", text, re.S)
        if not m:
            raise ValueError(f"无法解析JSONP: {text[:120]}")
        payload = m.group(1)
        return json.loads(payload)

    @staticmethod
    def _encode_4399(password: str, key: str) -> str:
        # 等价于前端：util.str_to_hex(util.des(key, encodeURIComponent(str), 1, 0))
        # key 长度不足 8 时，按 JS 位运算行为补 \x00
        key_bytes = key.encode("utf-8")[:8].ljust(8, b"\x00")
        msg = quote(password, safe="").encode("utf-8")
        msg += b"\x00" * ((8 - len(msg) % 8) % 8)
        encrypted = DES.new(key_bytes, DES.MODE_ECB).encrypt(msg)
        return "0x" + encrypted.hex()

    def get_check_user(self, username: str) -> dict:
        cb = self._jsonp_name()
        params = {
            "_c": "login",
            "_a": "checkUser",
            "user": username,
            "jsoncallback": cb,
            "_": self._ts(),
        }
        r = self.s.get(ROOT + "user/", params=params, timeout=self.timeout)
        return self._parse_jsonp(r.text)

    def get_systime(self) -> str:
        cb = self._jsonp_name()
        params = {"_a": "getSystime", "jsoncallback": cb, "_": self._ts()}
        r = self.s.get(ROOT + "webStatic/", params=params, timeout=self.timeout)
        data = self._parse_jsonp(r.text)
        if isinstance(data, str):
            return data
        raise ValueError(f"systime 返回异常: {data}")

    def register(self, acc: Account) -> dict:
        # 先用 login.checkUser 取加密 key（前端注册逻辑即如此）
        ck = self.get_check_user(acc.username)
        key = ck.get("data", "") if isinstance(ck, dict) else ""
        if not key:
            return {"ok": False, "step": "check_user", "resp": ck, "msg": "未拿到加密key"}

        enc_pwd = self._encode_4399(acc.password, key)
        cb = self._jsonp_name()
        params = {
            "_c": "reg",
            "jsoncallback": cb,
            "cid": "3000",
            "login_name": acc.username,
            "login_password": enc_pwd,
            "relogin_pwd": enc_pwd,
            "qq": acc.qq,
            "true_name": acc.real_name,
            "sfz": acc.id_card,
            "encrypt": "1",
            "_": self._ts(),
        }

        r = self.s.get(ROOT + "user/", params=params, timeout=self.timeout)
        data = self._parse_jsonp(r.text)
        ok = bool(isinstance(data, dict) and data.get("state") is True)
        return {"ok": ok, "step": "register", "resp": data}

    def login(self, username: str, password: str, code: str = "", auto_login: bool = False) -> dict:
        ck = self.get_check_user(username)
        key = ck.get("data", "") if isinstance(ck, dict) else ""
        if not key:
            return {"ok": False, "step": "check_user", "resp": ck, "msg": "未拿到加密key"}

        systime = self.get_systime()
        enc_pwd = self._encode_4399(password, key)

        cb = self._jsonp_name()
        params = {
            "_c": "login",
            "user": username,
            "pwd": enc_pwd,
            "code": code,
            "jsoncallback": cb,
            "systime": systime,
            "_": self._ts(),
        }
        if auto_login:
            params["autoLogin"] = "on"

        r = self.s.get(ROOT + "user/", params=params, timeout=self.timeout)
        data = self._parse_jsonp(r.text)
        ok = bool(isinstance(data, dict) and data.get("state") is True)
        return {"ok": ok, "step": "login", "resp": data, "enc_pwd": enc_pwd, "systime": systime}


def _id_checksum(id17: str) -> str:
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    mapping = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]
    total = sum(int(a) * b for a, b in zip(id17, weights))
    return mapping[total % 11]


def generate_valid_id_card() -> str:
    area = "110105"
    year = random.randint(1990, 2004)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    birth = f"{year:04d}{month:02d}{day:02d}"
    seq = f"{random.randint(100, 299):03d}"
    id17 = area + birth + seq
    return id17 + _id_checksum(id17)


def random_username(prefix: str = "ctfuser") -> str:
    return prefix + datetime.now().strftime("%m%d%H%M%S") + "".join(random.choices(string.ascii_lowercase + string.digits, k=3))


def random_password() -> str:
    return "T" + "".join(random.choices(string.ascii_letters + string.digits, k=9)) + "@9"


def build_account(args) -> Account:
    username = args.username or random_username(args.prefix)
    password = args.password or random_password()
    qq = args.qq or str(random.randint(10000000, 999999999))
    real_name = args.real_name or "测试用户"
    id_card = args.id_card or generate_valid_id_card()
    return Account(username=username, password=password, qq=qq, real_name=real_name, id_card=id_card)


def parse_args():
    p = argparse.ArgumentParser(description="4399 逆向JS发包自动注册登录脚本")
    p.add_argument("--username", default="", help="指定用户名，不填自动生成")
    p.add_argument("--password", default="", help="指定密码，不填自动生成")
    p.add_argument("--qq", default="", help="QQ号")
    p.add_argument("--real-name", default="", help="实名姓名")
    p.add_argument("--id-card", default="", help="身份证号")
    p.add_argument("--prefix", default="ctfuser", help="自动用户名的前缀")

    p.add_argument("--skip-register", action="store_true", help="跳过注册，直接登录")
    p.add_argument("--code", default="", help="登录验证码（无验证码可留空）")
    p.add_argument("--auto-login", action="store_true", help="登录时带 autoLogin=on")
    p.add_argument("--timeout", type=int, default=12, help="请求超时秒数")
    p.add_argument("--save-account", default="", help="保存账号结果到文件")
    return p.parse_args()


def main():
    args = parse_args()
    acc = build_account(args)

    print("=" * 66)
    print("4399 逆向JS发包脚本")
    print("=" * 66)
    print(f"[*] username: {acc.username}")
    print(f"[*] password: {acc.password}")
    print(f"[*] id_card: {acc.id_card}")

    c = Web4399PacketClient(timeout=args.timeout)

    reg_result = {"ok": True, "step": "register", "resp": {"msg": "skipped"}}
    if not args.skip_register:
        print("[*] 开始注册发包...")
        reg_result = c.register(acc)
        print(f"[+] 注册结果: {reg_result['ok']} | {reg_result.get('resp')}")
    else:
        print("[*] 跳过注册")

    print("[*] 开始登录发包...")
    login_result = c.login(acc.username, acc.password, code=args.code, auto_login=args.auto_login)
    print(f"[+] 登录结果: {login_result['ok']} | {login_result.get('resp')}")

    if args.save_account:
        with open(args.save_account, "w", encoding="utf-8") as f:
            f.write(
                f"username={acc.username}\n"
                f"password={acc.password}\n"
                f"qq={acc.qq}\n"
                f"real_name={acc.real_name}\n"
                f"id_card={acc.id_card}\n"
                f"register_ok={reg_result['ok']}\n"
                f"login_ok={login_result['ok']}\n"
                f"register_resp={json.dumps(reg_result.get('resp', {}), ensure_ascii=False)}\n"
                f"login_resp={json.dumps(login_result.get('resp', {}), ensure_ascii=False)}\n"
            )
        print(f"[+] 结果已保存: {args.save_account}")

    # 返回码：登录成功=0，否则2
    raise SystemExit(0 if login_result["ok"] else 2)


if __name__ == "__main__":
    main()
