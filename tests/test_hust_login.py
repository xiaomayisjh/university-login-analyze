import base64
import json
import unittest
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from hust自动登录 import HUSTLogin, LoginStatus


LOGIN_HTML = """
<html><body>
<form id="loginForm" action="/cas/login" method="post">
  <input type="hidden" name="lt" value="LT-test-token">
  <input type="hidden" name="execution" value="e1s1">
  <input type="hidden" name="_eventId" value="submit">
  <input type="hidden" name="phoneCode" value="">
</form>
</body></html>
"""


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, json_body=None, url="https://pass.hust.edu.cn/cas/login"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._json_body = json_body
        self.url = url
        self.content = text.encode("utf-8")

    def json(self):
        if self._json_body is None:
            raise ValueError("not json")
        return self._json_body


class FakeSession:
    def __init__(self, public_key):
        self.public_key = public_key
        self.headers = {}
        self.cookies = {}
        self.get_calls = []
        self.post_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return FakeResponse(text=LOGIN_HTML, url=url)

    def post(self, url, data=None, **kwargs):
        self.post_calls.append((url, data, kwargs))
        if url.endswith("/rsa"):
            return FakeResponse(json_body={"publicKey": self.public_key}, url=url)
        return FakeResponse(
            status_code=302,
            headers={"Location": "https://portal.example.test/?ticket=ST-123"},
            url=url,
        )


class HUSTLoginTests(unittest.TestCase):
    def test_login_encrypts_credentials_and_submits_dynamic_cas_fields(self):
        private_key = RSA.generate(1024)
        public_key = base64.b64encode(private_key.publickey().export_key(format="DER")).decode("ascii")
        session = FakeSession(public_key)
        client = HUSTLogin(
            "student001",
            "secret-password",
            session=session,
            captcha_code="A7K9",
            user_agent="test-agent",
            visitor_id="visitor-test",
        )

        self.assertTrue(client.login())
        self.assertEqual(client.last_status, LoginStatus.SUCCESS)
        self.assertEqual(session.post_calls[0][0], "https://pass.hust.edu.cn/cas/rsa")

        login_url, data, kwargs = session.post_calls[1]
        self.assertEqual(login_url, "https://pass.hust.edu.cn/cas/login")
        self.assertEqual(data["lt"], "LT-test-token")
        self.assertEqual(data["execution"], "e1s1")
        self.assertEqual(data["code"], "A7K9")
        self.assertEqual(data["ua"], "test-agent")
        self.assertEqual(data["visitorId"], "visitor-test")
        self.assertEqual(data["rsa"], "")
        self.assertFalse(kwargs["allow_redirects"])

        cipher = PKCS1_v1_5.new(private_key)
        self.assertEqual(cipher.decrypt(base64.b64decode(data["ul"]), b""), b"student001")
        self.assertEqual(cipher.decrypt(base64.b64decode(data["pl"]), b""), b"secret-password")

    def test_service_parameter_is_preserved_on_initial_page_and_login(self):
        private_key = RSA.generate(1024)
        public_key = base64.b64encode(private_key.publickey().export_key(format="DER")).decode("ascii")
        session = FakeSession(public_key)
        client = HUSTLogin(
            "student001",
            "secret-password",
            session=session,
            login_url="https://pass.hust.edu.cn/cas/login?service=https%3A%2F%2Fportal.example.test%2Fhome",
            captcha_code="A7K9",
        )

        self.assertTrue(client.login())
        page_url = session.get_calls[0][0]
        self.assertEqual(parse_qs(urlparse(page_url).query)["service"], ["https://portal.example.test/home"])
        login_url = session.post_calls[1][0]
        self.assertEqual(parse_qs(urlparse(login_url).query)["service"], ["https://portal.example.test/home"])


if __name__ == "__main__":
    unittest.main()
