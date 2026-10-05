"""Check that login scripts share one importable captcha package."""

from pathlib import Path
import subprocess
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class LoginCaptchaImportTests(unittest.TestCase):
    def test_all_login_scripts_can_import_together_without_shadowing_package(self):
        # BUAA previously inserted captcha_solver/ before the package root and
        # loaded captcha_solver.py as a flat module, breaking subsequent imports.
        code = r'''
import importlib
import sys
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
script_names = [
    "buaa自动登录", "nwpu自动登录", "bnu自动登录", "tsinghua自动登录",
    "xjtu自动登录", "fudan_sso自动登录", "whu自动登录", "scu自动登录",
    "cdu_vpn自动登录", "zju_webvpn自动登录", "pku自动登录", "nju自动登录",
    "bit自动登录", "hit邮箱自动登录", "nau自动登录",
]
with patch("requests.sessions.Session.request", side_effect=AssertionError("Network request during import")):
    for name in script_names:
        script = importlib.import_module(name)
        package = importlib.import_module("captcha_solver")
        assert hasattr(package, "__path__"), name + " shadowed the captcha_solver package"
        canonical = importlib.import_module("captcha_solver.captcha_solver")
        solver_name = "HybridCaptchaSolver" if name in ("nju自动登录", "bit自动登录") else "CaptchaSolver"
        assert getattr(script, solver_name) is getattr(canonical, solver_name), name + " uses a different solver"
print("Imported all 15 captcha-using login scripts without network requests")
'''
        process = subprocess.run(
            [sys.executable, "-c", code, str(PROJECT_ROOT)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("Imported all 15", process.stdout)


if __name__ == "__main__":
    unittest.main()
