# UniAuth-Analyzer | 高校登录协议分析工具

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/License-Apache%202.0-orange?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Security-Red%20Team-red?style=flat-square" alt="Security">
</p>

## 📖 项目简介

**UniAuth-Analyzer** 是一个专注于中国各大高校统一身份认证（SSO）系统登录协议分析与自动化研究的项目。本项目收录了针对多所知名高校登录逻辑的深度解析脚本，旨在通过技术手段理解现代 Web 安全认证机制。

主要应用场景包括：
- **安全研究**：深入理解 OAuth2, CAS, SAML 等认证协议在实际场景中的落地。
- **CTF 竞赛**：为 CTF 选手提供授权环境下的自动化渗透测试参考。
- **协议审计**：分析登录过程中的加密强度与参数构造安全性。

---

## 🚀 核心功能

- **🎯 多校覆盖**：已完成华中科技大学 (HUST)、清华大学 (THU)、复旦大学 (Fudan)、山东大学 (SDU)、西安交通大学 (XJTU)、四川大学 (SCU) 等多校登录适配。
- **🧩 验证码识别**：共享 `captcha_solver` 全部使用 [AntiCAP API](https://anticap.314521.xyz/docs) 识别文字验证码与滑块双图；保留现有脚本的调用接口。
- **🔐 加密解析**：完整解析登录过程中的 RSA、AES 加密逻辑及动态参数（如 `execution`, `lt` 等）的提取。
- **🖼️ 动图验证码处理**：HUST 验证码逐帧解码、动态干扰抑制、二值化和放大后再交给共享 OCR 服务。
- **🛠️ 模块化架构**：各校脚本解耦，具备高度的可扩展性与独立性。

---

## 📁 目录结构

```text
university-login-analyze/
├── captcha_solver/          # 验证码识别模块
├── hust自动登录.py       # 华中科技大学 CAS 登录协议脚本
├── tsinghua自动登录.py      # 清华大学登录分析脚本
├── fudan_sso自动登录.py     # 复旦大学登录分析脚本
├── sdu自动登录.py           # 山东大学登录分析脚本
├── xjtu自动登录.py          # 西安交通大学登录分析脚本
├── scu自动登录.py           # 四川大学登录分析脚本
├── cdu_vpn自动登录.py       # 成都大学 VPN 登录分析脚本
├── nau自动登录.py           # 南京审计大学登录分析脚本
├── LICENSE                  # Apache 2.0 许可证
└── README.md                # ⚡ 项目导航手册
```

---

## ⚖️ 法律免责声明 (Critical Disclaimer)

> **[重要] 在使用本项目之前，请务必仔细阅读以下条款：**

1.  **授权原则**：本项目及其相关代码**仅供学习、交流目的以及在获得法律书面授权的 CTF 比赛/渗透测试环境中使用**。
2.  **严禁非法**：严禁将本项目中的任何技术、代码或思路用于任何未经授权的入侵、攻击、窃取数据、绕过安全控制或其他非法行为。
3.  **不当使用**：任何因不当使用、非法传播或通过本项目代码导致的法律风险（包括但不限于民事、行政或刑事责任）均由使用者**一人承担**。
4.  **无担保性**：开发者不保证代码的绝对安全性或对未来系统更新的永久兼容性，亦不为使用本代码导致的任何直接或间接损失负责。
5.  **合规合规再合规**：请在操作前确保已阅读并遵守《中华人民共和国网络安全法》及当地相关法律法规。

---

## 🛠️ 快速上手

### 环境准备
安装项目依赖：
```bash
pip install -r requirements.txt
```

### 验证码服务配置
全部验证码识别统一调用 `https://anticap.314521.xyz/api/v1`。组件自动读取**项目根目录**的 `.env`，与运行命令所在目录无关。首次配置可复制 `.env.example`：

```powershell
Copy-Item .env.example .env
```

在 `.env` 中设置：

```dotenv
ANTICAP_API_BASE_URL=https://anticap.314521.xyz
ANTICAP_API_KEY=YOUR_API_KEY
ANTICAP_TIMEOUT=90
```

配置优先级为：构造函数显式参数 > 进程环境变量 > 项目 `.env`。真实密钥仅保存在被 Git 忽略的 `.env`；`.env.example` 只包含占位符。

现有接口保持兼容：
- `from captcha_solver import CaptchaSolver, HybridCaptchaSolver` 与旧的 `captcha_solver.captcha_solver` 导入方式均受支持。
- `solve_image_captcha(image_path=..., image_data=...)` 调用 `POST /api/v1/ocr`，返回去除首尾空白的文字。
- `solve_slide_captcha(...)` 调用 `POST /api/v1/slider/match`，返回 `{"x": x1, "target": [x1, y1, x2, y2]}`。为兼容旧调用，`bg_image_*` 表示**滑块小图（target）**，`slide_image_*` 表示**背景大图（background）**。坐标是输入原图像素，武汉大学脚本的画布缩放逻辑保持不变。
- 上传前会识别图片格式；AntiCAP 不接受但 Pillow 能读取的格式（例如成都大学返回的 GIF）会自动转换为 PNG，并保留首帧和图像尺寸。PNG、JPEG、WEBP、BMP 会直接上传。
- 滑块接口需要双图；仅传 `full_image_data` 会明确报参数错误。单图本身不足以构造该 API 的匹配请求。
- `HybridCaptchaSolver` 保留历史 `primary`、`fallback` 参数，但任何值都只使用 AntiCAP API，不再加载本地 AntiCAP 或其他识别服务。

组件使用 Bearer API Key 鉴权，保留服务端错误代码、HTTP 状态和请求编号。未识别结果和零滑块匹配框会抛出 `CaptchaSolverError`，不会被当成有效验证码，也不会自动回退到旧服务。`solver.last_meta` 可查看最近一次成功响应的版本、设备和请求编号。

### 浏览器用户脚本
`captcha_solver/ocr.js`（文字与滑块）和 `captcha_solver/ocr2.js`（文字与算术）也使用相同的 AntiCAP API。安装后，通过用户脚本管理器提供的 **AntiCAP 密钥配置菜单**输入密钥；密钥存入各脚本独立的 `GM_getValue`/`GM_setValue` 存储，浏览器脚本不读取 Python 的 `.env`，源码也不包含真实密钥。

`ocr2.js` 的自定义网页规则改为用户脚本本地存储，添加、查询与删除规则不再调用旧规则服务器。旧服务器中的规则不会自动复制，可通过原有“添加当前页面规则”菜单重新设置。

### 组件测试
离线回归测试覆盖 OCR、滑块、配置优先级、错误处理及 15 个登录脚本的共同导入，不会发送登录请求：

```bash
python -m unittest discover -s tests -v
```

浏览器用户脚本使用 Node.js 22 的内置测试工具，在模拟的 DOM、网络和用户脚本存储中验证；不依赖浏览器或第三方 Node 包：

```bash
node --test tests/test_captcha_userscripts.cjs
```

使用 `.env` 中的服务和密钥进行联网测试；只上传脚本生成的文字图片与滑块双图：

```bash
python tests/anticap_smoke.py
```

### 运行示例
以清华大学登录分析为例：
```bash
python tsinghua自动登录.py
```

---

## 📜 开源许可证

本项目采用 **[Apache License 2.0](LICENSE)** 协议开源。详细条款请参阅 LICENSE 文件。

---

## 🤝 贡献与反馈

如果你对其他高校的登录协议有独到见解，欢迎提交 Issue 或 Pull Request。在提交前，请确保你的研究行为已获得相关方授权。

---

