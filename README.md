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

- **🎯 多校覆盖**：已完成清华大学 (THU)、复旦大学 (Fudan)、山东大学 (SDU)、西安交通大学 (XJTU)、四川大学 (SCU) 等多校登录适配。
- **🧩 验证码识别**：内置 `captcha_solver` 支持，实现图形验证码的自动获取与识别。
- **🔐 加密解析**：完整解析登录过程中的 RSA、AES 加密逻辑及动态参数（如 `execution`, `lt` 等）的提取。
- **🛠️ 模块化架构**：各校脚本解耦，具备高度的可扩展性与独立性。

---

## 📁 目录结构

```text
university-login-analyze/
├── captcha_solver/          # 验证码识别模块
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
确保已安装 Python 3.8+ 并安装相关依赖：
```bash
pip install requests beautifulsoup4 pycryptodome
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

