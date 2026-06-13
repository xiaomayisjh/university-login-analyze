#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
武汉理工大学智慧理工大自动登录脚本
通过调用Node.js实现完整的RSA加密和登录流程
"""

import subprocess
import json
import sys
import os


def login(username, password):
    """
    执行武汉理工大学智慧理工大登录
    
    Args:
        username: 用户名
        password: 密码
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # 获取脚本路径
        script_path = os.path.join(os.path.dirname(__file__), 'whut_login_nodejs.js')
        
        if not os.path.exists(script_path):
            return False, "Node.js登录脚本不存在"
        
        # 调用Node.js脚本
        result = subprocess.run(
            ['node', script_path, username, password],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8'
        )
        
        # 获取输出
        output = result.stdout
        
        # 解析JSON结果
        json_marker = 'RESULT_JSON:'
        if json_marker in output:
            json_part = output.split(json_marker)[1].strip()
            result_data = json.loads(json_part)
            
            if result_data.get('success'):
                return True, f"登录成功！重定向URL: {result_data.get('redirectUrl', '')}"
            else:
                error = result_data.get('error', '未知错误')
                return False, f"登录失败: {error}"
        else:
            # 如果没有JSON标记，返回完整输出
            return False, output
            
    except subprocess.TimeoutExpired:
        return False, "登录超时"
    except FileNotFoundError:
        return False, "未找到Node.js，请确保已安装Node.js"
    except Exception as e:
        return False, f"登录过程出错: {str(e)}"


def main():
    """主函数"""
    print("=" * 60)
    print("武汉理工大学智慧理工大自动登录脚本")
    print("=" * 60)
    
    # 测试账号
    username = "testuser123@test.com"
    password = "Test123pwd"
    
    print(f"用户名: {username}")
    print()
    
    # 执行登录
    success, message = login(username, password)
    
    print()
    print("=" * 60)
    if success:
        print("✓ 登录完成！")
    else:
        print("✗ 登录失败")
    print("=" * 60)
    print()
    print(message)


if __name__ == "__main__":
    main()
