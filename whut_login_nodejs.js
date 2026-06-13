const JSEncrypt = require('jsencrypt');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// 创建axios实例
const client = axios.create({
    baseURL: 'https://zhlgd.whut.edu.cn',
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    },
    maxRedirects: 0,
    validateStatus: function (status) {
        return status < 400; // 接受所有小于400的状态码
    }
});

async function login(username, password) {
    console.log('开始登录流程...');
    
    try {
        // 步骤1: 获取登录页面
        console.log('步骤1: 获取登录页面...');
        const loginPageResponse = await client.get('/tpass/login');
        const html = loginPageResponse.data;
        
        // 提取隐藏字段
        const ltMatch = html.match(/name="lt"[^>]*value="([^"]*)"/);
        const lt = ltMatch ? ltMatch[1] : '';
        
        const executionMatch = html.match(/name="execution"[^>]*value="([^"]*)"/);
        const execution = executionMatch ? executionMatch[1] : '';
        
        const serviceIdMatch = html.match(/id="service_id"[^>]*value="([^"]*)"/);
        const serviceId = serviceIdMatch ? serviceIdMatch[1] : '';
        
        console.log(`LT: ${lt}`);
        console.log(`Execution: ${execution}`);
        
        // 步骤2: 获取RSA公钥
        console.log('步骤2: 获取RSA公钥...');
        const rsaResponse = await client.post('/tpass/rsa?skipWechat=true', null, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json, text/javascript, */*; q=0.01',
            }
        });
        
        const publicKey = rsaResponse.data.publicKey;
        console.log(`公钥: ${publicKey}`);
        
        // 步骤3: 使用JSEncrypt加密
        console.log('步骤3: 加密用户名和密码...');
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        
        const encryptedUsername = encrypt.encrypt(username);
        const encryptedPassword = encrypt.encrypt(password);
        
        console.log(`加密后用户名长度: ${encryptedUsername.length}`);
        console.log(`加密后密码长度: ${encryptedPassword.length}`);
        
        // 步骤4: 构建登录数据
        console.log('步骤4: 提交登录请求...');
        const loginData = new URLSearchParams({
            un: username,
            pd: password,
            ul: encryptedUsername,
            pl: encryptedPassword,
            lt: lt,
            execution: execution,
            _eventId: 'submit',
            rsa: '',
            ua: client.defaults.headers['User-Agent'],
            visitorId: generateVisitorId(),
        });
        
        if (serviceId) {
            loginData.append('service_id', serviceId);
        }
        
        // 步骤5: 发送登录请求
        const loginResponse = await client.post('/tpass/login', loginData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'https://zhlgd.whut.edu.cn/tpass/login',
                'Origin': 'https://zhlgd.whut.edu.cn',
            },
            maxRedirects: 0,
            validateStatus: function (status) {
                return true; // 接受所有状态码
            }
        });
        
        console.log(`响应状态码: ${loginResponse.status}`);
        
        // 检查是否重定向（登录成功）
        if (loginResponse.status === 302 || loginResponse.status === 301) {
            const redirectUrl = loginResponse.headers.location;
            console.log('✓ 登录成功！');
            console.log(`重定向URL: ${redirectUrl}`);
            
            return {
                success: true,
                redirectUrl: redirectUrl
            };
        } else {
            // 检查错误信息
            const responseHtml = loginResponse.data;
            const errorMatch = responseHtml.match(/id="errormsg"[^>]*>([^<]*)</);
            
            if (errorMatch) {
                console.log(`✗ 登录失败: ${errorMatch[1]}`);
            } else {
                console.log(`✗ 登录失败，状态码: ${loginResponse.status}`);
                console.log(`响应内容前500字符: ${responseHtml.substring(0, 500)}`);
            }
            
            return {
                success: false,
                error: errorMatch ? errorMatch[1] : 'Unknown error'
            };
        }
        
    } catch (error) {
        console.error('✗ 登录过程出错:', error.message);
        if (error.response) {
            console.error('响应状态:', error.response.status);
            console.error('响应数据:', error.response.data);
        }
        return {
            success: false,
            error: error.message
        };
    }
}

function generateVisitorId() {
    const crypto = require('crypto');
    const data = `${Date.now()}_${Math.random()}`;
    return crypto.createHash('md5').update(data).digest('hex');
}

// 主函数
if (require.main === module) {
    const username = process.argv[2] || 'testuser123@test.com';
    const password = process.argv[3] || 'Test123pwd';
    
    console.log('='.repeat(60));
    console.log('武汉理工大学智慧理工大自动登录脚本');
    console.log('='.repeat(60));
    console.log(`用户名: ${username}`);
    console.log('');
    
    login(username, password).then(result => {
        console.log('');
        console.log('='.repeat(60));
        if (result.success) {
            console.log('登录完成！');
        } else {
            console.log('登录失败，请检查账号密码或网络连接');
        }
        console.log('='.repeat(60));
        
        // 输出JSON结果供Python解析
        console.log('\nRESULT_JSON:');
        console.log(JSON.stringify(result));
    });
}

module.exports = { login };
