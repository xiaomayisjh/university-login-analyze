// ==UserScript==
// @name         验证码
// @namespace    http://tampermonkey.net/
// @version      0.6.0
// @description  AntiCAP 数英及算术验证码识别，页面规则保存在本地
// @author       lcymzzZ
// @license      GPL Licence
// @connect      anticap.314521.xyz
// @connect      *
// @match        http://*/*
// @match        https://*/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// ==/UserScript==

(function() {
    'use strict';

    var element, input, imgIndex, canvasIndex, inputIndex, captchaType;
    var localRules = null;
    const ANTICAP_API_BASE = 'https://anticap.314521.xyz/api/v1';
    const RULE_STORAGE_KEY = 'ANTICAP_LOCAL_RULES';

    // 每份用户脚本独立安装，不从网页 DOM/localStorage 获取密钥。
    function requestAntiCAP(endpoint, payload) {
        const key = String(GM_getValue('ANTICAP_API_KEY', '') || '').trim();
        if (!key) return Promise.reject(new Error('请通过脚本菜单配置 AntiCAP API 密钥'));
        const redact = value => String(value || '').split(key).join('[redacted]').slice(0, 300);
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'POST',
                url: ANTICAP_API_BASE + endpoint,
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
                data: JSON.stringify(payload),
                responseType: 'json',
                timeout: 15000,
                onload(response) {
                    let body;
                    try {
                        body = response.response && typeof response.response === 'object'
                            ? response.response : JSON.parse(response.responseText);
                    } catch (_) {
                        reject(new Error('AntiCAP 返回非 JSON 数据 (HTTP ' + response.status + ')'));
                        return;
                    }
                    if (!(response.status >= 200 && response.status < 300)) {
                        const error = body && body.error || {};
                        reject(new Error('AntiCAP HTTP ' + response.status + ' ' + redact(error.code) +
                            ': ' + redact(error.message) + ' request_id=' + redact(body && body.request_id)));
                        return;
                    }
                    if (endpoint === '/math') {
                        if (!body || typeof body !== 'object') {
                            reject(new Error('AntiCAP /math 响应不是对象')); return;
                        }
                        if (body.result === null) { resolve(null); return; }
                        if (typeof body.result !== 'number' || !Number.isFinite(body.result)) {
                            reject(new Error('AntiCAP /math 响应 result 不是数字')); return;
                        }
                        resolve(body.result);
                        return;
                    }
                    if (!body.meta || !['ok', 'no_match'].includes(body.meta.status)) {
                        reject(new Error('AntiCAP 响应缺少有效 meta.status'));
                        return;
                    }
                    resolve(body.meta.status === 'no_match' || body.result == null ? null : body.result);
                },
                onerror() { reject(new Error('AntiCAP 网络请求失败')); },
                ontimeout() { reject(new Error('AntiCAP 请求超时')); },
                onabort() { reject(new Error('AntiCAP 请求已取消')); }
            });
        });
    }

    function ruleUrl(url) {
        return String(url).split(/[?#]/)[0];
    }

    function readRuleDictionary() {
        const rules = GM_getValue(RULE_STORAGE_KEY, {});
        return rules && typeof rules === 'object' && !Array.isArray(rules) ? { ...rules } : {};
    }
    var exist = false;
    var iscors = false;
    var inBlack = false;
    var firstin = true;
    
    var fisrtUse = GM_getValue("fisrtUse", true);
    if (fisrtUse) {
        var mzsm = prompt("自动识别填充网页验证码\n首次使用，请阅读并同意以下免责条款。\n\n \
1. 此脚本仅用于学习研究，您必须在下载后24小时内将所有内容从您的计算机或手机或任何存储设备中完全删除，若违反规定引起任何事件本人对此均不负责。\n \
2. 请勿将此脚本用于任何商业或非法目的，若违反规定请自行对此负责。\n \
3. 本人对此脚本引发的问题概不负责，包括但不限于由脚本错误引起的任何损失和损害。\n \
4. 任何以任何方式查看此脚本的人或直接或间接使用此脚本的使用者都应仔细阅读此条款。\n \
5. 本人保留随时更改或补充此条款的权利，一旦您使用或复制了此脚本，即视为您已接受此免责条款。\n\n \
若您同意以上内容，请输入“我已阅读并同意以上内容” 然后开始使用。", "");
        if (mzsm == "我已阅读并同意以上内容") {
            GM_setValue("fisrtUse", false);
        }
        else {
            alert("免责条款未同意，脚本停止运行。\n若不想使用，请自行禁用脚本，以免每个页面都弹出该提示。");
            return;
        }
    }

    //添加菜单
    GM_registerMenuCommand('添加当前页面规则', addRule);
    GM_registerMenuCommand('清除当前页面规则', delRule);
    GM_registerMenuCommand('管理网页黑名单', manageBlackList);
    GM_registerMenuCommand('配置 AntiCAP API 密钥', configureAntiCAPKey);
    GM_registerMenuCommand('交流/反馈群：764904163', ()=>{window.open("https://jq.qq.com/?_wv=1027&k=9OATqk9I")});

    GM_setValue("preCode", "");

    function configureAntiCAPKey() {
        const key = prompt('配置 AntiCAP API 密钥（留空可清除）', '');
        if (key === null) return;
        GM_setValue('ANTICAP_API_KEY', key.trim());
        GM_setValue('preCode', '');
        firstin = true;
        alert('AntiCAP 密钥配置已保存，请刷新页面或验证码后重试');
    }

    //判断是否为验证码（预设规则）
    function isCode(){
        if (element.height >= 100 || element.height == element.width)
            return false;
        var attrList = ["id", "title", "alt", "name", "className", "src"];
        var strList = ["code", "Code", "CODE", "captcha", "Captcha", "CAPTCHA", "yzm", "Yzm", "YZM", "check", "Check", "CHECK", "random", "Random", "RANDOM", "veri", "Veri", "VERI", "验证码", "看不清", "换一张"];
        for (var i = 0; i < attrList.length; i++) {
            for (var j = 0; j < strList.length; j++) {
                // var str = "element." + attrList[i];
                var attr = element[attrList[i]];
                if (attr.indexOf(strList[j]) != -1) {
                    return true;
                }
            }
        }
        return false;
    }

    //判断是否为验证码输入框（预设规则）
    function isInput(){
        var attrList = ["placeholder", "alt", "title", "id", "className", "name"];
        var strList = ["code", "Code", "CODE", "captcha", "Captcha", "CAPTCHA", "yzm", "Yzm", "YZM", "check", "Check", "CHECK", "random", "Random", "RANDOM", "veri", "Veri", "VERI", "验证码", "看不清", "换一张"];
        for (var i = 0; i < attrList.length; i++) {
            for (var j = 0; j < strList.length; j++) {
                // var str = "input." + attrList[i];
                var attr = input[attrList[i]];
                if (attr.indexOf(strList[j]) != -1) {
                    // console.log(attr);
                    return true;
                }
            }
        }
        return false;
    }

    //手动添加规则（操作）
    function addRule(){
        var ruleData = {"url": window.location.href.split("?")[0], "img": "", "input": "", "inputType": "", "type": "", "captchaType": ""};
        //检测鼠标右键点击事件
        topNotice("请在验证码图片上点击鼠标 “右”👉 键");
        document.oncontextmenu = function(e){
            e = e || window.event;
            e.preventDefault();

            if (e.target.tagName == "IMG" || e.target.tagName == "GIF") {
                var imgList = document.getElementsByTagName('img');
                for (var i = 0; i < imgList.length; i++) {
                    if (imgList[i] == e.target) {
                        var k = i;
                        ruleData.type = "img";
                    }
                }
            }
            else if (e.target.tagName == "CANVAS") {
                var imgList = document.getElementsByTagName('canvas');
                for (var i = 0; i < imgList.length; i++) {
                    if (imgList[i] == e.target) {
                        var k = i;
                        ruleData.type = "canvas";
                    }
                }
            }
            if (k == null) {
                topNotice("选择有误，请重新点击验证码图片");
                return;
            }
            ruleData.img = k;
            topNotice("请在验证码输入框上点击鼠标 “左”👈 键");
            document.onclick = function(e){
                e = e || window.event;
                e.preventDefault();
                var inputList = document.getElementsByTagName('input');
                var textareaList = document.getElementsByTagName('textarea');
                // console.log(inputList);
                if (e.target.tagName == "INPUT") {
                    ruleData.inputType = "input";
                    for (var i = 0; i < inputList.length; i++) {
                        if (inputList[i] == e.target) {
                            if (inputList[0] && (inputList[0].id == "_w_simile" || inputList[0].id == "black_node")) {
                                var k = i - 1;
                            }
                            else {
                                var k = i;
                            }
                        }
                    }
                }
                else if (e.target.tagName == "TEXTAREA") {
                    ruleData.inputType = "textarea";
                    for (var i = 0; i < textareaList.length; i++) {
                        if (textareaList[i] == e.target) {
                            var k = i;
                        }
                    }
                }
                if (k == null) {
                    topNotice("选择有误，请重新点击验证码输入框");
                    return;
                }
                ruleData.input = k;
                var r = confirm("选择验证码类型\n\n数/英验证码请点击“确定”，算术验证码请点击“取消”");
                if (r == true) {
                    ruleData.captchaType = "general";
                }
                else {
                    ruleData.captchaType = "math";
                }
                addR(ruleData).then((res)=>{
                    if (res.status == 200){
                        topNotice("添加规则成功");
                        document.oncontextmenu = null;
                        document.onclick = null;
                        start();
                    }
                    else {
                        topNotice("Error，添加规则失败");
                        document.oncontextmenu = null;
                        document.onclick = null;
                    }
                });
            }
        }
    }

    // 页面规则仅保存在用户脚本 GM 字典中，新 API 没有规则接口。
    function addR(ruleData) {
        const rules = readRuleDictionary();
        const url = ruleUrl(ruleData.url);
        rules[url] = { ...ruleData, url };
        GM_setValue(RULE_STORAGE_KEY, rules);
        GM_setValue('preCode', '');
        firstin = true;
        return Promise.resolve({ status: 200 });
    }

    //删除当前页面规则
    function delRule(){
        var ruleData = {"url": window.location.href.split("?")[0]}
        delR(ruleData).then((res)=>{
            if (res.status == 200)
                topNotice("删除规则成功");
            else
                topNotice("Error，删除规则失败");
        });
    }

    // 删除本地页面规则，其他页面的规则保持不变。
    function delR(ruleData) {
        const rules = readRuleDictionary();
        const url = ruleUrl(ruleData.url);
        delete rules[url];
        GM_setValue(RULE_STORAGE_KEY, rules);
        if (url === ruleUrl(window.location.href)) {
            localRules = null;
            exist = false;
            captchaType = null;
            firstin = true;
            GM_setValue('preCode', '');
        }
        return Promise.resolve({ status: 200 });
    }

    //按已存规则填充
    function codeByRule(){
        var code = "";
        var src = element.src;
        if (firstin){
            firstin = false;
            if (src.indexOf('data:image') != -1) {
                // console.log(src);
                code = src.split("base64,")[1];
                GM_setValue("tempCode", code);
                    if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                        // console.log("preCode:" + GM_getValue("preCode"))
                        // console.log("tempCode:" + GM_getValue("tempCode"))
                        GM_setValue("preCode", GM_getValue("tempCode"));
                        p1(code).then((ans) => {
                            if (ans !== null && ans !== undefined && ans !== '')
                                writeIn1(ans);
                            else
                                codeByRule();
                        });
                    }
            }
            else if (src.indexOf('blob') != -1) {
                const image = new Image()
                image.src = src;
                image.onload = () => {
                    const canvas = document.createElement('canvas')
                    canvas.width = image.width
                    canvas.height = image.height
                    const context = canvas.getContext('2d')
                    context.drawImage(image, 0, 0, image.width, image.height);
                    code = canvas.toDataURL().split("base64,")[1];
                    GM_setValue("tempCode", code);
                    if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                        GM_setValue("preCode", GM_getValue("tempCode"));
                        p1(code).then((ans) => {
                            if (ans !== null && ans !== undefined && ans !== '')
                                writeIn1(ans);
                            else
                                codeByRule();
                        });
                    }
                }
            }
            else {
                try {
                    var img = element;
                    if (img.src && img.width != 0 && img.height != 0) {
                        var canvas = document.createElement("canvas");
                        var ctx = canvas.getContext("2d");
                        canvas.width = img.width;
                        canvas.height = img.height;
                        ctx.drawImage(img, 0, 0, img.width, img.height);
                        code = canvas.toDataURL("image/png").split("base64,")[1];
                        GM_setValue("tempCode", code);
                        if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                            // console.log("preCode:" + GM_getValue("preCode"))
                            // console.log("tempCode:" + GM_getValue("tempCode"))
                            GM_setValue("preCode", GM_getValue("tempCode"));
                            p1(code).then((ans) => {
                                if (ans !== null && ans !== undefined && ans !== '')
                                    writeIn1(ans);
                                else
                                    codeByRule();
                            });
                        }
                    }
                    else {
                        codeByRule();
                    }
                }
                catch(err){
                    return;
                }
            }
        }
        else {
            if (src.indexOf('data:image') != -1) {
                // console.log(src);
                code = src.split("base64,")[1];
                GM_setValue("tempCode", code);
                if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                    // console.log("preCode:" + GM_getValue("preCode"))
                    // console.log("tempCode:" + GM_getValue("tempCode"))
                    GM_setValue("preCode", GM_getValue("tempCode"));
                    p1(code).then((ans) => {
                        writeIn1(ans);
                    });
                }
            }
            else if (src.indexOf('blob') != -1) {
                const image = new Image() 
				image.src = src;
				image.onload = () => {
					const canvas = document.createElement('canvas')
					canvas.width = image.width
					canvas.height = image.height
					const context = canvas.getContext('2d')
					context.drawImage(image, 0, 0, image.width, image.height);
					code = canvas.toDataURL().split("base64,")[1];
                    GM_setValue("tempCode", code);
                    if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                        GM_setValue("preCode", GM_getValue("tempCode"));
                        p1(code).then((ans) => {
                            writeIn1(ans);
                        })
                    }
                }
            }
            else {
                var canvas = document.createElement("canvas");
                var ctx = canvas.getContext("2d");
                element.onload = function() {
                    // console.log("img.onload");
                    canvas.width = element.width;
                    canvas.height = element.height;
                    ctx.drawImage(element, 0, 0, element.width, element.height);
                    code = canvas.toDataURL("image/png").split("base64,")[1];
                    GM_setValue("tempCode", code);
                    if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                        // console.log("preCode:" + GM_getValue("preCode"))
                        // console.log("tempCode:" + GM_getValue("tempCode"))
                        GM_setValue("preCode", GM_getValue("tempCode"));
                        p1(code).then((ans) => {
                            writeIn1(ans);
                        });
                    }
                }
            }
        }
    }

    function canvasRule(){
        setTimeout(function(){
            // console.log(element.toDataURL("image/png"));
            try {
                var code = element.toDataURL("image/png").split("base64,")[1];
                GM_setValue("tempCode", code);
                if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                    // console.log("preCode:" + GM_getValue("preCode"))
                    // console.log("tempCode:" + GM_getValue("tempCode"))
                    GM_setValue("preCode", GM_getValue("tempCode"));
                    p1(code).then((ans) => {
                        writeIn1(ans);
                    });
                }
            }
            catch(err){
                canvasRule();
            }
        }, 100);
    }

    //寻找网页中的验证码
    function findCode(k){
        var code = '';
        var codeList = document.getElementsByTagName('img');
        // console.log(codeList);
        for (var i = k; i < codeList.length; i++) {
            var src = codeList[i].src;
            element = codeList[i];
            if (src.indexOf('data:image') != -1) {
                if (isCode()) {
                    firstin = false;
                    code = src.split("base64,")[1];
                    // console.log('code: ' + code);
                    GM_setValue("tempCode", code);
                    if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                        // console.log("preCode:" + GM_getValue("preCode"))
                        // console.log("tempCode:" + GM_getValue("tempCode"))
                        GM_setValue("preCode", GM_getValue("tempCode"));
                        p(code, i).then((ans) => {
                            writeIn(ans);
                        });
                    }
                    break;
                }
            }
            else {
                if (isCode()) {
                    if (firstin){
                        firstin = false;
                        var img = element;
                        if (img.src && img.width != 0 && img.height != 0) {
                            var canvas = document.createElement("canvas");
                            var ctx = canvas.getContext("2d");
                            canvas.width = img.width;
                            canvas.height = img.height;
                            ctx.drawImage(img, 0, 0, img.width, img.height);
                            code = canvas.toDataURL("image/png").split("base64,")[1];
                            try{
                                code = canvas.toDataURL("image/png").split("base64,")[1];
                            }
                            catch(err){
                                //console.log(err);
                                findCode(i + 1);
                                return;
                            }
                            // console.log(code);
                            GM_setValue("tempCode", code);
                            if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                                iscors = isCORS();
                                // console.log("preCode:" + GM_getValue("preCode"))
                                // console.log("tempCode:" + GM_getValue("tempCode"))
                                GM_setValue("preCode", GM_getValue("tempCode"));
                                p(code, i).then((ans) => {
                                    if (ans !== null && ans !== undefined && ans !== '')
                                        writeIn(ans);
                                    else
                                        findCode(i);
                                });
                                return;
                            }
                        }
                        else{
                            findCode(i);
                            return;
                        }
                    }
                    else {
                        var canvas = document.createElement("canvas");
                        var ctx = canvas.getContext("2d");
                        element.onload = function(){
                            canvas.width = element.width;
                            canvas.height = element.height;
                            ctx.drawImage(element, 0, 0, element.width, element.height);
                            try{
                                code = canvas.toDataURL("image/png").split("base64,")[1];
                            }
                            catch(err){
                                //console.log(err);
                                findCode(i + 1);
                                return;
                            }
                            // console.log(code);
                            GM_setValue("tempCode", code);
                            if (GM_getValue("tempCode") != GM_getValue("preCode")) {
                                iscors = isCORS();
                                // console.log("preCode:" + GM_getValue("preCode"))
                                // console.log("tempCode:" + GM_getValue("tempCode"))
                                GM_setValue("preCode", GM_getValue("tempCode"));
                                p(code, i).then((ans) => {
                                    writeIn(ans);
                                });
                                return;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    //寻找网页中的验证码输入框
    function findInput(){
        var inputList = document.getElementsByTagName('input');
        // console.log(inputList);
        for (var i = 0; i < inputList.length; i++) {
            input = inputList[i];
            if (isInput()) {
                return true;
            }
        }
    }

    function writeIn(ans){
        if (findInput() && ans !== null && ans !== undefined && ans !== '') {
            ans = String(ans).replace(/\s+/g, '');
            input.value = ans;
            if (typeof InputEvent !== 'undefined') input.dispatchEvent(new InputEvent('input', { bubbles: true }));
            ['input', 'change', 'focus', 'keypress', 'keyup', 'keydown', 'select'].forEach(eventName => fire(input, eventName));
            input.value = ans;
        }
    }

    function p(code, i){
        return requestAntiCAP('/ocr', { img_base64: String(code) }).then(result => {
            if (typeof result !== 'string' || !result.trim()) return null;
            console.log('识别结果已收到');
            return result;
        }).catch(error => {
            console.log('AntiCAP OCR 识别失败:', error.message);
            return null;
        });
    }

    // 识别验证码（自定义规则）；0 是有效的算术结果，不能用 truthiness 判断。
    function p1(code){
        const endpoint = captchaType === 'math' ? '/math' : '/ocr';
        return requestAntiCAP(endpoint, { img_base64: String(code) }).then(result => {
            if (captchaType === 'math') {
                if (typeof result !== 'number' || !Number.isFinite(result)) return null;
                console.log('算术识别结果已收到');
                return result;
            }
            if (typeof result !== 'string' || !result.trim()) return null;
            console.log('识别结果已收到');
            return result;
        }).catch(error => {
            console.log('AntiCAP 识别失败:', error.message);
            return null;
        });
    }

    //判断是否跨域
    function isCORS(){
        try {
            if (element.src.indexOf('http') != -1 || element.src.indexOf('https') != -1) {
                if (element.src.indexOf(window.location.host) == -1) {
                    console.log("检测到当前页面存在跨域问题");
                    return true;
                }
                //console.log("当前页面不存在跨域问题");
                return false;
            }
        }
        catch(err){
            return;
        }
    }

    //将url转换为base64（解决跨域问题）
    function p2(){
        return new Promise((resolve, reject) =>{
            GM_xmlhttpRequest({
                url: element.src,
                method: "GET",
                headers: {'Content-Type': 'application/json; charset=utf-8','path' : window.location.href},
                responseType: "blob",
                onload: function(response) {
                    // console.log(response);
                    let blob = response.response;
                    let reader = new FileReader();
                    reader.onloadend = (e) => {
                        let data = e.target.result;
                        element.src = data;
                        return resolve(data);
                    }
                    reader.readAsDataURL(blob);
                }
            });
        });
    }

    //此段逻辑借鉴Crab大佬的代码，十分感谢
    function fire(element,eventName){
        var event = document.createEvent("HTMLEvents");
        event.initEvent(eventName, true, true);
        element.dispatchEvent(event);
    }
    function FireForReact(element, eventName) {
        try {
            let env = new Event(eventName);
            element.dispatchEvent(env);
            var funName = Object.keys(element).find(p => Object.keys(element[p]).find(f => f.toLowerCase().endsWith(eventName)));
            if (funName != undefined) {
                element[funName].onChange(env)
            }
        }
        catch (e) {}
    }

    function writeIn1(ans){
        if (ans === null || ans === undefined || ans === '') return;
        ans = String(ans).replace(/\s+/g, '');
        if (input.tagName === 'TEXTAREA') input.value = ans;
        else input.value = ans;
        if (typeof InputEvent !== 'undefined') input.dispatchEvent(new InputEvent('input', { bubbles: true }));
        ['input', 'change', 'focus', 'keypress', 'keyup', 'keydown', 'select'].forEach(eventName => fire(input, eventName));
        FireForReact(input, 'change');
        input.value = ans;
    }

    // 查询本地规则，不访问远程规则服务。
    function compareUrl(){
        const rule = readRuleDictionary()[ruleUrl(window.location.href)];
        localRules = rule || null;
        return Promise.resolve(Boolean(rule));
    }

    //开始识别
    function start(){
        compareUrl().then((isExist) => {
            if (isExist) {
                exist = true;
                console.log("【自动识别填充验证码】已存在该网站规则");
                if (localRules["type"] == "img") {
                    captchaType = localRules["captchaType"];
                    imgIndex = localRules["img"];
                    inputIndex = localRules["input"];
                    element = document.getElementsByTagName('img')[imgIndex];
                    // console.log(element.src);
                    if (localRules["inputType"] == "textarea") {
                        input = document.getElementsByTagName('textarea')[inputIndex];
                    }
                    else {
                        input = document.getElementsByTagName('input')[inputIndex];
                        var inputList = document.getElementsByTagName('input');
                        // console.log(inputList);
                        if (inputList[0] && (inputList[0].id == "_w_simile" || inputList[0].id == "black_node")) {
                            inputIndex = parseInt(inputIndex) + 1;
                            input = inputList[inputIndex];
                        }
                    }
                    // console.log(input);
                    if (element && input) {
                        iscors = isCORS();
                        // console.log(input);
                        // console.log(element);
                        if (iscors) {
                            p2().then(() => {
                                // console.log(data);
                                codeByRule();
                            });
                        }
                        else {
                            codeByRule();
                        }
                    }
                    else
                        pageChange();
                }
                else if (localRules["type"] == "canvas") {
                    captchaType = localRules["captchaType"];
                    canvasIndex = localRules["img"];
                    inputIndex = localRules["input"];
                    element = document.getElementsByTagName('canvas')[canvasIndex];
                    if (localRules["inputType"] == "textarea") {
                        input = document.getElementsByTagName('textarea')[inputIndex];
                    }
                    else {
                        input = document.getElementsByTagName('input')[inputIndex];
                        var inputList = document.getElementsByTagName('input');
                        // console.log(inputList);
                        if (inputList[0] && (inputList[0].id == "_w_simile" || inputList[0].id == "black_node")) {
                            inputIndex = parseInt(inputIndex) + 1;
                            input = inputList[inputIndex];
                        }
                    }
                    iscors = isCORS();
                    if (iscors) {
                        p2().then(() => {
                            // console.log(data);
                            canvasRule();
                        });
                    }
                    else {
                        canvasRule();
                    }
                }
            }
            else {
                console.log("【自动识别填充验证码】不存在该网站规则，正在根据预设规则自动识别...");
                findCode(0);
            }
        });
    }

    //页面变化执行函数
    function pageChange(){
        if (exist) {
            if (localRules["type"] == "img" || localRules["type"] == null) {
                element = document.getElementsByTagName('img')[imgIndex];
                if (localRules["inputType"] == "textarea") {
                    input = document.getElementsByTagName('textarea')[inputIndex];
                }
                else {
                    input = document.getElementsByTagName('input')[inputIndex];
                    var inputList = document.getElementsByTagName('input');
                    if (inputList[0] && (inputList[0].id == "_w_simile" || inputList[0].id == "black_node")) {
                        input = inputList[inputIndex];
                    }
                }
                // console.log(element);
                // console.log(input);
                iscors = isCORS();
                if (iscors) {
                    p2().then(() => {
                        // console.log(data);
                        codeByRule();
                    });
                }
                else {
                    codeByRule();
                }
            }
            else if (localRules["type"] == "canvas") {
                element = document.getElementsByTagName('canvas')[canvasIndex];
                if (localRules["inputType"] == "textarea") {
                    input = document.getElementsByTagName('textarea')[inputIndex];
                }
                else {
                    input = document.getElementsByTagName('input')[inputIndex];
                    var inputList = document.getElementsByTagName('input');
                    if (inputList[0] && (inputList[0].id == "_w_simile" || inputList[0].id == "black_node")) {
                        input = inputList[inputIndex];
                    }
                }
                // console.log(element);
                // console.log(input);
                iscors = isCORS();
                if (iscors) {
                    p2().then(() => {
                        // console.log(data);
                        canvasRule();
                    });
                }
                else {
                    canvasRule();
                }
            }
        }
        else {
            findCode(0);
        }
    }

    function topNotice(msg){
        var div = document.createElement('div');
        div.id = 'topNotice';
        div.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 5%; z-index: 9999999999; background: rgba(117,140,148,1); display: flex; justify-content: center; align-items: center; color: #fff; font-family: "Microsoft YaHei"; text-align: center;';
        div.innerHTML = msg;
        div.style.fontSize = 'medium';
        document.body.appendChild(div);
        setTimeout(function(){
            document.body.removeChild(document.getElementById('topNotice'));
        }, 3500);
    }

    function manageBlackList(){
        var blackList = GM_getValue("blackList", []);
        var div = document.createElement("div");
        div.style.cssText = 'width: 700px; height: 350px; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: white; border: 1px solid black; z-index: 9999999999; text-align: center; padding-top: 20px; padding-bottom: 20px; padding-left: 20px; padding-right: 20px; box-shadow: 0px 0px 10px 0px rgba(0,0,0,0.75); border-radius: 10px; overflow: auto;';
        div.innerHTML = "<h3 style='margin-bottom: 12px; font-weight: bold; font-size: 18px;'>黑名单</h3><button style='position: absolute; top: 10px; left: 10px; width: 50px; height: 30px; line-height: 30px; text-align: center; font-size: 13px; margin: 10px' id='add'>添加</button><table id='blackList' style='width:100%; border-collapse:collapse; border: 1px solid black;'><thead style='background-color: #f5f5f5;'><tr><th style='width: 80%; text-align: center; padding: 5px;'>字符串</th><th style='width: 20%; text-align: center; padding: 5px;'>操作</th></tr></thead><tbody></tbody></table><button style='position: absolute; top: 10px; right: 10px; width: 30px; height: 30px; line-height: 30px; text-align: center; font-size: 18px; font-weight: bold; color: #333; background-color: transparent; border: none; outline: none; cursor: pointer;' id='close'>×</button>";
        document.body.insertBefore(div, document.body.firstChild);
        var table = document.getElementById("blackList").getElementsByTagName('tbody')[0];
        for (var i = 0; i < blackList.length; i++) {
            var row = table.insertRow(i);
            row.insertCell(0).innerHTML = "<div style='white-space: nowrap; overflow: hidden; text-overflow: ellipsis;'>" + blackList[i] + "</div>";
            var removeBtn = document.createElement("button");
            removeBtn.className = "remove";
            removeBtn.style.cssText = 'background-color: transparent; color: blue; border: none; padding: 5px; font-size: 14px; border-radius: 5px;';
            removeBtn.innerText = "移除";
            row.insertCell(1).appendChild(removeBtn);
        }
        var close = document.getElementById("close");
        close.onclick = function(){
            div.remove();
        }
        var add = document.getElementById("add");
        add.onclick = function(){
            var zz = prompt("请输入一个字符串，任何URL中包含该字符串的网页都将被加入黑名单");
            if (zz == null) return;
            var blackList = GM_getValue("blackList", []);
            if (blackList.indexOf(zz) == -1) {
                blackList.push(zz);
                GM_setValue("blackList", blackList);
                var row = table.insertRow(table.rows.length);
                row.insertCell(0).innerHTML = "<div style='white-space: nowrap; overflow: hidden; text-overflow: ellipsis;'>" + zz + "</div>";
                var removeBtn = document.createElement("button");
                removeBtn.className = "remove";
                removeBtn.style.cssText = "background-color: transparent; color: blue; border: none; padding: 5px; font-size: 14px; border-radius: 5px; cursor: pointer; ";
                removeBtn.innerText = "移除";
                row.insertCell(1).appendChild(removeBtn);
                removeBtn.onclick = function(){
                    var index = this.parentNode.parentNode.rowIndex - 1;
                    blackList.splice(index, 1);
                    GM_setValue("blackList", blackList);
                    this.parentNode.parentNode.remove();
                }
                topNotice("添加黑名单成功，刷新页面生效")
            }
            else {
                topNotice("该网页已在黑名单中");
            }
        }
        var remove = document.getElementsByClassName("remove");
        for (var i = 0; i < remove.length; i++) {
            remove[i].onclick = function(){
                var index = this.parentNode.parentNode.rowIndex - 1;
                blackList.splice(index, 1);
                GM_setValue("blackList", blackList);
                this.parentNode.parentNode.remove();
                topNotice("移除黑名单成功，刷新页面生效");
            }
        }
    }

    console.log("【自动识别填充验证码】正在运行...");

    var url = window.location.href;
    var blackList = GM_getValue("blackList", []);
    var inBlack = blackList.some(function(blackItem) {
        return url.includes(blackItem);
    });
    if (inBlack) {
        console.log("【自动识别填充验证码】当前页面在黑名单中");
        return;
    } else {
        start();
    }

    var imgSrc = "";
    //监听页面变化
    setTimeout(function(){
        const targetNode = document.body;
        const config = { attributes:true, childList: true, subtree: true};
        const callback = function() {
            if (inBlack) return;
            try {
                if (iscors){
                    if (element == undefined) {
                        pageChange();
                    }
                    if (element.src != imgSrc) {
                        console.log("【自动识别填充验证码】页面/验证码已更新，正在识别...");
                        imgSrc = element.src;
                        pageChange();
                    }
                }
                else {
                    console.log("【自动识别填充验证码】页面/验证码已更新，正在识别...");
                    pageChange();
                }
            }
            catch(err) {
                return;
                // pageChange();
            }
        }
        const observer = new MutationObserver(callback);
        observer.observe(targetNode, config);
    }, 1000);

    //监听canvas变化
    setTimeout(function(){
        if (inBlack) return;
        try {
            if (element.tagName != "CANVAS") return;
        }
        catch(err) {
            return;
        }
        var canvasData1 = element.toDataURL();
        setInterval(function(){
            var canvasData2 = element.toDataURL();
            if (canvasData1 != canvasData2) {
                console.log("【自动识别填充验证码】页面/验证码已更新，正在识别...");
                canvasData1 = canvasData2;
                pageChange();
            }
        }, 0);
    }, 1000);

    //监听url变化
    setTimeout(function(){
        if (inBlack) return;
        var tempUrl = window.location.href;
        setInterval(function(){
            if (tempUrl != window.location.href) {
                console.log("【自动识别填充验证码】页面/验证码已更新，正在识别...");
                tempUrl = window.location.href;
                start();
            }
        });
    }, 500)
})();