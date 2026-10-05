'use strict';

// Run with: node --test tests/test_captcha_userscripts.cjs
// Real userscript source runs inside vm; all DOM, GM storage/network and timers
// are mocks. No browser, login site or online API is used by this suite.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const ROOT = path.resolve(__dirname, '..');
const API = 'https://anticap.314521.xyz/api/v1';
const PAGE = 'https://sample.test/login';
const RULE_STORE = 'ANTICAP_LOCAL_RULES';
const names = ['ocr.js', 'ocr2.js'];
const source = name => fs.readFileSync(path.join(ROOT, 'captcha_solver', name), 'utf8');
const ok = result => ({ result, meta: { status: 'ok', request_id: 'mock-request' } });
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
async function settled(promise) {
    let timer;
    try {
        return await Promise.race([promise, new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('Recognition promise did not settle')), 100);
        })]);
    } finally { clearTimeout(timer); }
}

class MockEvent {
    constructor(type, options = {}) { this.type = type; Object.assign(this, options); }
    initEvent(type, bubbles, cancelable) { Object.assign(this, { type, bubbles, cancelable }); }
}
function element(tag = 'div', options = {}) {
    const rect = { left: 0, top: 0, width: 100, height: 30, ...options.rect };
    return {
        tagName: tag.toUpperCase(), nodeType: 1, id: '', className: '', name: '',
        alt: '', title: '', placeholder: '', src: '', value: 'unchanged', type: 'text',
        style: {}, textContent: '', innerHTML: '', events: [], children: [],
        complete: true, naturalWidth: rect.width, naturalHeight: rect.height,
        width: rect.width, height: rect.height, offsetWidth: rect.width, offsetHeight: rect.height,
        getBoundingClientRect: () => ({ ...rect, right: rect.left + rect.width, bottom: rect.top + rect.height }),
        getAttribute(name) { return this[name] || null; },
        dispatchEvent(event) { this.events.push(event); return true; },
        addEventListener() {}, closest: () => null,
        querySelector: () => null, querySelectorAll: () => [],
        appendChild(child) { this.children.push(child); child.parentElement = this; return child; },
        removeChild(child) { this.children = this.children.filter(item => item !== child); },
        ...options,
    };
}
function fixture() {
    const image = element('img', { id: 'captcha', src: 'data:image/png;base64,SU1BR0U=' });
    const input = element('input', { id: 'captcha-input' });
    const form = element('form');
    image.parentElement = form;
    input.parentElement = form;
    form.querySelectorAll = selector => selector.includes('input') ? [input] : [];
    return { image, input };
}
function sliderFixture({ single = false, canvas = false, wrapper = false } = {}) {
    const background = element(canvas ? 'canvas' : 'img', {
        className: 'slider-bg', src: 'data:image/png;base64,QkFDSw==',
        naturalWidth: 600, naturalHeight: 300, width: 600, height: 300,
        rect: { left: 100, top: 40, width: 300, height: 150 },
    });
    const piece = element(canvas ? 'canvas' : 'img', {
        className: 'slider-puzzle', src: 'data:image/png;base64,UElFQ0U=',
        naturalWidth: 60, naturalHeight: 60, width: 60, height: 60,
        rect: { left: 120, top: 55, width: 30, height: 30 },
    });
    if (canvas) {
        background.toDataURL = () => 'data:image/png;base64,QkFDSw==';
        piece.toDataURL = () => 'data:image/png;base64,UElFQ0U=';
    }
    const backgroundNode = wrapper ? element('div') : background;
    const pieceNode = wrapper ? element('div') : piece;
    if (wrapper) {
        backgroundNode.querySelector = () => background;
        pieceNode.querySelector = () => piece;
    }
    const slider = element('button', { className: 'slider-btn', rect: { left: 110, top: 210, width: 40, height: 30 } });
    const track = element('div', { className: 'slider-track', rect: { left: 100, top: 210, width: 300, height: 30 } });
    const container = element('div', { className: 'slider-container' });
    container.querySelector = selector => {
        if (selector.includes('slider-btn')) return slider;
        if (selector.includes('slider-track')) return track;
        if (selector.includes('slider-bg')) return backgroundNode;
        if (selector.includes('slider-puzzle')) return single ? null : pieceNode;
        return null;
    };
    container.querySelectorAll = selector => selector === 'img' ? [background, ...(single ? [] : [piece])] : [];
    return { background, piece, slider, track, container };
}
function harness(name, options = {}) {
    const requests = [], logs = [], menus = new Map(), prompts = [], timers = new Map(), listeners = new Map();
    const storage = new Map(Object.entries({ fisrtUse: false, ...options.storage }));
    if (options.key !== null) storage.set('ANTICAP_API_KEY', options.key || randomUUID());
    const key = storage.get('ANTICAP_API_KEY');
    const f = options.captcha || null, s = options.slider || null;
    let timerId = 0, drawn = null;
    const document = {
        readyState: 'loading', body: element('body'),
        addEventListener(type, callback) { listeners.set(type, callback); },
        dispatchEvent(event) { listeners.get(event.type)?.(event); },
        getElementsByTagName(tag) {
            if (tag === 'img') return f ? [f.image] : [];
            if (tag === 'input') return f ? [f.input] : [];
            if (tag === 'textarea') return f?.textarea ? [f.textarea] : [];
            if (tag === 'canvas') return f?.canvas ? [f.canvas] : [];
            return [];
        },
        querySelectorAll(selector) {
            if (s && selector === '.slider-container') return [s.container];
            if (f && (selector === 'img[src*="captcha"]' || selector === 'img[id*="captcha"]' || selector === 'img, canvas')) return [f.image];
            if (f && selector.includes('input')) return [f.input];
            return [];
        },
        querySelector: () => null,
        getElementById(id) { return this.body.children.find(child => child.id === id); },
        createEvent: () => new MockEvent(''),
        createElement(tag) {
            const node = element(tag);
            if (tag === 'canvas') {
                node.getContext = () => ({ drawImage(image) { drawn = image; } });
                node.toDataURL = () => {
                    if (options.taintedCanvas) throw new Error('mock tainted canvas');
                    return drawn?.src || 'data:image/png;base64,SU1BR0U=';
                };
            }
            return node;
        },
    };
    const sandbox = {
        document, Event: MockEvent, MouseEvent: MockEvent, InputEvent: MockEvent, KeyboardEvent: MockEvent,
        Uint8Array, URL, btoa: text => Buffer.from(text, 'binary').toString('base64'),
        console: Object.fromEntries(['log', 'error', 'warn'].map(level => [level, (...args) => logs.push(args.join(' '))])),
        prompt(message, defaultValue) { prompts.push({ message, defaultValue }); return options.promptAnswer ?? null; },
        alert(message) { logs.push(String(message)); }, confirm: () => options.generalRule !== false,
        GM_getValue: (name, fallback) => storage.has(name) ? storage.get(name) : fallback,
        GM_setValue: (name, value) => storage.set(name, structuredClone(value)),
        GM_registerMenuCommand: (label, callback) => menus.set(label, callback),
        GM_xmlhttpRequest(request) {
            requests.push(request);
            if (request.method === 'GET' && request.responseType === 'arraybuffer') {
                request.onload?.({ status: 200, response: Uint8Array.from([65, 66]).buffer });
            } else if (options.failure === 'network') {
                request.onerror?.({ message: 'mock network failure' });
            } else if (options.failure === 'timeout') {
                request.ontimeout?.();
            } else {
                const body = options.body ?? ok('AB12');
                request.onload?.({ status: options.status ?? 200, response: options.responseTextOnly ? null : body,
                    responseText: options.rawText ?? JSON.stringify(body) });
            }
            return { abort() {} };
        },
        setTimeout(callback, delay = 0) { const id = ++timerId; timers.set(id, { callback, delay, interval: false }); return id; },
        clearTimeout: id => timers.delete(id),
        setInterval(callback, delay = 0) { const id = ++timerId; timers.set(id, { callback, delay, interval: true }); return id; },
        clearInterval: id => timers.delete(id),
        MutationObserver: class { constructor(callback) { this.callback = callback; } observe() {} },
        // Access to a page-stored credential is intentionally an error.
        localStorage: { getItem() { throw new Error('Page credentials must not be read'); } },
    };
    sandbox.window = sandbox;
    sandbox.top = sandbox.self = sandbox;
    sandbox.location = { href: options.url || PAGE + '?next=home#form', host: 'sample.test' };
    sandbox.getComputedStyle = node => ({ display: 'block', visibility: 'visible', position: 'static', ...node.computedStyle });
    sandbox.open = () => {};
    const expose = name === 'ocr.js'
        ? 'globalThis.subject = { recognizeCaptcha, calculateSlideDistance, checkForCaptcha, checkForSliderCaptcha, simulateSliderDrag };'
        : 'globalThis.subject = { p, p1, addR, delR, compareUrl, start, writeIn, writeIn1, setType(value) { captchaType = value; }, setInput(value) { input = value; } };';
    // Test instrumentation is inserted only into the vm copy, never production.
    const instrumented = source(name).replace(/\}\)\(\);\s*$/, expose + '\n})();');
    vm.createContext(sandbox);
    vm.runInContext(instrumented, sandbox, { filename: name });
    return {
        requests, logs, menus, prompts, storage, key, document, subject: sandbox.subject,
        async domReady() { listeners.get('DOMContentLoaded')?.(); await flush(); },
        async runTimeout(delay) {
            const matches = [...timers.entries()].filter(([, timer]) => !timer.interval && timer.delay === delay);
            for (const [id, timer] of matches) { timers.delete(id); timer.callback(); }
            await flush();
        },
        async finishDrag() {
            for (let i = 0; i < 40; i++) {
                for (const [id, timer] of [...timers.entries()]) if (timer.interval && timer.delay === 20 && timers.has(id)) timer.callback();
                await this.runTimeout(20);
            }
        },
    };
}
function checkRequest(h, endpoint, payload) {
    const request = h.requests.at(-1);
    assert.ok(request, 'recognition request exists');
    assert.equal(request.method, 'POST');
    assert.equal(request.url, API + endpoint);
    assert.equal(request.headers.Authorization === 'Bearer ' + h.key, true, 'uses GM credential as Bearer token');
    assert.equal(request.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(request.data), payload);
    assert.ok(request.timeout > 0, 'request has finite timeout');
    assert.ok(h.logs.every(line => !h.key || !line.includes(h.key)), 'credential is never logged');
}
async function recognize(h, name, input, image = 'SU1BR0U=') {
    if (name === 'ocr.js') return h.subject.recognizeCaptcha(image, input);
    const result = await settled(h.subject.p(image, 0));
    h.subject.writeIn(result);
    return result;
}

for (const name of names) {
    test(name + ': standalone metadata grants, fixed HTTPS and no upstream auto-update', () => {
        const code = source(name);
        for (const grant of ['GM_xmlhttpRequest', 'GM_getValue', 'GM_setValue', 'GM_registerMenuCommand']) {
            assert.ok(new RegExp('@grant\\s+' + grant).test(code), name + ' grants ' + grant);
        }
        assert.ok(/https:\/\/anticap\.314521\.xyz\/api\/v1/.test(code), 'fixed AntiCAP base URL');
        assert.ok(!/@(?:downloadURL|updateURL|require)|captcha\.tangyun|captcha\.zwhyzzz|jfbym|queryRule|updateRule|deleteRule/.test(code), 'no legacy endpoints or external code');
    });
    test(name + ': menu saves a credential without pre-filling or logging it', async () => {
        const h = harness(name, { key: null, promptAnswer: '  ' + randomUUID() + '  ' });
        await flush();
        const menu = [...h.menus.entries()].find(([label]) => /AntiCAP.*(?:密钥|API Key)/i.test(label));
        assert.ok(menu, 'AntiCAP credential configuration menu exists');
        menu[1]();
        await flush();
        assert.equal(typeof h.storage.get('ANTICAP_API_KEY'), 'string');
        assert.equal(h.storage.get('ANTICAP_API_KEY'), h.storage.get('ANTICAP_API_KEY').trim());
        assert.equal(h.prompts.at(-1).defaultValue, '');
        assert.ok(h.logs.every(line => !line.includes(h.storage.get('ANTICAP_API_KEY'))));
    });
    test(name + ': missing credential produces no API request', async () => {
        const f = fixture(), h = harness(name, { key: null, captcha: f });
        await flush();
        h.requests.length = 0;
        await recognize(h, name, f.input);
        await flush();
        assert.equal(h.requests.length, 0);
        assert.equal(f.input.value, 'unchanged');
        assert.equal(f.input.events.length, 0);
    });
    test(name + ': OCR contract and DOM input/change events', async () => {
        const f = fixture(), h = harness(name, { captcha: f, body: ok(' AB12 ') });
        await flush();
        f.input.events.length = 0;
        await recognize(h, name, f.input);
        await flush();
        checkRequest(h, '/ocr', { img_base64: 'SU1BR0U=' });
        assert.equal(f.input.value, 'AB12');
        assert.ok(f.input.events.some(event => event.type === 'input'));
        assert.ok(f.input.events.some(event => event.type === 'change' && event.bubbles));
    });
    test(name + ': auto discovery runs on mock DOM without a health or rule request', async () => {
        const f = fixture(), h = harness(name, { captcha: f });
        if (name === 'ocr.js') { await h.domReady(); await h.runTimeout(1000); }
        await flush();
        checkRequest(h, '/ocr', { img_base64: 'SU1BR0U=' });
        assert.equal(f.input.value, 'AB12');
        assert.ok(h.requests.every(request => request.url === API + '/ocr'));
    });
    for (const scenario of [
        { title: 'no_match with a misleading non-null result', body: { result: 'BAD', meta: { status: 'no_match' } } },
        { title: 'null result', body: ok(null) },
        { title: 'wrong result type', body: ok(42) },
        { title: 'missing meta status', body: { result: 'BAD' } },
        { title: '401 structured error', status: 401, body: { error: { code: 'invalid_api_key', message: 'mock authentication error' }, request_id: 'mock-error' } },
        { title: '429 structured error', status: 429, body: { error: { code: 'rate_limited', message: 'mock quota error' }, request_id: 'mock-error' } },
        { title: 'non-2xx success-looking body', status: 500, body: ok('BAD') },
        { title: 'malformed JSON', responseTextOnly: true, rawText: 'not JSON' },
        { title: 'network failure', failure: 'network' },
        { title: 'timeout', failure: 'timeout' },
    ]) {
        test(name + ': settles without modifying input on ' + scenario.title, { timeout: 500 }, async () => {
            const f = fixture(), h = harness(name, { captcha: f, ...scenario });
            await flush();
            f.input.value = 'unchanged'; f.input.events.length = 0;
            await recognize(h, name, f.input);
            assert.equal(f.input.value, 'unchanged');
            assert.equal(f.input.events.length, 0);
            assert.ok(h.logs.every(line => !line.includes(h.key)));
            if (scenario.status === 401) assert.ok(h.logs.some(line => line.includes('invalid_api_key') && line.includes('mock-error')));
        });
    }
    test(name + ': supports GM text-only response parsing', async () => {
        const f = fixture(), h = harness(name, { captcha: f, body: ok('TEXT'), responseTextOnly: true });
        await flush();
        await recognize(h, name, f.input);
        assert.equal(f.input.value, 'TEXT');
    });
}

test('ocr2.js: math zero is posted to /math, preserved and written with events', async () => {
    const f = fixture(), h = harness('ocr2.js', { captcha: f, body: { result: 0 } });
    await flush();
    h.subject.setType('math'); h.subject.setInput(f.input);
    const result = await h.subject.p1('SU1BR0U=');
    assert.equal(result, 0);
    h.subject.writeIn1(result);
    checkRequest(h, '/math', { img_base64: 'SU1BR0U=' });
    assert.equal(f.input.value, '0');
    assert.ok(f.input.events.some(event => event.type === 'input'));
});
test('ocr2.js: stored math rule auto-fills zero and ignores query/hash in rule key', async () => {
    const f = fixture();
    const rule = { url: PAGE, type: 'img', img: 0, input: 0, inputType: 'input', captchaType: 'math' };
    const h = harness('ocr2.js', { captcha: f, body: ok(0), storage: { [RULE_STORE]: { [PAGE]: rule } } });
    await flush();
    checkRequest(h, '/math', { img_base64: 'SU1BR0U=' });
    assert.equal(f.input.value, '0');
    assert.equal(h.requests.length, 1);
});
test('ocr2.js: local rule add/query/update/delete persist without any network request', async () => {
    const h = harness('ocr2.js');
    await flush(); h.requests.length = 0;
    assert.equal(await h.subject.compareUrl(), false);
    const rule = { url: PAGE + '?next=other#x', type: 'img', img: 0, input: 0, inputType: 'input', captchaType: 'general' };
    assert.equal((await h.subject.addR(rule)).status, 200);
    assert.equal(await h.subject.compareUrl(), true);
    assert.equal(h.storage.get(RULE_STORE)[PAGE].captchaType, 'general');
    await h.subject.addR({ ...rule, captchaType: 'math' });
    assert.equal(h.storage.get(RULE_STORE)[PAGE].captchaType, 'math');
    const nextPage = PAGE + '/other';
    await h.subject.addR({ ...rule, url: nextPage });
    await h.subject.delR({ url: PAGE + '?next=home#form' });
    assert.equal(await h.subject.compareUrl(), false);
    assert.equal(h.storage.get(RULE_STORE)[PAGE], undefined);
    assert.ok(h.storage.get(RULE_STORE)[nextPage]);
    assert.equal(h.requests.length, 0);
    const reloaded = harness('ocr2.js', { storage: Object.fromEntries(h.storage) });
    await flush();
    assert.equal(await reloaded.subject.compareUrl(), false);
});
test('ocr2.js: rule selection menu saves locally and runs the selected math rule', async () => {
    const f = fixture(), h = harness('ocr2.js', { captcha: f, body: ok(0), generalRule: false });
    await flush(); h.requests.length = 0;
    h.menus.get('添加当前页面规则')();
    h.document.oncontextmenu({ target: f.image, preventDefault() {} });
    h.document.onclick({ target: f.input, preventDefault() {} });
    await flush();
    assert.equal(h.storage.get(RULE_STORE)[PAGE].captchaType, 'math');
    checkRequest(h, '/math', { img_base64: 'SU1BR0U=' });
    assert.equal(f.input.value, '0');
    h.menus.get('清除当前页面规则')();
    await flush();
    assert.equal(h.storage.get(RULE_STORE)[PAGE], undefined);
    assert.ok(h.requests.every(request => request.url === API + '/math'));
});
test('ocr2.js: textarea rule writes value rather than interpreting OCR as HTML', async () => {
    const h = harness('ocr2.js'), input = element('textarea');
    await flush(); h.subject.setInput(input);
    h.subject.writeIn1('<text>');
    assert.equal(input.value, '<text>');
    assert.equal(input.innerHTML, '');
    assert.ok(input.events.some(event => event.type === 'change'));
});

for (const kind of ['img', 'canvas', 'wrapper']) {
    test('ocr.js: slider dual-image contract and CSS scale/start offset (' + kind + ')', async () => {
        const s = sliderFixture({ canvas: kind === 'canvas', wrapper: kind === 'wrapper' });
        const h = harness('ocr.js', { body: ok({ target: [240, 30, 300, 90] }) });
        const result = await settled(h.subject.calculateSlideDistance(s.slider, s.track, s.container));
        assert.equal(result, 100, '240 * (300/600) - (120-100), not raw 240');
        checkRequest(h, '/slider/match', { target_base64: 'UElFQ0U=', background_base64: 'QkFDSw==' });
        assert.equal(h.requests.length, 1, 'no health request');
    });
}
test('ocr.js: detected slider automatically drags the scaled distance', async () => {
    const s = sliderFixture(), h = harness('ocr.js', { slider: s, body: ok({ target: [240, 30, 300, 90] }) });
    await h.domReady(); await h.runTimeout(2000); await h.finishDrag();
    const down = s.slider.events.find(event => event.type === 'mousedown');
    const up = s.slider.events.find(event => event.type === 'mouseup');
    assert.ok(down && up, 'drag emits mousedown and mouseup');
    assert.equal(up.clientX - down.clientX, 100);
    checkRequest(h, '/slider/match', { target_base64: 'UElFQ0U=', background_base64: 'QkFDSw==' });
});
test('ocr.js: a single screenshot fails explicitly without an API request or random drag', async () => {
    const s = sliderFixture({ single: true }), h = harness('ocr.js');
    const result = await settled(h.subject.calculateSlideDistance(s.slider, s.track, s.container));
    assert.equal(result, null);
    assert.equal(h.requests.length, 0);
    assert.ok(h.logs.some(line => /双图|两张|独立|背景.*拼图/.test(line)));
    assert.equal(s.slider.events.length, 0);
});
for (const scenario of [
    { title: 'no_match', body: { result: { target: [240, 30, 300, 90] }, meta: { status: 'no_match' } } },
    { title: 'zero coordinates', body: ok({ target: [0, 0, 0, 0] }) },
    { title: 'null', body: ok(null) },
    { title: 'reversed box', body: ok({ target: [300, 30, 240, 90] }) },
    { title: 'out-of-image box', body: ok({ target: [240, 30, 700, 90] }) },
    { title: 'negative box', body: ok({ target: [-1, 30, 59, 90] }) },
    { title: 'structured API error', status: 400, body: { error: { code: 'bad_image', message: 'mock invalid image' }, request_id: 'mock-error' } },
    { title: 'timeout', failure: 'timeout' },
]) {
    test('ocr.js: slider ' + scenario.title + ' does not fall back to a random distance', { timeout: 500 }, async () => {
        const s = sliderFixture(), h = harness('ocr.js', scenario);
        assert.equal(await settled(h.subject.calculateSlideDistance(s.slider, s.track, s.container)), null);
        assert.equal(s.slider.events.length, 0);
        assert.ok(h.requests.every(request => request.url === API + '/slider/match'));
    });
}
test('ocr.js: a genuine match at image x=0 is distinct from the zero-box sentinel', async () => {
    const s = sliderFixture();
    s.piece.getBoundingClientRect = () => ({ left: 100, top: 55, width: 30, height: 30 });
    const h = harness('ocr.js', { body: ok({ target: [0, 30, 60, 90] }) });
    assert.equal(await settled(h.subject.calculateSlideDistance(s.slider, s.track, s.container)), 0);
});
test('ocr.js: slider displacement outside the remaining track fails rather than clamps', async () => {
    const s = sliderFixture();
    s.track.getBoundingClientRect = () => ({ left: 100, width: 120, top: 210, height: 30 });
    const h = harness('ocr.js', { body: ok({ target: [240, 30, 300, 90] }) });
    assert.equal(await settled(h.subject.calculateSlideDistance(s.slider, s.track, s.container)), null);
});
test('ocr.js: cross-origin image fetch never receives the API credential', async () => {
    const f = fixture(); f.image.src = 'https://images.sample.test/captcha.png';
    const h = harness('ocr.js', { captcha: f, taintedCanvas: true });
    await h.domReady(); await h.runTimeout(1000);
    const imageRequest = h.requests.find(request => request.method === 'GET');
    assert.ok(imageRequest);
    assert.equal(imageRequest.url, f.image.src);
    assert.equal(imageRequest.headers?.Authorization, undefined);
    checkRequest(h, '/ocr', { img_base64: 'QUI=' });
});
