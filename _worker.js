// @ts-nocheck
// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
// https://github.com/bia-pain-bache/BPB-Worker-Panel

import { connect } from 'cloudflare:sockets';

let users = {}; // ذخیره کاربران به صورت شیء

let userID = '89b3cbba-e6ac-485a-9481-976a0415eab9';
const proxyIPs = ['bpb.yousef.isegaro.com'];
const defaultHttpPorts = ['80', '8080', '2052', '2082', '2086', '2095', '8880'];
const defaultHttpsPorts = ['443', '8443', '2053', '2083', '2087', '2096'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let dohURL = 'https://cloudflare-dns.com/dns-query';
let trojanPassword = `bpb-trojan`;
let hashPassword = 'b5d0a5f7ff7aac227bc68b55ae713131ffdf605ca0da52cce182d513';
let panelVersion = '2.6.4';

if (!isValidUUID(userID)) throw new Error(`Invalid UUID: ${userID}`);
if (!isValidSHA224(hashPassword)) throw new Error(`Invalid Hash password: ${hashPassword}`);

export default {
    async fetch(request, env, ctx) {
        try {          
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            trojanPassword = env.TROJAN_PASS || trojanPassword;
            hashPassword = env.HASH_PASS || hashPassword;
            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                
                const searchParams = new URLSearchParams(url.search);
                const host = request.headers.get('Host');
                const client = searchParams.get('app');

                switch (url.pathname) {
                    case '/register':
                        const { username, password, accessDuration, bandwidthLimit } = await request.json();
                        try {
                            const message = await registerUser(username, password, accessDuration, bandwidthLimit);
                            return new Response(message, { status: 201 });
                        } catch (error) {
                            return new Response(error.message, { status: 400 });
                        }

                    case '/login':
                        const { username: loginUser, password: loginPassword } = await request.json();
                        try {
                            const token = await loginUser(loginUser, loginPassword);
                            return new Response(JSON.stringify({ token }), { status: 200 });
                        } catch (error) {
                            return new Response(error.message, { status: 401 });
                        }

                    case '/logout':
                        const logoutMessage = logoutUser();
                        return new Response(logoutMessage, { status: 200 });

                    case '/users':
                        const userList = listUsers();
                        return new Response(JSON.stringify(userList), { status: 200 });

                    case '/toggle-access':
                        const { username: toggleUsername } = await request.json();
                        try {
                            const message = toggleUserAccess(toggleUsername);
                            return new Response(message, { status: 200 });
                        } catch (error) {
                            return new Response(error.message, { status: 400 });
                        }

                    case '/reset-bandwidth':
                        const { username: resetUsername } = await request.json();
                        try {
                            const message = resetUserBandwidth(resetUsername);
                            return new Response(message, { status: 200 });
                        } catch (error) {
                            return new Response(error.message, { status: 400 });
                        }

                    case '/delete-user':
                        const { username: deleteUsername } = await request.json();
                        try {
                            const message = await deleteUser(deleteUsername);
                            return new Response(message, { status: 200 });
                        } catch (error) {
                            return new Response(error.message, { status: 400 });
                        }

                    default:
                        // return new Response('Not found', { status: 404 });
                        url.hostname = 'www.speedtest.net';
                        url.protocol = 'https:';

		    
                        request = new Request(url, request);
                        return await fetch(request);
                }
            } else {
                // مدیریت وب‌سکیت
            }
        } catch (err) {
            const errorPage = renderErrorPage('Something went wrong!', err, false);
            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
        }
    }
};

/**
 * ثبت‌نام کاربر
 */
async function registerUser(username, password, accessDurationInDays, bandwidthLimitInGB) {
    if (users[username]) {
        throw new Error(`کاربر با نام ${username} وجود دارد.`);
    }
    const hashedPassword = await hashPassword(password);
    const creationDate = new Date(); // تاریخ ایجاد اکانت
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + accessDurationInDays);
    users[username] = { 
        password: hashedPassword, 
        creationDate,
        expiration: expirationDate,
        bandwidthLimit: bandwidthLimitInGB * 1024 * 1024 * 1024, // تبدیل به بایت
        usedBandwidth: 0, // مقدار مصرف شده
        isActive: true // وضعیت فعال/غیرفعال
    };
    return 'ثبت‌نام با موفقیت انجام شد.';
}

/**
 * ورود کاربر
 */
async function loginUser(username, password) {
    const user = users[username];
    if (!user) {
        throw new Error('کاربر یافت نشد.');
    }
    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
        throw new Error('رمز عبور نادرست است.');
    }

    const now = new Date();
    if (now > user.expiration) {
        throw new Error('دسترسی کاربر به پایان رسیده است.');
    }

    const token = generateJWTToken(username);
    return token;
}

/**
 * خروج کاربر
 */
function logoutUser() {
    return 'خروج با موفقیت انجام شد.';
}

/**
 * لیست کاربران
 */
function listUsers() {
    const now = new Date();
    return Object.keys(users).map(username => {
        const user = users[username];
        const daysRemaining = Math.ceil((user.expiration - now) / (1000 * 60 * 60 * 24)); // محاسبه روزهای باقی‌مانده
        return {
            username,
            creationDate: user.creationDate.toISOString(),
            expiration: user.expiration.toISOString(),
            daysRemaining,
            usedBandwidth: user.usedBandwidth / (1024 * 1024 * 1024), // تبدیل به گیگابایت
            bandwidthLimit: user.bandwidthLimit / (1024 * 1024 * 1024), // تبدیل به گیگابایت
            isActive: user.isActive
        };
    });
}

/**
 * فعال و غیرفعال کردن دسترسی کاربر
 */
function toggleUserAccess(username) {
    const user = users[username];
    if (!user) {
        throw new Error('کاربر یافت نشد.');
    }
    user.isActive = !user.isActive; // تغییر وضعیت
    return `دسترسی کاربر ${username} ${user.isActive ? 'فعال' : 'غیرفعال'} شد.`;
}

/**
 * حذف کاربر
 */
function deleteUser(username) {
    if (!users[username]) {
        throw new Error('کاربر یافت نشد.');
    }
    delete users[username];
    return `کاربر ${username} با موفقیت حذف شد.`;
}

/**
 * بازنشانی حجم استفاده شده
 */
function resetUserBandwidth(username) {
    const user = users[username];
    if (!user) {
        throw new Error('کاربر یافت نشد.');
    }
    user.usedBandwidth = 0; // بازنشانی مصرف
    return `حجم مصرفی کاربر ${username} با موفقیت بازنشانی شد.`;
}

/**
 * اعتبارسنجی UUID
 */
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

/**
 * اعتبارسنجی SHA224
 */
function isValidSHA224(hash) {
    const sha224Regex = /^[0-9a-f]{56}$/i;
    return sha224Regex.test(hash);
}

/**
 * صفحه خطا
 */
function renderErrorPage(message, error, refer) {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Error Page</title>
        <style>
            :root {
                --color: black;
                --header-color: #09639f;

                --background-color: #fff;
                --border-color: #ddd;
                --header-shadow: 2px 2px 4px rgba(0, 0, 0, 0.25);
            }
            body, html {
                height: 100%;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                font-family: system-ui;
                color: var(--color);
                background-color: var(--background-color);
            }
            h1 { font-size: 2.5rem; text-align: center; color: var(--header-color); text-shadow: var(--header-shadow); }
            #error-container { text-align: center; }
        </style>
    </head>
    <body>
        <div id="error-container">
            <h1>BPB Panel <span style="font-size: smaller;">${panelVersion}</span> 💦</h1>
            <div id="error-message">
                <h2>${message} ${refer 
                    ? 'Please try again or refer to <a href="https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/main/README.md">documents</a>' 
                    : ''}
                </h2>
                <p><b>${error ? `⚠️ ${error.stack.toString()}` : ''}</b></p>
            </div>
        </div>
    </body>
    </html>`;
}

// توابع کمکی مانند hashPassword، verifyPassword، generateJWTToken و غیره باید در اینجا تعریف شوند.		
