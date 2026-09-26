#include email_storage.inc;

// ==================== FALSE POSITIVE FILTERS ====================

function isInsideBase64Image(text, matchPos) {
    // check if the match sits inside a data:image/... base64 block
    var searchStart = Math.max(0, matchPos - 200);
    var chunk = text.substring(searchStart, matchPos + 200);
    if (chunk.indexOf("data:image/") != -1) return true;
    if (chunk.indexOf("data:font/") != -1) return true;
    if (chunk.indexOf("data:application/font") != -1) return true;
    if (chunk.indexOf("data:audio/") != -1) return true;
    if (chunk.indexOf("data:video/") != -1) return true;
    if (chunk.indexOf("data:application/octet-stream") != -1) return true;
    if (chunk.indexOf("data:application/pdf") != -1) return true;
    return false;
}

function isInsideSVGPath(text, matchPos) {
    var searchStart = Math.max(0, matchPos - 300);
    var chunk = text.substring(searchStart, matchPos);
    if (chunk.lastIndexOf("<path") > chunk.lastIndexOf("</path")) return true;
    if (chunk.lastIndexOf("<polygon") > chunk.lastIndexOf("</polygon")) return true;
    if (chunk.lastIndexOf(" d=\"") > chunk.lastIndexOf("\"") - 2) return true;
    return false;
}

function isInsideIntegrityAttr(text, matchPos) {
    var searchStart = Math.max(0, matchPos - 100);
    var chunk = text.substring(searchStart, matchPos);
    if (chunk.indexOf("integrity=") != -1) return true;
    if (chunk.indexOf("integrity =") != -1) return true;
    return false;
}

function isInsideCSSUrl(text, matchPos) {
    var searchStart = Math.max(0, matchPos - 100);
    var chunk = text.substring(searchStart, matchPos);
    if (chunk.indexOf("url(data:") != -1) return true;
    if (chunk.indexOf("background") != -1 && chunk.indexOf("base64") != -1) return true;
    return false;
}

function isKnownTestKey(value) {
    var testKeys = [
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUV",
        "sk_test_", "pk_test_",
        "xoxb-not-a-real-token",
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "your-api-key", "YOUR_API_KEY", "your_api_key_here",
        "INSERT_YOUR_KEY", "REPLACE_ME", "xxx", "changeme",
        "example", "placeholder", "dummy", "test123",
    ];
    var lv = value.toLowerCase();
    for (var i = 0; i < testKeys.length; i++) {
        if (lv.indexOf(testKeys[i].toLowerCase()) != -1) return true;
    }
    if (/^[x]{8,}$/.test(value) || /^[0]{8,}$/.test(value) || /^[*]{4,}$/.test(value)) return true;
    return false;
}

function isInComment(text, matchPos) {
    var searchStart = Math.max(0, matchPos - 200);
    var chunk = text.substring(searchStart, matchPos);
    var lastCommentOpen = chunk.lastIndexOf("<!--");
    var lastCommentClose = chunk.lastIndexOf("-->");
    if (lastCommentOpen > lastCommentClose) return true;
    var lastJSComment = chunk.lastIndexOf("//");
    if (lastJSComment != -1) {
        var afterComment = chunk.substring(lastJSComment);
        if (afterComment.indexOf("\n") == -1) return true;
    }
    return false;
}

function isFalsePositiveContext(text, matchPos, matchValue) {
    if (isInsideBase64Image(text, matchPos)) return true;
    if (isInsideSVGPath(text, matchPos)) return true;
    if (isInsideIntegrityAttr(text, matchPos)) return true;
    if (isInsideCSSUrl(text, matchPos)) return true;
    if (isKnownTestKey(matchValue)) return true;
    if (isInComment(text, matchPos)) return true;
    return false;
}

// ==================== EMAIL DETECTION ====================

var frameworkEmails = [
    "w3.org", "schema.org", "example.com", "example.org", "example.net",
    "test.com", "localhost", "noreply", "no-reply", "donotreply",
    "users.noreply.github.com", "wicg.io", "chromium.org",
    "webkit.org", "mozilla.org", "apple.com",
    "sentry.io", "sentry-next.wixpress.com",
];

function isFrameworkEmail(email) {
    var le = email.toLowerCase();
    for (var i = 0; i < frameworkEmails.length; i++) {
        if (le.indexOf("@" + frameworkEmails[i]) != -1) return true;
        if (le.indexOf(frameworkEmails[i]) != -1 && frameworkEmails[i].indexOf(".") != -1) return true;
    }
    if (le.indexOf("@") == -1) return false;
    var domain = le.split("@")[1];
    if (!domain) return false;
    if (domain.indexOf(".") == -1) return true;
    return false;
}

function extractAllEmails(text) {
    var results = [];
    var seen = {};

    // 1. Standard email regex (RFC 5322 relaxed)
    var emailRe = /[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*/g;
    var m;
    while (m = emailRe.exec(text)) {
        var email = m[0].replace(/[.,;:!?)>'"\]]+$/, "");
        if (email.indexOf(".") == email.length - 1) email = email.substring(0, email.length - 1);
        if (!email || email.length < 5) continue;
        var domain = email.split("@")[1];
        if (!domain || domain.indexOf(".") == -1) continue;
        if (domain.toLowerCase().endsWith(".png") || domain.toLowerCase().endsWith(".jpg") ||
            domain.toLowerCase().endsWith(".gif") || domain.toLowerCase().endsWith(".svg") ||
            domain.toLowerCase().endsWith(".css") || domain.toLowerCase().endsWith(".js")) continue;
        if (isInsideBase64Image(text, m.index)) continue;
        if (isInsideSVGPath(text, m.index)) continue;
        if (!isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
            seen[email.toLowerCase()] = true;
            results.push(email);
        }
    }

    // 2. mailto: links
    var mailtoRe = /mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi;
    while (m = mailtoRe.exec(text)) {
        var email = m[1];
        if (!isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
            seen[email.toLowerCase()] = true;
            results.push(email);
        }
    }

    // 3. Obfuscated: [at] (at) {at} -at- _at_
    var obfRe = /([a-zA-Z0-9._%+\-]+)\s*[\[\(\{<]?\s*(?:at|AT|@)\s*[\]\)\}>]?\s*([a-zA-Z0-9.\-]+\s*[\[\(\{<]?\s*(?:dot|DOT|\.)\s*[\]\)\}>]?\s*[a-zA-Z]{2,})/g;
    while (m = obfRe.exec(text)) {
        var email = m[1].trim() + "@" + m[2].replace(/\s*[\[\(\{<]?\s*(?:dot|DOT)\s*[\]\)\}>]?\s*/g, ".").trim();
        if (email.indexOf(".") != -1 && !isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
            seen[email.toLowerCase()] = true;
            results.push(email + " (deobfuscated)");
        }
    }

    // 4. HTML entity encoded: &#64; = @ , &#46; = .
    var decoded = text.replace(/&#64;/g, "@").replace(/&#x40;/gi, "@")
                     .replace(/&#46;/g, ".").replace(/&#x2e;/gi, ".");
    if (decoded != text) {
        var entityRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
        while (m = entityRe.exec(decoded)) {
            var email = m[0];
            if (!isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
                seen[email.toLowerCase()] = true;
                results.push(email + " (entity-encoded)");
            }
        }
    }

    // 5. JS var name/domain concatenation patterns
    var jsMailRe = /var\s+\w*(?:mail|email|addr|contact)\w*\s*=\s*["']([^"'@]+)["']\s*\+?\s*["']?@["']?\s*\+?\s*["']([^"']+)["']/gi;
    while (m = jsMailRe.exec(text)) {
        var email = m[1] + "@" + m[2];
        if (!isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
            seen[email.toLowerCase()] = true;
            results.push(email + " (JS-constructed)");
        }
    }

    // 6. JSON fields with email values
    var jsonMailRe = /["'](?:email|mail|contact|from|to|reply.?to|sender|recipient|author.?email)["']\s*:\s*["']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']/gi;
    while (m = jsonMailRe.exec(text)) {
        var email = m[1];
        if (!isFrameworkEmail(email) && !seen[email.toLowerCase()]) {
            seen[email.toLowerCase()] = true;
            results.push(email);
        }
    }

    // 7. meta tags
    var metaMailRe = /<meta\s[^>]*content=["']([^"']*@[^"']*)["'][^>]*>/gi;
    while (m = metaMailRe.exec(text)) {
        var content = m[1];
        var innerRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
        var m2;
        while (m2 = innerRe.exec(content)) {
            if (!isFrameworkEmail(m2[0]) && !seen[m2[0].toLowerCase()]) {
                seen[m2[0].toLowerCase()] = true;
                results.push(m2[0]);
            }
        }
    }

    return results;
}

// ==================== SECRET/KEY DETECTION ====================

var secretPatterns = [
    // AWS
    { name: "AWS Access Key ID", re: /(?:^|[^a-zA-Z0-9])(AKIA[0-9A-Z]{16})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "AWS Secret Access Key", re: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["']?([a-zA-Z0-9\/+=]{40})["']?/gi, sev: 4 },
    { name: "AWS Session Token", re: /(?:aws_session_token)\s*[=:]\s*["']?([a-zA-Z0-9\/+=]{100,})["']?/gi, sev: 4 },

    // Google
    { name: "Google API Key", re: /(?:^|[^a-zA-Z0-9])(AIza[0-9A-Za-z_\-]{35})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },
    { name: "Google OAuth Client Secret", re: /(?:client_secret|GOOGLE_SECRET)\s*[=:]\s*["']?([a-zA-Z0-9_\-]{24,})["']?/gi, sev: 4 },
    { name: "Google Cloud Service Account", re: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"/g, sev: 4 },
    { name: "Firebase Config", re: /(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId|appId)\s*:\s*["']([^"']{10,})["']/g, sev: 2 },

    // GitHub
    { name: "GitHub Personal Access Token", re: /(?:^|[^a-zA-Z0-9])(ghp_[a-zA-Z0-9]{36})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "GitHub OAuth Token", re: /(?:^|[^a-zA-Z0-9])(gho_[a-zA-Z0-9]{36})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "GitHub App Token", re: /(?:^|[^a-zA-Z0-9])((?:ghu|ghs|ghr)_[a-zA-Z0-9]{36})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "GitHub Fine-Grained Token", re: /(?:^|[^a-zA-Z0-9])(github_pat_[a-zA-Z0-9_]{82})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // GitLab
    { name: "GitLab Token", re: /(?:^|[^a-zA-Z0-9])(glpat-[a-zA-Z0-9_\-]{20,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "GitLab CI Token", re: /(?:^|[^a-zA-Z0-9])(glcbt-[a-zA-Z0-9_\-]{20,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // Slack
    { name: "Slack Bot Token", re: /(?:^|[^a-zA-Z0-9])(xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Slack User Token", re: /(?:^|[^a-zA-Z0-9])(xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Slack Webhook", re: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, sev: 3 },

    // Stripe
    { name: "Stripe Live Secret Key", re: /(?:^|[^a-zA-Z0-9])(sk_live_[a-zA-Z0-9]{24,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Stripe Live Publishable Key", re: /(?:^|[^a-zA-Z0-9])(pk_live_[a-zA-Z0-9]{24,})(?:[^a-zA-Z0-9]|$)/g, sev: 2 },
    { name: "Stripe Restricted Key", re: /(?:^|[^a-zA-Z0-9])(rk_live_[a-zA-Z0-9]{24,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // PayPal
    { name: "PayPal Braintree Token", re: /(?:access_token\$production\$)[a-zA-Z0-9]{16}\$[a-zA-Z0-9]{32}/g, sev: 4 },

    // Square
    { name: "Square Access Token", re: /(?:^|[^a-zA-Z0-9])(sq0atp-[a-zA-Z0-9_\-]{22,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Square OAuth Secret", re: /(?:^|[^a-zA-Z0-9])(sq0csp-[a-zA-Z0-9_\-]{43,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // Twilio
    { name: "Twilio API Key", re: /(?:^|[^a-zA-Z0-9])(SK[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },
    { name: "Twilio Auth Token", re: /(?:twilio_auth_token|TWILIO_AUTH)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, sev: 4 },

    // SendGrid
    { name: "SendGrid API Key", re: /(?:^|[^a-zA-Z0-9])(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // Mailgun
    { name: "Mailgun API Key", re: /(?:^|[^a-zA-Z0-9])(key-[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },

    // Heroku
    { name: "Heroku API Key", re: /(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*["']?([a-f0-9\-]{36})["']?/gi, sev: 4 },

    // npm
    { name: "npm Access Token", re: /(?:^|[^a-zA-Z0-9])(npm_[a-zA-Z0-9]{36})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "npm Auth Token", re: /\/\/registry\.npmjs\.org\/:_authToken=([a-f0-9\-]{36})/g, sev: 4 },

    // PyPI
    { name: "PyPI API Token", re: /(?:^|[^a-zA-Z0-9])(pypi-[a-zA-Z0-9_\-]{50,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // NuGet
    { name: "NuGet API Key", re: /(?:^|[^a-zA-Z0-9])(oy2[a-zA-Z0-9]{43})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },

    // Discord
    { name: "Discord Bot Token", re: /(?:^|[^a-zA-Z0-9])([MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Discord Webhook", re: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+/g, sev: 3 },

    // Telegram
    { name: "Telegram Bot Token", re: /(?:^|[^a-zA-Z0-9])([0-9]{8,10}:[a-zA-Z0-9_\-]{35})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },

    // Azure
    { name: "Azure Storage Key", re: /(?:AccountKey|azure_storage_key|AZURE_KEY)\s*[=:]\s*["']?([a-zA-Z0-9+\/=]{44,88})["']?/gi, sev: 4 },
    { name: "Azure Connection String", re: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+\/=]{44,88}/g, sev: 4 },

    // DigitalOcean
    { name: "DigitalOcean Token", re: /(?:^|[^a-zA-Z0-9])(dop_v1_[a-f0-9]{64})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "DigitalOcean Spaces Key", re: /(?:^|[^a-zA-Z0-9])(doo_v1_[a-f0-9]{64})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // Cloudflare
    { name: "Cloudflare API Token", re: /(?:cloudflare_api_token|CF_API_TOKEN)\s*[=:]\s*["']?([a-zA-Z0-9_\-]{40,})["']?/gi, sev: 4 },

    // Shopify
    { name: "Shopify Access Token", re: /(?:^|[^a-zA-Z0-9])(shpat_[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Shopify Custom App Token", re: /(?:^|[^a-zA-Z0-9])(shpca_[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },
    { name: "Shopify Private App Password", re: /(?:^|[^a-zA-Z0-9])(shppa_[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)/g, sev: 4 },

    // Datadog
    { name: "Datadog API Key", re: /(?:datadog_api_key|DD_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, sev: 3 },

    // Generic patterns
    { name: "Generic API Key", re: /(?:api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,64})["']/gi, sev: 2 },
    { name: "Generic Secret", re: /(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,64})["']/gi, sev: 3 },
    { name: "Generic Token", re: /(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{20,500})["']/gi, sev: 3 },
    { name: "Generic Password", re: /(?:password|passwd|pwd|pass)\s*[=:]\s*["']([^"']{4,64})["']/gi, sev: 3 },
    { name: "Authorization Header (Bearer)", re: /[Aa]uthorization['":\s]+[Bb]earer\s+([a-zA-Z0-9_\-\.]{20,500})/g, sev: 3 },
    { name: "Authorization Header (Basic)", re: /[Aa]uthorization['":\s]+[Bb]asic\s+([a-zA-Z0-9+\/=]{8,200})/g, sev: 3 },
    { name: "Credentials in URL", re: /https?:\/\/([a-zA-Z0-9._\-]+):([a-zA-Z0-9._\-!@#$%^&*]{3,})@[a-zA-Z0-9.\-]+/g, sev: 4 },

    // Database connection strings
    { name: "Database Connection String", re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp|rabbitmq):\/\/[a-zA-Z0-9._\-]+:[^@\s]{3,}@[a-zA-Z0-9.\-]+/g, sev: 4 },
    { name: "JDBC Connection String", re: /jdbc:[a-zA-Z0-9]+:\/\/[^\s"']+/g, sev: 3 },

    // JWT (full tokens in source code)
    { name: "JWT Token", re: /(?:^|[^a-zA-Z0-9])(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})(?:[^a-zA-Z0-9]|$)/g, sev: 3 },
];

// ==================== CRYPTO KEY / CERT DETECTION ====================

var cryptoPatterns = [
    { name: "RSA Private Key", re: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g, sev: 4 },
    { name: "DSA Private Key", re: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g, sev: 4 },
    { name: "EC Private Key", re: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g, sev: 4 },
    { name: "Private Key (Generic)", re: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, sev: 4 },
    { name: "Encrypted Private Key", re: /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----/g, sev: 3 },
    { name: "OpenSSH Private Key", re: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g, sev: 4 },
    { name: "PGP Private Key Block", re: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g, sev: 4 },
    { name: "PGP Message (encrypted data)", re: /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g, sev: 2 },
    { name: "RSA Public Key", re: /-----BEGIN RSA PUBLIC KEY-----[\s\S]*?-----END RSA PUBLIC KEY-----/g, sev: 1 },
    { name: "Public Key (Generic)", re: /-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g, sev: 1 },
    { name: "X.509 Certificate", re: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, sev: 1 },
    { name: "Certificate Request", re: /-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----/g, sev: 1 },
    { name: "PKCS7 Data", re: /-----BEGIN PKCS7-----[\s\S]*?-----END PKCS7-----/g, sev: 1 },
    { name: "SSH Public Key (RSA)", re: /ssh-rsa\s+[a-zA-Z0-9+\/=]{100,}/g, sev: 1 },
    { name: "SSH Public Key (Ed25519)", re: /ssh-ed25519\s+[a-zA-Z0-9+\/=]{40,}/g, sev: 1 },
    { name: "SSH Public Key (ECDSA)", re: /ecdsa-sha2-nistp\d+\s+[a-zA-Z0-9+\/=]{60,}/g, sev: 1 },
];

// ==================== SCAN FUNCTIONS ====================

function scanForSecrets(text) {
    var findings = [];

    for (var i = 0; i < secretPatterns.length; i++) {
        var p = secretPatterns[i];
        p.re.lastIndex = 0;
        var m;
        while (m = p.re.exec(text)) {
            var matchValue = m[1] || m[0];

            if (isFalsePositiveContext(text, m.index, matchValue)) continue;
            if (isKnownTestKey(matchValue)) continue;

            // skip very short generic matches
            if (p.name.indexOf("Generic") != -1 && matchValue.length < 8) continue;

            // skip passwords that are common defaults in docs
            if (p.name.indexOf("Password") != -1) {
                var lv = matchValue.toLowerCase();
                if (lv == "password" || lv == "pass" || lv == "changeme" ||
                    lv == "admin" || lv == "root" || lv == "test" ||
                    lv == "123456" || lv == "${" || lv.indexOf("{{") != -1) continue;
            }

            // for JWT, do basic structure validation
            if (p.name == "JWT Token") {
                var parts = matchValue.split(".");
                if (parts.length != 3) continue;
                if (parts[0].length < 10 || parts[1].length < 10) continue;
                // try decode header
                try {
                    var hdr = b642plain(parts[0].replace(/-/g, "+").replace(/_/g, "/"));
                    if (hdr.indexOf('"alg"') == -1 && hdr.indexOf('"typ"') == -1) continue;
                } catch(e) { continue; }
            }

            // for Google API keys, validate length
            if (p.name == "Google API Key" && matchValue.length != 39) continue;

            // for AWS keys, validate prefix
            if (p.name == "AWS Access Key ID" && matchValue.length != 20) continue;

            findings.push({
                type: "secret",
                name: p.name,
                value: matchValue.substring(0, 120),
                severity: p.sev,
                position: m.index
            });
        }
    }

    return findings;
}

function scanForCryptoKeys(text) {
    var findings = [];

    for (var i = 0; i < cryptoPatterns.length; i++) {
        var p = cryptoPatterns[i];
        p.re.lastIndex = 0;
        var m;
        while (m = p.re.exec(text)) {
            // skip if inside a base64 image or SVG
            if (isInsideBase64Image(text, m.index)) continue;

            var keyPreview = m[0].substring(0, 80);
            if (m[0].length > 80) keyPreview += "...(" + m[0].length + " bytes)";

            findings.push({
                type: "crypto",
                name: p.name,
                value: keyPreview,
                severity: p.sev,
                position: m.index
            });
        }
    }

    return findings;
}

function scanForJWTPayloads(text) {
    var findings = [];
    var jwtRe = /(?:^|[^a-zA-Z0-9])(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)(?:[^a-zA-Z0-9]|$)/g;
    var m;
    while (m = jwtRe.exec(text)) {
        var token = m[1];
        var parts = token.split(".");
        if (parts.length != 3) continue;
        if (isInsideBase64Image(text, m.index)) continue;

        try {
            var hdr = b642plain(parts[0].replace(/-/g, "+").replace(/_/g, "/"));
            var payload = b642plain(parts[1].replace(/-/g, "+").replace(/_/g, "/"));

            if (hdr.indexOf('"alg"') == -1) continue;

            var hdrObj, payObj;
            try { hdrObj = JSON.parse(hdr); } catch(e) { continue; }
            try { payObj = JSON.parse(payload); } catch(e) { continue; }

            var details = "Algorithm: " + (hdrObj.alg || "unknown");
            if (hdrObj.typ) details += ", Type: " + hdrObj.typ;

            // check for sensitive data in payload
            var sensitiveFields = [];
            var payStr = payload.toLowerCase();
            var sensitiveKeys = ["password", "secret", "private_key", "api_key", "apikey",
                "credit_card", "ssn", "token", "auth", "session"];
            for (var s = 0; s < sensitiveKeys.length; s++) {
                if (payStr.indexOf(sensitiveKeys[s]) != -1) {
                    sensitiveFields.push(sensitiveKeys[s]);
                }
            }

            // check expiry
            if (payObj.exp) {
                var now = Math.floor(Date.now() / 1000);
                if (payObj.exp < now) details += "[break]EXPIRED (exp: " + payObj.exp + ")";
                else details += "[break]Expires: " + new Date(payObj.exp * 1000).toISOString();
            }

            if (payObj.sub) details += "[break]Subject: " + payObj.sub;
            if (payObj.iss) details += "[break]Issuer: " + payObj.iss;
            if (payObj.email) details += "[break]Email: " + payObj.email;
            if (payObj.role || payObj.roles) details += "[break]Role: " + (payObj.role || JSON.stringify(payObj.roles));

            var sev = 2;
            if (sensitiveFields.length > 0) {
                sev = 3;
                details += "[break]Sensitive fields in payload: " + sensitiveFields.join(", ");
            }
            if (hdrObj.alg == "none" || hdrObj.alg == "None" || hdrObj.alg == "NONE") {
                sev = 4;
                details += "[break]CRITICAL: alg=none - token has no signature!";
            }
            if (hdrObj.alg == "HS256" && parts[2].length < 10) {
                sev = 3;
                details += "[break]WARNING: Very short signature - possible weak secret";
            }

            findings.push({
                type: "jwt",
                name: "JWT Token in Source",
                value: token.substring(0, 60) + "...",
                severity: sev,
                details: details,
                position: m.index
            });

        } catch(e) { continue; }
    }

    return findings;
}

function scanResponseHeaders(response) {
    var findings = [];
    var headerNames = ["X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Runtime", "X-Version", "X-Generator", "X-Drupal-Cache",
        "X-Request-Id", "X-Correlation-Id", "X-Amzn-Requestid",
        "X-Debug-Token", "X-Debug-Token-Link",
        "Set-Cookie", "X-Forwarded-For", "Via"];

    for (var i = 0; i < headerNames.length; i++) {
        var val = response.headerValue(headerNames[i]);
        if (!val) continue;

        // check cookies for secrets
        if (headerNames[i] == "Set-Cookie") {
            var cookieSecrets = scanForSecrets(val);
            for (var j = 0; j < cookieSecrets.length; j++) {
                cookieSecrets[j].name = "Secret in Set-Cookie: " + cookieSecrets[j].name;
                findings.push(cookieSecrets[j]);
            }

            // check for JWT in cookies
            var jwtInCookie = scanForJWTPayloads(val);
            for (var j = 0; j < jwtInCookie.length; j++) {
                jwtInCookie[j].name = "JWT in Cookie";
                findings.push(jwtInCookie[j]);
            }
        }

        // check debug headers
        if (headerNames[i] == "X-Debug-Token-Link" || headerNames[i] == "X-Debug-Token") {
            findings.push({
                type: "header",
                name: "Debug Header: " + headerNames[i],
                value: val.substring(0, 100),
                severity: 2,
                position: 0
            });
        }
    }

    // check for emails in headers
    var allHeaders = response.headersString || "";
    var headerEmails = extractAllEmails(allHeaders);
    for (var i = 0; i < headerEmails.length; i++) {
        findings.push({
            type: "email_header",
            name: "Email in HTTP Header",
            value: headerEmails[i],
            severity: 1,
            position: 0
        });
    }

    return findings;
}
