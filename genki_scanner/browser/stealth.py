"""
Stealth patches for Playwright browser.
Anti-fingerprint, WebDriver flag removal, navigator spoofing,
WebGL/Canvas noise, timezone/locale consistency, CF bypass.
"""

STEALTH_JS = """
// --- WebDriver flag removal ---
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
delete navigator.__proto__.webdriver;

// --- Chrome runtime mock ---
window.chrome = {
    runtime: {
        onConnect: { addListener: function() {} },
        onMessage: { addListener: function() {} },
        connect: function() { return { onMessage: { addListener: function() {} } }; },
        sendMessage: function() {},
        id: undefined,
    },
    loadTimes: function() { return {}; },
    csi: function() { return {}; },
};

// --- Permissions API spoof ---
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

// --- Plugin/MimeType arrays ---
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
            { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
        ];
        plugins.refresh = function() {};
        return plugins;
    }
});

Object.defineProperty(navigator, 'mimeTypes', {
    get: () => {
        const mimes = [
            { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: navigator.plugins[0] },
        ];
        return mimes;
    }
});

// --- Languages ---
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'language', { get: () => 'en-US' });

// --- Hardware concurrency ---
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

// --- Platform ---
Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });

// --- WebGL vendor/renderer spoof ---
const getParameterProto = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Google Inc. (NVIDIA)';
    if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)';
    return getParameterProto.call(this, param);
};

const getParameterProto2 = WebGL2RenderingContext.prototype.getParameter;
WebGL2RenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Google Inc. (NVIDIA)';
    if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)';
    return getParameterProto2.call(this, param);
};

// --- Canvas fingerprint noise ---
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (this.width === 0 && this.height === 0) return origToDataURL.apply(this, arguments);
    const ctx = this.getContext('2d');
    if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = imageData.data[i] ^ (1);
        }
        ctx.putImageData(imageData, 0, 0);
    }
    return origToDataURL.apply(this, arguments);
};

// --- Iframe contentWindow ---
try {
    Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
        get: function() {
            return window;
        }
    });
} catch(e) {}

// --- Connection rtt ---
if (navigator.connection) {
    Object.defineProperty(navigator.connection, 'rtt', { get: () => 50 });
}

// --- Headless detection bypass ---
Object.defineProperty(document, 'hidden', { get: () => false });
Object.defineProperty(document, 'visibilityState', { get: () => 'visible' });

// --- Notification constructor check ---
try {
    window.Notification = {
        permission: 'default',
        requestPermission: function() { return Promise.resolve('default'); },
    };
} catch(e) {}
"""

CF_TURNSTILE_WAIT_JS = """
async function waitForTurnstile(timeout = 30000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        // Check if Turnstile challenge iframe exists
        const frames = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
        if (frames.length === 0) {
            // No challenge present or already solved
            const cfRay = document.querySelector('meta[name="cf-ray"]');
            if (cfRay || !document.querySelector('#challenge-running')) {
                return true;
            }
        }
        await new Promise(r => setTimeout(r, 1000));
    }
    return false;
}
"""

VIEWPORT_PROFILES = {
    "desktop_1080": {"width": 1920, "height": 1080},
    "desktop_1440": {"width": 2560, "height": 1440},
    "laptop": {"width": 1366, "height": 768},
    "macbook": {"width": 1440, "height": 900},
    "macbook_pro": {"width": 1680, "height": 1050},
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
]
