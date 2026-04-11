import express from "express";
import "dotenv/config";
import OpenAI from "openai";
import sqlite3pkg from "sqlite3";
import bcrypt from "bcrypt";
import session from "express-session";
import https from "https";
import http from "http";
import fs from "fs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

const sqlite3 = sqlite3pkg.verbose();
const serverApp = express();

// Read TLS cert early so we can use it in session config
const certPath = "/etc/letsencrypt/live/chatty.mk";
let tlsOptions = null;
try {
    tlsOptions = {
        cert: fs.readFileSync(`${certPath}/fullchain.pem`),
        key:  fs.readFileSync(`${certPath}/privkey.pem`),
    };
} catch (err) {
    console.warn("⚠️  TLS cert not found — falling back to HTTP only:", err.message);
}

// ──────────────────────────────────────────────────────────────────
// SECURITY MIDDLEWARE  (OWASP Top 10 coverage)
// ──────────────────────────────────────────────────────────────────

// 1. Trust proxy (needed for correct IP behind nginx / reverse proxy)
serverApp.set("trust proxy", 1);

// 2. Helmet — sets X-Frame-Options, X-Content-Type-Options, HSTS,
//    Referrer-Policy, Permissions-Policy, and a strict CSP.
serverApp.use((req, res, next) => {
    // Generate a per-request nonce for inline scripts (CSP)
    res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
    next();
});

serverApp.use(helmet({
    // HSTS — force HTTPS for 1 year, include subdomains
    hsts: tlsOptions ? {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    } : false,

    // Content Security Policy
    contentSecurityPolicy: {
        directives: {
            defaultSrc:     ["'self'"],
            scriptSrc: [
                "'self'",
                // Ad networks
                "https://pl29124663.profitablecpmratenetwork.com",
                "https://pl29124765.profitablecpmratenetwork.com",
                "https://www.highperformanceformat.com",
                // Fonts & Tailwind (homepage uses CDN)
                "https://cdn.tailwindcss.com",
                (req, res) => `'nonce-${res.locals.cspNonce}'`,
            ],
            styleSrc:       ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com"],
            fontSrc:        ["'self'", "https://fonts.gstatic.com"],
            imgSrc:         ["'self'", "data:", "blob:", "https:"],
            connectSrc:     ["'self'"],
            frameSrc:       ["'none'"],
            objectSrc:      ["'none'"],
            baseUri:        ["'self'"],
            formAction:     ["'self'"],
            upgradeInsecureRequests: tlsOptions ? [] : null,
        },
    },

    // Prevent MIME-type sniffing
    noSniff: true,

    // Deny framing (clickjacking)
    frameguard: { action: "deny" },

    // Hide Express fingerprint
    hidePoweredBy: true,

    // XSS filter for older browsers
    xssFilter: true,

    // Referrer policy
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));

// 3. Rate limiters — brute-force / DoS protection (OWASP A07)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 20,                     // 20 attempts per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many attempts. Please try again in 15 minutes." },
    skipSuccessfulRequests: true,
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,        // 1 minute
    max: 60,                     // 60 requests/min per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Rate limit exceeded. Please slow down." },
});

const imageLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,                      // 5 image generations/min
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Image generation rate limit reached. Please wait a moment." },
});

// Apply auth limiter to login/signup
serverApp.use("/login", authLimiter);
serverApp.use("/signup", authLimiter);

// Apply API limiter to all API routes
serverApp.use("/api/", apiLimiter);

// 4. Body size limits — prevent large payload attacks
serverApp.use(express.urlencoded({ extended: true, limit: "2mb" }));
serverApp.use(express.json({ limit: "15mb" }));  // 15mb for image uploads
serverApp.use(express.static("public"));

// 5. Sessions — hardened (OWASP A02)
serverApp.use(
    session({
        secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex"),
        resave: false,
        saveUninitialized: false,
        name: "sid",             // Don't leak "connect.sid"
        cookie: {
            secure:   !!tlsOptions,
            httpOnly: true,       // Prevent JS access to cookie
            sameSite: "strict",   // CSRF mitigation
            maxAge:   7 * 24 * 60 * 60 * 1000,  // 7 days
        },
    })
);

// 6. Security headers not covered by helmet
serverApp.use((req, res, next) => {
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    next();
});

// ──────────────────────────────────────────────────────────────────
// INPUT SANITISATION HELPERS
// ──────────────────────────────────────────────────────────────────

// Strip characters that have no place in usernames
function sanitizeUsername(username) {
    if (typeof username !== "string") return "";
    return username.trim().replace(/[^a-zA-Z0-9_\-\.]/g, "").slice(0, 32);
}

// Validate password constraints
function validatePassword(password) {
    if (typeof password !== "string") return false;
    return password.length >= 8 && password.length <= 128;
}

// Generic string truncation / trim
function sanitizeString(str, maxLen = 1000) {
    if (typeof str !== "string") return "";
    return str.trim().slice(0, maxLen);
}

// ──────────────────────────────────────────────────────────────────
// PATHS
// ──────────────────────────────────────────────────────────────────


import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------- 
// LOGIN PROTECTION
// ----------------------
function requireLogin(req, res, next) {
    if (!req.session.user) {
        if ((req.originalUrl || "").startsWith("/api/")) {
            return res.status(401).json({ error: "Unauthorized. Please log in again." });
        }
        return res.redirect("/login.html");
    }
    next();
}

// ----------------------
// DATABASE SETUP
// ----------------------
const db = new sqlite3.Database("./users.db", (err) => {
    if (err) console.log(err);
    console.log("Connected to SQLite DB");
});

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
`);

db.run(`
    CREATE TABLE IF NOT EXISTS chat_conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT,
        model TEXT,
        messages TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

// shared chats (public links)
db.run(`
    CREATE TABLE IF NOT EXISTS shared_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        title TEXT,
        model TEXT,
        messages TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

// starred messages
db.run(`
    CREATE TABLE IF NOT EXISTS starred_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        message_index INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (chat_id) REFERENCES chat_conversations(id)
    )
`);

// chat settings (system prompt, temperature, etc)
db.run(`
    CREATE TABLE IF NOT EXISTS chat_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL UNIQUE,
        system_prompt TEXT,
        temperature REAL DEFAULT 0.7,
        max_tokens INTEGER DEFAULT 2048,
        top_p REAL DEFAULT 1.0,
        FOREIGN KEY (chat_id) REFERENCES chat_conversations(id)
    )
`);

// user preferences (theme, accent, font size, etc)
db.run(`
    CREATE TABLE IF NOT EXISTS user_preferences (
        user_id INTEGER PRIMARY KEY,
        accent_color TEXT DEFAULT '#7c6cf8',
        font_size TEXT DEFAULT 'md',
        bubble_style TEXT DEFAULT 'rounded',
        ai_name TEXT DEFAULT 'AI',
        sidebar_width INTEGER DEFAULT 252,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

// add banned column to users if not present (migration-safe)
db.run(`ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0`, () => {});

// ----------------------
// ADMIN GUARD
// ----------------------
const ADMIN_USERNAME = "rvnaw4y";

function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.username !== ADMIN_USERNAME) {
        if ((req.originalUrl || "").startsWith("/api/")) {
            return res.status(403).json({ error: "Forbidden" });
        }
        return res.redirect("/chat");
    }
    next();
}

// ----------------------
// ADS
// ----------------------

// Popunder — loads once, fires on first click (global on public pages)
const AD_POPUNDER = `<script src="https://pl29124663.profitablecpmratenetwork.com/90/4a/1c/904a1c9c701444bada023cd278274bae.js"><\/script>`;

// Banner 468×60
const AD_BANNER = `
<div class="ad-banner-wrap">
  <script async="async" data-cfasync="false" src="https://pl29124765.profitablecpmratenetwork.com/abe92782ed9ee894bda77e5c78bb5bcf/invoke.js"><\/script>
  <div id="container-abe92782ed9ee894bda77e5c78bb5bcf"></div>
</div>`;

// Inline/native unit
const AD_INLINE = `
<div class="ad-inline-wrap">
  <script>
    atOptions = { 'key':'fd4b6c44fce1c929dcabdf067c940ad6','format':'iframe','height':60,'width':468,'params':{} };
  <\/script>
  <script src="https://www.highperformanceformat.com/fd4b6c44fce1c929dcabdf067c940ad6/invoke.js"><\/script>
</div>`;

// Shared CSS for ad containers (injected once into pages that show ads)
const AD_STYLES = `<style>
.ad-banner-wrap,.ad-inline-wrap{display:flex;justify-content:center;align-items:center;width:100%;padding:8px 0;background:transparent;overflow:hidden}
.ad-banner-wrap{border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:0}
.ad-inline-wrap{border-top:1px solid rgba(255,255,255,0.06);margin-top:0;padding:12px 0}
@media(max-width:500px){.ad-banner-wrap,.ad-inline-wrap{transform:scale(0.72);transform-origin:center}}
</style>`;

const SITE_URL    = "https://chatty.mk";
const SITE_NAME   = "Chatty";
const DEFAULT_IMG = `${SITE_URL}/img/og-image.png`;

const PAGE_META = {
    "/": {
        title:       "Chatty — Free AI Chat with Multiple Models",
        description: "Chat with Llama, Mistral, Gemma, DeepSeek and more for free. Chatty is a fast, private AI chat app powered by NVIDIA NIM.",
        keywords:    "free AI chat, Llama AI, Mistral AI, NVIDIA NIM, AI chatbot, free chatbot, multi-model AI, chatty.mk",
        canonical:   `${SITE_URL}/`,
        index:       true,
        jsonld: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebApplication",
            name: SITE_NAME,
            url: SITE_URL,
            description: "Free multi-model AI chat app powered by NVIDIA NIM.",
            applicationCategory: "Artificial Intelligence",
            operatingSystem: "Any",
            offers: { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
            featureList: ["Multiple AI models", "AI image generation", "Chat history", "Shareable conversations", "Free to use"],
        }),
    },
    "/signup": {
        title:       "Sign Up Free — Chatty",
        description: "Create a free Chatty account and start chatting with multiple AI models instantly. No credit card required.",
        keywords:    "sign up free AI, free AI account, Chatty signup, chatty.mk",
        canonical:   `${SITE_URL}/signup`,
        index:       true,
    },
    "/login": {
        title:       "Log In — Chatty",
        description: "Sign in to Chatty and start chatting with free AI models including Llama, Mistral, and more.",
        canonical:   `${SITE_URL}/login`,
        index:       false,
    },
    "/chat": {
        title:       "Chat — Chatty",
        description: "Your AI chat session on Chatty.",
        canonical:   `${SITE_URL}/chat`,
        index:       false,
    },
    "/privacy": {
        title:       "Privacy Policy — Chatty",
        description: "Read Chatty's privacy policy. We respect your data and keep your conversations private.",
        canonical:   `${SITE_URL}/privacy`,
        index:       true,
    },
    "/tos": {
        title:       "Terms of Service — Chatty",
        description: "Read the terms of service for Chatty, the free multi-model AI chat platform.",
        canonical:   `${SITE_URL}/tos`,
        index:       true,
    },
    "/credits": {
        title:       "Credits — Chatty",
        description: "Credits and acknowledgements for Chatty, powered by NVIDIA NIM and open-source AI models.",
        canonical:   `${SITE_URL}/credits`,
        index:       true,
    },
    "/shared": {
        title:       "Shared Conversation — Chatty",
        description: "View a shared AI conversation from Chatty.",
        canonical:   `${SITE_URL}/shared`,
        index:       true,
    },
    "/admin": {
        title:       "Admin — Chatty",
        description: "Chatty admin panel.",
        canonical:   `${SITE_URL}/admin`,
        index:       false,
    },
};

function buildMetaTags(route, extraTitle) {
    const m = PAGE_META[route] || {
        title: `${SITE_NAME}`,
        description: "Free AI chat powered by NVIDIA NIM.",
        canonical: `${SITE_URL}${route}`,
        index: false,
    };
    const title = extraTitle || m.title;
    const robots = m.index ? "index, follow" : "noindex, nofollow";
    const kw = m.keywords ? `\n  <meta name="keywords" content="${m.keywords}" />` : "";
    const ld = m.jsonld ? `\n  <script type="application/ld+json">${m.jsonld}</script>` : "";

    return `<title>${title}</title>
  <meta name="description" content="${m.description}" />${kw}
  <meta name="robots" content="${robots}" />
  <link rel="canonical" href="${m.canonical}" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="${SITE_NAME}" />
  <meta property="og:title" content="${title}" />
  <meta property="og:description" content="${m.description}" />
  <meta property="og:url" content="${m.canonical}" />
  <meta property="og:image" content="${DEFAULT_IMG}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${title}" />
  <meta name="twitter:description" content="${m.description}" />
  <meta name="twitter:image" content="${DEFAULT_IMG}" />${ld}`;
}

// Read a file, inject meta tags + optional ads, send it
function sendWithSEO(res, filePath, route, extraTitle, adOpts = {}) {
    fs.readFile(filePath, "utf8", (err, html) => {
        if (err) return res.status(404).send("Not found");
        // Replace existing <title>...</title> + anything we injected before
        html = html.replace(/<title>[\s\S]*?<\/title>/, "");
        // Strip any previously injected meta blocks
        html = html.replace(/\s*<meta name="description"[^>]*>/g, "");
        html = html.replace(/\s*<meta name="keywords"[^>]*>/g, "");
        html = html.replace(/\s*<meta name="robots"[^>]*>/g, "");
        html = html.replace(/\s*<link rel="canonical"[^>]*>/g, "");
        html = html.replace(/\s*<meta property="og:[^"]*"[^>]*>/g, "");
        html = html.replace(/\s*<meta name="twitter:[^"]*"[^>]*>/g, "");
        html = html.replace(/\s*<script type="application\/ld\+json">[\s\S]*?<\/script>/g, "");
        // Inject after <head>
        html = html.replace("<head>", `<head>\n  ${buildMetaTags(route, extraTitle)}`);

        // Inject ads
        if (adOpts.popunder) {
            html = html.replace("</head>", `${AD_POPUNDER}\n${AD_STYLES}\n</head>`);
        }
        if (adOpts.bannerTop) {
            // After opening <body> tag
            html = html.replace(/<body[^>]*>/, (match) => `${match}\n${AD_BANNER}`);
        }
        if (adOpts.bannerBottom) {
            html = html.replace("</body>", `${AD_INLINE}\n</body>`);
        }

        res.setHeader("Content-Type", "text/html");
        res.send(html);
    });
}

// ----------------------
// ROUTES
// ----------------------

// Home
serverApp.get("/", (req, res) => {
    sendWithSEO(res, path.join(__dirname, "public", "index.html"), "/", null,
        { popunder: true, bannerTop: true, bannerBottom: true });
});

// Chat (PROTECTED)
serverApp.get("/chat", requireLogin, (req, res) => {
    sendWithSEO(res, path.join(__dirname, "public", "chat.html"), "/chat");
});

// Signup
serverApp.post("/signup", async (req, res) => {
    const username = sanitizeUsername(req.body.username || "");
    const password = req.body.password || "";

    if (!username) return res.status(400).send("Invalid username. Use letters, numbers, _ - . only (max 32 chars).");
    if (!validatePassword(password)) return res.status(400).send("Password must be 8–128 characters.");

    const hashed = await bcrypt.hash(password, 12);

    db.run(
        `INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, hashed],
        function (err) {
            if (err) return res.status(409).send("Username already taken.");
            res.send("Signup successful! <a href='/login.html'>Login here</a>");
        }
    );
});

// Login
serverApp.post("/login", (req, res) => {
    const username = sanitizeUsername(req.body.username || "");
    const password = req.body.password || "";

    if (!username || !password) return res.status(400).send("Missing username or password.");

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        async (err, row) => {
            // Always run bcrypt to prevent timing attacks even if user not found
            const dummyHash = "$2b$12$invalidhashfortimingxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            const match = await bcrypt.compare(password, row ? row.password : dummyHash);

            if (!row || !match) return res.status(401).send("Invalid username or password.");
            if (row.banned) return res.status(403).send("Your account has been suspended.");

            // Regenerate session on login to prevent session fixation (OWASP A07)
            req.session.regenerate((regenerateErr) => {
                if (regenerateErr) return res.status(500).send("Session error. Please try again.");
                req.session.user = { id: row.id, username: row.username };
                res.redirect("/chat");
            });
        }
    );
});

// ----------------------
// NVIDIA NIM ROUTES
// ----------------------
const openai = new OpenAI({
    baseURL: "https://integrate.api.nvidia.com/v1",
    apiKey: process.env.NVIDIA_API_KEY,
});

// Curated list of free NVIDIA NIM models
// vision:true = supports image input
const NVIDIA_MODELS = [
    { id: "meta/llama-3.3-70b-instruct",          label: "Llama 3.3 70B",            vision: false },
    { id: "meta/llama-3.1-8b-instruct",           label: "Llama 3.1 8B",             vision: false },
    { id: "meta/llama-3.2-3b-instruct",           label: "Llama 3.2 3B",             vision: false },
    { id: "meta/llama-3.2-11b-vision-instruct",   label: "Llama 3.2 11B Vision 👁",  vision: true  },
    { id: "meta/llama-3.2-90b-vision-instruct",   label: "Llama 3.2 90B Vision 👁",  vision: true  },
    { id: "mistralai/mistral-7b-instruct-v0.3",   label: "Mistral 7B",               vision: false },
    { id: "mistralai/mixtral-8x7b-instruct-v0.1", label: "Mixtral 8x7B",             vision: false },
    { id: "mistralai/mistral-nemo",                label: "Mistral NeMo 12B",         vision: false },
    { id: "google/gemma-2-9b-it",                 label: "Gemma 2 9B",               vision: false },
    { id: "google/gemma-2-27b-it",                label: "Gemma 2 27B",              vision: false },
    { id: "nvidia/llama-3.1-nemotron-70b-instruct", label: "Nemotron 70B",           vision: false },
    { id: "deepseek-ai/deepseek-r1",              label: "DeepSeek R1",              vision: false },
    { id: "microsoft/phi-3-medium-128k-instruct", label: "Phi-3 Medium 128k",        vision: false },
    { id: "microsoft/phi-3-mini-128k-instruct",   label: "Phi-3 Mini 128k",          vision: false },
    { id: "qwen/qwen2-7b-instruct",               label: "Qwen2 7B",                 vision: false },
];

// Per-model memory (dynamically keyed by model id)
let chatMemory = {};

function toUserMessageContent(message) {
    return typeof message === "string" ? message.trim() : "";
}

function normalizeAssistantReply(reply) {
    if (typeof reply === "string") return reply;
    if (Array.isArray(reply)) {
        const text = reply
            .map((part) => {
                if (typeof part === "string") return part;
                if (part && typeof part === "object" && part.type === "text") return part.text || "";
                return "";
            })
            .join("\n")
            .trim();
        return text || "No response received";
    }
    if (reply && typeof reply === "object") return JSON.stringify(reply);
    return "No response received";
}

// Retry logic with exponential backoff
async function makeAPICall(model, messages, temperature, maxTokens, topP, retries = 3) {
    for (let attempt = 0; attempt < retries; attempt++) {
        try {
            const completion = await openai.chat.completions.create({
                model,
                messages,
                temperature: temperature !== undefined ? temperature : 0.7,
                max_tokens: maxTokens !== undefined ? maxTokens : 2048,
                top_p: topP !== undefined ? topP : 1.0,
            });
            return completion.choices[0].message.content;
        } catch (err) {
            const status = err.status;
            if (status === 429 && attempt < retries - 1) {
                const waitTime = Math.pow(2, attempt) * 1000;
                console.log(`Rate limited. Retrying in ${waitTime}ms... (Attempt ${attempt + 1}/${retries})`);
                await new Promise(resolve => setTimeout(resolve, waitTime));
                continue;
            }
            if (status === 401 || status === 403) {
                throw new Error("Authentication failed. Please check your NVIDIA_API_KEY in the .env file.");
            }
            if (attempt === retries - 1) throw err;
        }
    }
}

// generic chat route – handles any model string sent in the body
serverApp.post("/api/chat", requireLogin, async (req, res) => {
    const { message, reset, model, temperature, maxTokens, topP, systemPrompt, imageBase64, imageMimeType } = req.body;

    if (!model) {
        return res.status(400).json({ reply: "Model not specified" });
    }

    if (!chatMemory[model]) chatMemory[model] = [];

    try {
        if (reset) {
            chatMemory[model] = [];
            return res.json({ reply: "Memory cleared!" });
        }

        const normalizedMessage = typeof message === "string" ? message.trim() : "";
        if (!normalizedMessage && !imageBase64) {
            return res.status(400).json({ reply: "Message is empty" });
        }

        // Build content — plain text or multipart (text + image) for vision models
        let userContent;
        if (imageBase64 && imageMimeType) {
            userContent = [];
            if (normalizedMessage) {
                userContent.push({ type: "text", text: normalizedMessage });
            }
            userContent.push({
                type: "image_url",
                image_url: { url: `data:${imageMimeType};base64,${imageBase64}` },
            });
        } else {
            userContent = toUserMessageContent(normalizedMessage);
        }

        chatMemory[model].push({ role: "user", content: userContent });

        const messages = systemPrompt
            ? [{ role: "system", content: systemPrompt }, ...chatMemory[model]]
            : chatMemory[model];

        const rawReply = await makeAPICall(model, messages, temperature, maxTokens, topP);
        const reply = normalizeAssistantReply(rawReply);
        chatMemory[model].push({ role: "assistant", content: rawReply });

        res.json({ reply });
    } catch (err) {
        console.error("API Error:", err.message);
        
        let userMessage = "Error contacting AI :(";
        
        if (err.message.includes("data policy")) {
            userMessage = err.message;
        } else if (err.message.includes("Authentication")) {
            userMessage = err.message;
        } else if (err.status === 429) {
            userMessage = "⏳ Rate limited. Please wait a moment and try again.";
        } else if (err.status === 404) {
            userMessage = "❌ Model not found or unavailable. Try selecting a different model.";
        } else if (err.message && (err.message.includes("vision") || err.message.includes("image"))) {
            userMessage = "❌ This model doesn't support image uploads. Try a vision-capable model.";
        }
        
        res.status(err.status || 500).json({ reply: userMessage });
    }
});



// ----------------------
// MODEL LISTING
// ----------------------

serverApp.get("/api/models", requireLogin, (req, res) => {
    // Check if admin has saved a custom model list
    db.get(`SELECT accent_color FROM user_preferences WHERE user_id = -999`, [], (err, row) => {
        if (!err && row && row.accent_color) {
            try {
                const models = JSON.parse(row.accent_color);
                return res.json(models);
            } catch {}
        }
        // Fall back to hardcoded curated list
        res.json(NVIDIA_MODELS);
    });
});

// ----------------------
// CHAT HISTORY ROUTES
// ----------------------

// Save chat conversation
serverApp.post("/api/save-chat", requireLogin, (req, res) => {
    const { title, model, messages } = req.body;
    const userId = req.session.user.id;

    db.run(
        `INSERT INTO chat_conversations (user_id, title, model, messages) VALUES (?, ?, ?, ?)`,
        [userId, title, model, JSON.stringify(messages)],
        function (err) {
            if (err) {
                console.error("Save error:", err);
                return res.status(500).json({ error: "Could not save chat" });
            }
            res.json({ id: this.lastID, message: "Chat saved!" });
        }
    );
});

// Update chat conversation
serverApp.put("/api/chat/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const { title, messages } = req.body;
    const userId = req.session.user.id;

    db.run(
        `UPDATE chat_conversations SET title = ?, messages = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
        [title, JSON.stringify(messages), chatId, userId],
        function (err) {
            if (err) {
                console.error("Update error:", err);
                return res.status(500).json({ error: "Could not update chat" });
            }
            res.json({ message: "Chat updated!" });
        }
    );
});

// Get all chats for user
serverApp.get("/api/chats", requireLogin, (req, res) => {
    const userId = req.session.user.id;

    db.all(
        `SELECT id, title, model, created_at, updated_at FROM chat_conversations WHERE user_id = ? ORDER BY updated_at DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error("Fetch error:", err);
                return res.status(500).json({ error: "Could not fetch chats" });
            }
            res.json(rows || []);
        }
    );
});

// Get specific chat with messages
serverApp.get("/api/chat/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const userId = req.session.user.id;

    db.get(
        `SELECT * FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        (err, row) => {
            if (err || !row) {
                return res.status(404).json({ error: "Chat not found" });
            }
            res.json({
                ...row,
                messages: JSON.parse(row.messages)
            });
        }
    );
});

// Delete chat
serverApp.delete("/api/chat/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const userId = req.session.user.id;

    db.run(
        `DELETE FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        function (err) {
            if (err) {
                console.error("Delete error:", err);
                return res.status(500).json({ error: "Could not delete chat" });
            }
            res.json({ message: "Chat deleted!" });
        }
    );
});

// ----------------------
// SHARING ROUTES
// ----------------------

// serve the shared chat page (no login required)
serverApp.get("/shared/:token", (req, res) => {
    sendWithSEO(res, path.join(__dirname, "public", "shared.html"), "/shared", null,
        { popunder: true, bannerTop: true, bannerBottom: true });
});

// create a public share link for a chat
serverApp.post("/api/share-chat", requireLogin, (req, res) => {
    const { title, model, messages } = req.body;
    const token = Math.random().toString(36).substring(2, 10);

    db.run(
        `INSERT INTO shared_chats (token, title, model, messages) VALUES (?, ?, ?, ?)`,
        [token, title, model, JSON.stringify(messages)],
        function (err) {
            if (err) {
                console.error("Share error:", err);
                return res.status(500).json({ error: "Could not create share link" });
            }
            const url = `${req.protocol}://${req.get("host")}/shared/${token}`;
            res.json({ url });
        }
    );
});

// return shared chat data as JSON
serverApp.get("/api/shared/:token", (req, res) => {
    const { token } = req.params;
    db.get(
        `SELECT title, model, messages FROM shared_chats WHERE token = ?`,
        [token],
        (err, row) => {
            if (err || !row) return res.status(404).json({ error: "Not found" });
            res.json({
                title: row.title,
                model: row.model,
                messages: JSON.parse(row.messages),
            });
        }
    );
});

// ----------------------
// CHAT SETTINGS ROUTES
// ----------------------

// Save/update chat settings
serverApp.post("/api/chat-settings/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const { systemPrompt, temperature, maxTokens, topP } = req.body;
    const userId = req.session.user.id;

    // First verify user owns this chat
    db.get(
        `SELECT id FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        (err, row) => {
            if (err || !row) {
                return res.status(403).json({ error: "Chat not found or unauthorized" });
            }

            db.run(
                `INSERT OR REPLACE INTO chat_settings (chat_id, system_prompt, temperature, max_tokens, top_p)
                 VALUES (?, ?, ?, ?, ?)`,
                [chatId, systemPrompt, temperature || 0.7, maxTokens || 2048, topP || 1.0],
                function (err) {
                    if (err) {
                        return res.status(500).json({ error: "Could not save settings" });
                    }
                    res.json({ message: "Settings saved!" });
                }
            );
        }
    );
});

// Get chat settings
serverApp.get("/api/chat-settings/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const userId = req.session.user.id;

    db.get(
        `SELECT chat_conversations.id FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        (err, row) => {
            if (err || !row) {
                return res.status(403).json({ error: "Chat not found or unauthorized" });
            }

            db.get(
                `SELECT system_prompt, temperature, max_tokens, top_p FROM chat_settings WHERE chat_id = ?`,
                [chatId],
                (err, settings) => {
                    if (err) {
                        return res.status(500).json({ error: "Could not fetch settings" });
                    }
                    res.json(settings || { temperature: 0.7, max_tokens: 2048, top_p: 1.0 });
                }
            );
        }
    );
});

// ----------------------
// STARRED MESSAGES ROUTES
// ----------------------

// Star a message
serverApp.post("/api/starred", requireLogin, (req, res) => {
    const { chatId, messageIndex } = req.body;
    const userId = req.session.user.id;

    db.get(
        `SELECT id FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        (err, row) => {
            if (err || !row) {
                return res.status(403).json({ error: "Chat not found or unauthorized" });
            }

            db.run(
                `INSERT INTO starred_messages (chat_id, message_index) VALUES (?, ?)`,
                [chatId, messageIndex],
                function (err) {
                    if (err) {
                        return res.status(500).json({ error: "Could not star message" });
                    }
                    res.json({ id: this.lastID, message: "Message starred!" });
                }
            );
        }
    );
});

// Unstar a message
serverApp.delete("/api/starred/:messageId", requireLogin, (req, res) => {
    const { messageId } = req.params;
    const userId = req.session.user.id;

    db.run(
        `DELETE FROM starred_messages 
         WHERE id = ? AND chat_id IN (SELECT id FROM chat_conversations WHERE user_id = ?)`,
        [messageId, userId],
        function (err) {
            if (err) {
                return res.status(500).json({ error: "Could not unstar message" });
            }
            res.json({ message: "Message unstarred!" });
        }
    );
});

// Get starred messages for a chat
serverApp.get("/api/starred/:chatId", requireLogin, (req, res) => {
    const { chatId } = req.params;
    const userId = req.session.user.id;

    db.get(
        `SELECT id FROM chat_conversations WHERE id = ? AND user_id = ?`,
        [chatId, userId],
        (err, row) => {
            if (err || !row) {
                return res.status(403).json({ error: "Chat not found or unauthorized" });
            }

            db.all(
                `SELECT id, message_index FROM starred_messages WHERE chat_id = ? ORDER BY message_index`,
                [chatId],
                (err, rows) => {
                    if (err) {
                        return res.status(500).json({ error: "Could not fetch starred messages" });
                    }
                    res.json(rows || []);
                }
            );
        }
    );
});

// ----------------------
// SEARCH ROUTES
// ----------------------

// Search conversations
serverApp.get("/api/search", requireLogin, (req, res) => {
    const { q } = req.query;
    const userId = req.session.user.id;

    if (!q || q.trim().length === 0) {
        return res.json([]);
    }

    const searchTerm = `%${q}%`;

    db.all(
        `SELECT id, title, model, created_at, updated_at FROM chat_conversations 
         WHERE user_id = ? AND (title LIKE ? OR messages LIKE ?)
         ORDER BY updated_at DESC LIMIT 20`,
        [userId, searchTerm, searchTerm],
        (err, rows) => {
            if (err) {
                console.error("Search error:", err);
                return res.status(500).json({ error: "Could not search chats" });
            }
            res.json(rows || []);
        }
    );
});

// ----------------------
// IMAGE GENERATION (NVIDIA NIM - Stable Diffusion XL)
// ----------------------
serverApp.post("/api/generate-image", requireLogin, imageLimiter, async (req, res) => {
    const { prompt, width = 1024, height = 1024 } = req.body;
    if (!prompt || !prompt.trim()) {
        return res.status(400).json({ error: "Prompt is required" });
    }
    if (!process.env.NVIDIA_API_KEY) {
        return res.status(500).json({ error: "NVIDIA_API_KEY not set in .env file. Get a free key at build.nvidia.com" });
    }

    const authHeaders = {
        "Authorization": `Bearer ${process.env.NVIDIA_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
    };

    try {
        // NVIDIA NIM flux-schnell — returns 200 sync or 202 async w/ polling
        const initRes = await fetch("https://integrate.api.nvidia.com/v1/images/generations", {
            method: "POST",
            headers: authHeaders,
            body: JSON.stringify({
                model: "black-forest-labs/flux-schnell",
                prompt: prompt.trim(),
                n: 1,
                width: parseInt(width),
                height: parseInt(height),
                response_format: "b64_json",
            }),
        });

        if (initRes.status === 401 || initRes.status === 403) {
            return res.status(401).json({ error: "Invalid NVIDIA API key. Get a free key at build.nvidia.com" });
        }
        if (initRes.status === 402) {
            return res.status(402).json({ error: "NVIDIA free credits exhausted. Check build.nvidia.com" });
        }
        if (initRes.status === 400 || initRes.status === 422) {
            const t = await initRes.text().catch(() => "");
            console.error("NVIDIA bad request:", t);
            return res.status(400).json({ error: "Invalid prompt or parameters. Try a different prompt." });
        }

        // Helper to extract image from a parsed response body
        async function extractImage(data) {
            const b64 = data?.data?.[0]?.b64_json;
            if (b64) return b64;
            const url = data?.data?.[0]?.url;
            if (url) {
                const imgRes = await fetch(url);
                const buf = await imgRes.arrayBuffer();
                return Buffer.from(buf).toString("base64");
            }
            return null;
        }

        // 200 — synchronous response
        if (initRes.status === 200) {
            const data = await initRes.json();
            const b64 = await extractImage(data);
            if (b64) return res.json({ imageBase64: b64, mimeType: "image/png" });
            return res.status(502).json({ error: "No image in response from NVIDIA API" });
        }

        // 202 — async, poll until done
        if (initRes.status === 202) {
            const initData = await initRes.json().catch(() => ({}));
            const requestId = initRes.headers.get("nvcf-reqid")
                || initRes.headers.get("request-id")
                || initData?.requestId || initData?.id;

            if (!requestId) {
                console.error("202 but no request ID. Headers:", [...initRes.headers.entries()], "Body:", initData);
                return res.status(502).json({ error: "Image generation started but no tracking ID returned. Please try again." });
            }

            const pollUrl = `https://integrate.api.nvidia.com/v1/status/${requestId}`;
            for (let i = 0; i < 30; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const pollRes = await fetch(pollUrl, { headers: authHeaders });
                if (pollRes.status === 202) continue;
                if (pollRes.status === 200) {
                    const pollData = await pollRes.json();
                    const b64 = await extractImage(pollData);
                    if (b64) return res.json({ imageBase64: b64, mimeType: "image/png" });
                    return res.status(502).json({ error: "No image in polling response" });
                }
                console.error("Poll error:", pollRes.status, await pollRes.text().catch(() => ""));
                return res.status(502).json({ error: `Image generation failed during processing (${pollRes.status})` });
            }
            return res.status(504).json({ error: "Image generation timed out after 60s. Please try again." });
        }

        const errText = await initRes.text().catch(() => "");
        console.error("NVIDIA image gen unexpected status:", initRes.status, errText);
        return res.status(502).json({ error: `Image generation failed (${initRes.status})` });

    } catch (err) {
        console.error("Image generation error:", err);
        res.status(500).json({ error: "Image generation failed: " + err.message });
    }
});

// Admin model list override (stored in DB as a special row)
serverApp.post("/api/admin/models", requireAdmin, (req, res) => {
    const { models } = req.body;
    if (!Array.isArray(models)) return res.status(400).json({ error: "Invalid models array" });
    // Store as JSON in a dedicated table row keyed by user_id = -999
    db.run(`
        INSERT INTO user_preferences (user_id, accent_color)
        VALUES (-999, ?)
        ON CONFLICT(user_id) DO UPDATE SET accent_color = excluded.accent_color
    `, [JSON.stringify(models)], (err) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true });
    });
});

// ----------------------
// USER PREFERENCES
// ----------------------

serverApp.get("/api/preferences", requireLogin, (req, res) => {
    const userId = req.session.user.id;
    db.get(`SELECT * FROM user_preferences WHERE user_id = ?`, [userId], (err, row) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(row || { accent_color: "#7c6cf8", font_size: "md", bubble_style: "rounded", ai_name: "AI", sidebar_width: 252 });
    });
});

serverApp.post("/api/preferences", requireLogin, (req, res) => {
    const userId = req.session.user.id;
    const { accent_color, font_size, bubble_style, ai_name, sidebar_width } = req.body;
    db.run(`
        INSERT INTO user_preferences (user_id, accent_color, font_size, bubble_style, ai_name, sidebar_width)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            accent_color = excluded.accent_color,
            font_size    = excluded.font_size,
            bubble_style = excluded.bubble_style,
            ai_name      = excluded.ai_name,
            sidebar_width= excluded.sidebar_width
    `, [userId, accent_color || "#7c6cf8", font_size || "md", bubble_style || "rounded", ai_name || "AI", sidebar_width || 252],
    (err) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true });
    });
});

// Logout — properly destroy session server-side
serverApp.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie("sid");
        res.redirect("/login.html");
    });
});

// Who am I?
serverApp.get("/api/me", requireLogin, (req, res) => {
    res.json({
        id: req.session.user.id,
        username: req.session.user.username,
        isAdmin: req.session.user.username === ADMIN_USERNAME,
    });
});

// ----------------------
// ADMIN ROUTES
// ----------------------

serverApp.get("/admin", requireAdmin, (req, res) => {
    sendWithSEO(res, path.join(__dirname, "public", "admin.html"), "/admin");
});

// Stats
serverApp.get("/api/admin/stats", requireAdmin, (req, res) => {
    db.get(`SELECT COUNT(*) as total FROM users WHERE banned = 0 OR banned IS NULL`, [], (err, users) => {
        db.get(`SELECT COUNT(*) as total FROM chat_conversations`, [], (err2, chats) => {
            db.get(`SELECT COUNT(*) as total FROM users WHERE banned = 1`, [], (err3, banned) => {
                res.json({
                    users:   users?.total  || 0,
                    chats:   chats?.total  || 0,
                    banned:  banned?.total || 0,
                });
            });
        });
    });
});

// List users
serverApp.get("/api/admin/users", requireAdmin, (req, res) => {
    db.all(`
        SELECT u.id, u.username, u.banned,
               COUNT(c.id) as chat_count,
               MAX(c.updated_at) as last_active
        FROM users u
        LEFT JOIN chat_conversations c ON c.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id ASC
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows || []);
    });
});

// Delete user
serverApp.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    if (String(id) === String(req.session.user.id)) {
        return res.status(400).json({ error: "Cannot delete yourself" });
    }
    db.run(`DELETE FROM chat_conversations WHERE user_id = ?`, [id], () => {
        db.run(`DELETE FROM users WHERE id = ?`, [id], function(err) {
            if (err) return res.status(500).json({ error: "DB error" });
            res.json({ ok: true });
        });
    });
});

// Ban / unban user
serverApp.post("/api/admin/users/:id/ban", requireAdmin, (req, res) => {
    const { id } = req.params;
    const { banned } = req.body;
    if (String(id) === String(req.session.user.id)) {
        return res.status(400).json({ error: "Cannot ban yourself" });
    }
    db.run(`UPDATE users SET banned = ? WHERE id = ?`, [banned ? 1 : 0, id], function(err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true });
    });
});

// Reset a user's password
serverApp.post("/api/admin/users/:id/reset-password", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ error: "Password too short" });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashed, id], function(err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true });
    });
});

// Get/set site-wide system prompt override
serverApp.get("/api/admin/site-settings", requireAdmin, (req, res) => {
    db.get(`SELECT value FROM user_preferences WHERE user_id = -1`, [], (err, row) => {
        // We store site settings with user_id = -1 as a convention
        res.json({ systemPromptOverride: row?.value || "" });
    });
});

// Broadcast message to a user (stored as a chat message from system)
serverApp.get("/api/admin/chats/:userId", requireAdmin, (req, res) => {
    const { userId } = req.params;
    db.all(`SELECT id, title, model, updated_at FROM chat_conversations WHERE user_id = ? ORDER BY updated_at DESC`, [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows || []);
    });
});

// Delete all chats for a user
serverApp.delete("/api/admin/chats/:userId", requireAdmin, (req, res) => {
    const { userId } = req.params;
    db.run(`DELETE FROM chat_conversations WHERE user_id = ?`, [userId], function(err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true, deleted: this.changes });
    });
});

// ----------------------
// SEO FILES
// ----------------------

serverApp.get("/robots.txt", (req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.send(`User-agent: *
Allow: /
Allow: /signup
Allow: /privacy
Allow: /tos
Allow: /credits
Allow: /shared/

Disallow: /admin
Disallow: /chat
Disallow: /login
Disallow: /api/

Sitemap: ${SITE_URL}/sitemap.xml`);
});

serverApp.get("/sitemap.xml", (req, res) => {
    const pages = [
        { loc: "/",        priority: "1.0", freq: "weekly"  },
        { loc: "/signup",  priority: "0.9", freq: "monthly" },
        { loc: "/privacy", priority: "0.3", freq: "yearly"  },
        { loc: "/tos",     priority: "0.3", freq: "yearly"  },
        { loc: "/credits", priority: "0.2", freq: "monthly" },
    ];
    const urls = pages.map(p => `
  <url>
    <loc>${SITE_URL}${p.loc}</loc>
    <changefreq>${p.freq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`).join("");
    res.setHeader("Content-Type", "application/xml");
    res.send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}\n</urlset>`);
});

// ----------------------
// WILDCARD ROUTE (MOVED TO END)
// ----------------------
serverApp.get("/:page", (req, res, next) => {
    const page = req.params.page;
    const filePath = path.join(__dirname, "public", `${page}.html`);
    const route = `/${page}`;
    // Only inject SEO if the file exists
    fs.access(filePath, fs.constants.R_OK, (err) => {
        if (err) return next();
        sendWithSEO(res, filePath, route);
    });
});

// ----------------------
// SERVER START
// ----------------------
const HTTP_PORT  = process.env.HTTP_PORT  || 80;
const HTTPS_PORT = process.env.HTTPS_PORT || 443;

if (tlsOptions) {
    // HTTPS server
    const httpsServer = https.createServer(tlsOptions, serverApp);
    httpsServer.listen(HTTPS_PORT, () => {
        console.log(`🔒 HTTPS server running at https://chatty.asteroid.ink:${HTTPS_PORT}`);
    });
    httpsServer.on("error", (err) => { console.error("HTTPS server error:", err); process.exit(1); });

    // HTTP → HTTPS redirect
    const redirectApp = express();
    redirectApp.use((req, res) => {
        res.redirect(301, `https://${req.headers.host}${req.url}`);
    });
    const httpServer = http.createServer(redirectApp);
    httpServer.listen(HTTP_PORT, () => {
        console.log(`↪️  HTTP redirect running on port ${HTTP_PORT}`);
    });
    httpServer.on("error", (err) => { console.error("HTTP redirect error:", err); });
} else {
    // No cert — plain HTTP fallback
    const PORT = process.env.PORT || 3000;
    const httpServer = http.createServer(serverApp);
    httpServer.listen(PORT, () => {
        console.log(`🚀 Server running at http://localhost:${PORT}`);
    });
    httpServer.on("error", (err) => { console.error("Server error:", err); process.exit(1); });
}