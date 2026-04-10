import express from "express";
import "dotenv/config";
import OpenAI from "openai";
import sqlite3pkg from "sqlite3";
import bcrypt from "bcrypt";
import session from "express-session";

const sqlite3 = sqlite3pkg.verbose();
const serverApp = express();

// ----------------------
// MIDDLEWARE
// ----------------------
serverApp.use(express.urlencoded({ extended: true, limit: "15mb" }));
serverApp.use(express.json({ limit: "15mb" }));
serverApp.use(express.static("public"));

// Sessions
serverApp.use(
    session({
        secret: "chattyisdabest1234",
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false },
    })
);

// ----------------------
// Paths
// ----------------------

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

// ----------------------
// ROUTES
// ----------------------

// Home
serverApp.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Chat (PROTECTED)
serverApp.get("/chat", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "chat.html"));
});

// Signup
serverApp.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.send("Missing username or password");

    const hashed = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, hashed],
        function (err) {
            if (err) return res.send("Username already taken");
            res.send("Signup successful! <a href='/login.html'>Login</a>");
        }
    );
});

// Login
serverApp.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        async (err, row) => {
            if (!row) return res.send("User not found");

            const match = await bcrypt.compare(password, row.password);
            if (!match) return res.send("Invalid password");

            req.session.user = { id: row.id, username: row.username };
            res.redirect("/chat");
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
    // Return curated NVIDIA NIM free models with metadata
    res.json(NVIDIA_MODELS);
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
    res.sendFile(path.join(__dirname, "public", "shared.html"));
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
serverApp.post("/api/generate-image", requireLogin, async (req, res) => {
    const { prompt, width = 1024, height = 1024 } = req.body;
    if (!prompt || !prompt.trim()) {
        return res.status(400).json({ error: "Prompt is required" });
    }

    if (!process.env.NVIDIA_API_KEY) {
        return res.status(500).json({ error: "NVIDIA_API_KEY not set in .env file. Get a free key at build.nvidia.com" });
    }

    try {
        // Use NVIDIA NIM image generation — flux-schnell is free tier
        const response = await fetch("https://integrate.api.nvidia.com/v1/images/generations", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.NVIDIA_API_KEY}`,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify({
                model: "black-forest-labs/flux-schnell",
                prompt: prompt.trim(),
                n: 1,
                width,
                height,
                response_format: "b64_json",
            }),
        });

        if (!response.ok) {
            const errText = await response.text();
            console.error("NVIDIA image gen error:", response.status, errText);
            if (response.status === 401 || response.status === 403) {
                return res.status(401).json({ error: "Invalid NVIDIA API key. Get a free key at build.nvidia.com" });
            }
            if (response.status === 402) {
                return res.status(402).json({ error: "NVIDIA free credits exhausted. Check build.nvidia.com for your usage." });
            }
            if (response.status === 422 || response.status === 400) {
                return res.status(400).json({ error: "Invalid image request. Try a different prompt." });
            }
            return res.status(502).json({ error: `Image generation failed (${response.status})` });
        }

        const data = await response.json();
        // OpenAI-compatible response: data.data[0].b64_json
        const b64 = data.data && data.data[0] && data.data[0].b64_json;
        if (!b64) {
            return res.status(502).json({ error: "No image returned from NVIDIA API" });
        }

        res.json({ imageBase64: b64, mimeType: "image/png" });
    } catch (err) {
        console.error("Image generation error:", err);
        res.status(500).json({ error: "Image generation failed: " + err.message });
    }
});

// ----------------------
// WILDCARD ROUTE (MOVED TO END)
// ----------------------
serverApp.get("/:page", (req, res, next) => {
    let page = req.params.page;
    let filePath = path.join(__dirname, "public", `${page}.html`);

    res.sendFile(filePath, (err) => {
        if (err) next();
    });
});

// ----------------------
// SERVER START
// ----------------------
const PORT = process.env.PORT || 3000;
const httpServer = serverApp.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});

httpServer.on("error", (err) => {
    console.error("Server failed to stay up:", err);
    process.exit(1);
});

httpServer.on("close", () => {
    console.log("HTTP server closed.");
});