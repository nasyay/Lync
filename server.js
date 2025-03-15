require("dotenv").config();
const express = require("express");
const sodium = require("sodium-native");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();

// Middleware
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON request bodies

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

const app = express();
app.use(express.json());

// Store messages temporarily in memory
let messages = [];

// Encrypt Message Function
function encryptMessage(plaintext) {
    const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);
    sodium.randombytes_buf(key);

    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
    sodium.randombytes_buf(nonce);

    const plaintextBuffer = Buffer.from(plaintext, "utf-8");
    const ciphertext = Buffer.alloc(plaintextBuffer.length + sodium.crypto_secretbox_MACBYTES);

    
    sodium.crypto_secretbox_easy(ciphertext, plaintextBuffer, nonce, key);

    return {
        ciphertext: ciphertext.toString("hex"),
        nonce: nonce.toString("hex"),
        key: key.toString("hex"),
    };
}

// Decrypt Message Function
function decryptMessage(ciphertext, nonce, key) {
    try {
        if (!ciphertext || !nonce || !key) {
            throw new Error("Missing required decryption parameters!");
        }

        const ciphertextBuffer = Buffer.from(ciphertext, "hex");
        const nonceBuffer = Buffer.from(nonce, "hex");
        const keyBuffer = Buffer.from(key, "hex");

        if (ciphertextBuffer.length < sodium.crypto_secretbox_MACBYTES) {
            throw new Error("Invalid ciphertext size!");
        }

        const decrypted = Buffer.alloc(ciphertextBuffer.length - sodium.crypto_secretbox_MACBYTES);
        const success = sodium.crypto_secretbox_open_easy(decrypted, ciphertextBuffer, nonceBuffer, keyBuffer);

        if (!success) {
            throw new Error("Decryption failed!");
        }

        return decrypted.toString("utf-8");
    } catch (error) {
        console.error("❌ Decryption error:", error.message);
        return null;
    }
}


// Route to Send a Message
app.post("/send", (req, res) => {
    const { message } = req.body;

    // Input validation
    if (!message || typeof message !== "string") {
        return res.status(400).json({ error: "Invalid message format!" });
    if (!message) {
        return res.status(400).json({ error: "Message cannot be empty!" });
    }

    const encryptedMessage = encryptMessage(message);

    messages.push({
        ...encryptedMessage,
        receivedAt: Date.now(), // Store timestamp when message was sent
        seenAt: null, // Initially not seen
    });

    res.json({ status: "Message sent!", encryptedMessage });
});

// Route to Read Messages
app.get("/messages", (req, res) => {
    const now = Date.now();

    // Remove expired messages (older than 6 hours and unseen)
    messages = messages.filter(msg => !msg.seenAt && (now - msg.receivedAt < 6 * 60 * 60 * 1000));

    if (messages.length === 0) {
        return res.json({ status: "No messages!" });
    }

    // Decrypt messages safely
    const decryptedMessages = messages.map(msg => {
        const text = decryptMessage(msg.ciphertext, msg.nonce, msg.key);
        return text ? { text, messageId: msg.receivedAt } : null;
    }).filter(msg => msg !== null); // Remove failed decryption messages

    // Mark messages as seen
    messages.forEach(msg => {
        msg.seenAt = now;
    });

    res.json({ messages: decryptedMessages });
});

// Auto-delete messages after 10 minutes if seen
setInterval(() => {
    const now = Date.now();
    messages = messages.filter(msg => !msg.seenAt || (now - msg.seenAt < 10 * 60 * 1000));
}, 60 * 1000); // Check every minute

// Error handling middleware
app.use((err, req, res, next) => {
    console.error("❌ Server error:", err.message);
    res.status(500).json({ error: "Something went wrong!" });
});

// Start the server
const PORT = process.env.PORT || 3010;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
const PORT = process.env.PORT || 3005;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
