const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

require('dotenv').config();


const SYSTEM_CONFIG = {
    currentUser: 'Skoegle',
    systemStartTime: '2025-02-17 09:31:31',
    version: '1.0.0',
    tokenExpiration: '365d',
};


const API_TOKENS = {
    'Bearer sf8s48fsf4s4f8s4d8f48sf': {
        owner: SYSTEM_CONFIG.currentUser,
        createdAt: SYSTEM_CONFIG.systemStartTime,
        expiresAt: '2026-02-17 09:31:31',
        permissions: ['send-otp', 'verify-otp', 'status', 'health', 'send-custom-mail', 'logs'],
        active: true,
        type: 'primary',
        rateLimit: {
            windowMs: 10 * 60 * 1000,
            maxRequests: 100
        }
    },
    'Bearer     ': {
        owner: SYSTEM_CONFIG.currentUser,
        createdAt: SYSTEM_CONFIG.systemStartTime,
        expiresAt: '2026-02-17 09:31:31',
        permissions: ['send-otp', 'verify-otp', 'status', 'health', 'send-custom-mail', "logs"],
        active: true,
        type: 'backup',
        rateLimit: {
            windowMs: 10 * 60 * 1000,
            maxRequests: 50
        }
    }
};


const userAttempts = new Map();
const userOTPRequests = new Map();
const otps = new Map();


const cleanupTrackingData = () => {
    const now = Date.now();
    [userAttempts, userOTPRequests].forEach(map => {
        for (const [key, data] of map.entries()) {
            if (now > data.resetTime) {
                map.delete(key);
            }
        }
    });


    for (const [key, data] of otps.entries()) {
        if (now > data.expiry) {
            otps.delete(key);
        }
    }
};


setInterval(cleanupTrackingData, 5 * 60 * 1000);

const whitelist = [
    'https://vmarg.skoegle.com',
    'https://dmarg.skoegle.com',
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:4200',
    'http://localhost:8080',
    "http://localhost:5001"
];


const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || whitelist.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Authorization'],
    credentials: true,
    maxAge: 600
};


const logRequest = (req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const log = {
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            query: req.query,
            status: res.statusCode,
            duration: `${duration}ms`,
            userAgent: req.headers['user-agent'],
            ip: req.ip,
            owner: req.tokenDetails?.owner || 'anonymous'
        };

        console.log(JSON.stringify(log));

        fs.appendFile(
            path.join(__dirname, 'logs', `${new Date().toISOString().split('T')[0]}.log`),
            JSON.stringify(log) + '\n',
            (err) => {
                if (err) console.error('Error writing to log file:', err);
            }
        );
    });
    next();
};


const validateBearerToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            error: 'Authorization header required',
            message: 'Use Authorization: Bearer YOUR_TOKEN'
        });
    }

    const tokenDetails = API_TOKENS[authHeader];
    if (!tokenDetails) {
        return res.status(401).json({
            error: 'Invalid token',
            message: 'Please provide a valid bearer token'
        });
    }

    if (!tokenDetails.active) {
        return res.status(403).json({ error: 'Token is inactive' });
    }

    const now = new Date();
    const expiryDate = new Date(tokenDetails.expiresAt);
    if (now > expiryDate) {
        return res.status(403).json({ error: 'Token has expired' });
    }

    const endpoint = req.path.substring(1).split('?')[0];
    if (!tokenDetails.permissions.includes(endpoint)) {
        return res.status(403).json({
            error: 'Insufficient permissions',
            allowedEndpoints: tokenDetails.permissions
        });
    }

    req.tokenDetails = tokenDetails;
    next();
};


const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: 465,
    secure: true,
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD
    }
});


const createRateLimiter = (windowMs, max) => {
    return rateLimit({
        windowMs,
        max,
        message: {
            error: 'Too many requests',
            message: `Please try again after ${windowMs / 1000 / 60} minutes`
        }
    });
};


app.use(cors(corsOptions));
app.use(morgan('dev'));
app.use(express.json());
app.use(logRequest);

app.get('/health', validateBearerToken, (req, res) => {
    res.status(200).json({
        status: 'healthy',
        version: SYSTEM_CONFIG.version,
        startTime: SYSTEM_CONFIG.systemStartTime,
        currentTime: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/send-otp', validateBearerToken, async (req, res) => {
    const { to } = req.query;
    const now = Date.now();

    if (!to || !to.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
        return res.json({ error: 'Valid email address required', valid: false , message: 'Please provide a valid email address' });
    }


    const userRequests = userOTPRequests.get(to) || { count: 0, resetTime: now + (10 * 60 * 1000) };

    if (userRequests.count >= 10) {
        const timeLeft = Math.ceil((userRequests.resetTime - now) / 1000 / 60);
        return res.json({
            error: 'OTP limit reached',
            message: `Please wait ${timeLeft} minutes`,
            valid: false
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const mailOptions = {
        from: process.env.SMTP_EMAIL,
        to,
        subject: 'Your OTP Code',
        text: `Your OTP is ${otp}. Valid for 5 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);

        userOTPRequests.set(to, {
            count: userRequests.count + 1,
            resetTime: userRequests.resetTime,
            lastRequest: now
        });

        otps.set(to, {
            code: otp,
            expiry: now + (5 * 60 * 1000),
            attempts: 0
        });

        res.json({
            message: 'OTP sent successfully',
            validFor: '5 minutes',
            remainingAttempts: 10 - (userRequests.count + 1),
            valid: true,
        });
    } catch (error) {
        console.error('Email error:', error);
        res.json({ error: 'Failed to send OTP' });
    }
});

app.get('/verify-otp', validateBearerToken, (req, res) => {
    const { to, otp } = req.query;
    const now = Date.now();

    if (!to || !otp) {
        return res.json({ error: 'Email and OTP required' ,valid: false, message: 'Please provide email and OTP' });
    }

    const otpData = otps.get(to);
    if (!otpData) {
        return res.json({ error: 'OTP expired or not found' ,valid: false,message: 'OTP expired or not found' });
    }

    if (now > otpData.expiry) {
        otps.delete(to);
        return res.json({ error: 'OTP expired' ,valid: false,message: 'OTP expired' });
    }

    if (otpData.attempts >= 3) {
        otps.delete(to);
        return res.json({ error: 'Too many failed attempts',valid: false, message: 'Too many failed attempts' });
    }

    if (otpData.code === otp) {
        otps.delete(to);
        const mailOptions = {
            from: process.env.SMTP_EMAIL,
            to,
            subject: 'Otp verified',
            text: 'Your OTP has been verified successfully'
        };

        transporter.sendMail(mailOptions);
        return res.json({
            message: 'OTP verified successfully',
            timestamp: new Date().toISOString(),
            valid: true,
            message: 'OTP verified successfully'
        });
    }

    otpData.attempts++;
    otps.set(to, otpData);

    res.json({
        error: 'Invalid OTP',
        remainingAttempts: 5 - otpData.attempts,
        valid: false,
        message: 'Invalid OTP'
    });
});

app.get('/status', validateBearerToken, (req, res) => {
    const { email } = req.query;
    const now = Date.now();

    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }

    const otpData = otps.get(email);
    const requestData = userOTPRequests.get(email);

    res.status(200).json({
        email,
        otpStatus: otpData ? {
            valid: now < otpData.expiry,
            expiresIn: Math.max(0, Math.ceil((otpData.expiry - now) / 1000)),
            remainingAttempts: 3 - otpData.attempts
        } : null,
        requestLimits: requestData ? {
            remaining: 10 - requestData.count,
            resetIn: Math.ceil((requestData.resetTime - now) / 1000 / 60)
        } : { remaining: 10, resetIn: 0 }
    });
});


app.post('/send-custom-mail', validateBearerToken, async (req, res) => {
    const { subject, body } = req.body;
    const { to } = req.query;

    if (!to || !to.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
        return res.status(400).json({ error: 'Valid email address required' });
    }

    if (!subject || !body) {
        return res.status(400).json({ error: 'Subject and body are required' });
    }

    const mailOptions = {
        from: process.env.SMTP_EMAIL,
        to,
        subject,
        text: body
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Email sent successfully' });
    } catch (error) {
        console.error('Email error:', error);
        res.status(500).json({ error: 'Failed to send email' });
    }
});


app.get('/logs', validateBearerToken, (req, res) => {
    const logDir = path.join(__dirname, 'logs');
    fs.readdir(logDir, (err, files) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to read log directory' });
        }

        const logs = files.map(file => ({
            date: file.replace('.log', ''),
            path: path.join(logDir, file)
        }));

        res.status(200).json(logs);
    });
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});


app.listen(port, () => {
    console.log(`Server started at ${SYSTEM_CONFIG.systemStartTime}`);
    console.log(`Running on http://localhost:${port}`);
});