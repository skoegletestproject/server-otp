const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const axios = require('axios'); // Add axios for making HTTP requests to SMS API
const Log = require('./Log'); // Import Log model from Logs.js
const app = express();
const port = process.env.PORT || 3000;
const mongoose = require('mongoose');
require('dotenv').config();


function connectToMongoDB() {
    const uri = process.env.MONGODB_URI;
    mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    });

    const db = mongoose.connection;
    db.on('error', console.error.bind(console, 'MongoDB connection error:'));
    db.once('open', () => {
        console.log('Connected to MongoDB');
    });
}
connectToMongoDB()

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

const SYSTEM_CONFIG = {
    currentUser: process.env.CURRENT_USER || 'ManojGowda89',
    systemStartTime: '2025-03-18 09:25:48', 
    version: '1.0.0',
    tokenExpiration: '365d',
};

// Pre-create rate limiters for different token types
const primaryLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests',
        message: 'Please try again after 10 minutes',
        valid: false
    },
    keyGenerator: (req) => {
        return req.headers.authorization || req.ip;
    }
});

const backupLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests',
        message: 'Please try again after 10 minutes',
        valid: false
    },
    keyGenerator: (req) => {
        return req.headers.authorization || req.ip;
    }
});

// Use different tokens for primary and backup
const API_TOKENS = {
    [process.env.PRIMARY_TOKEN || 'Bearer sf8s48fsf4s4f8s4d8f48sf']: {
        owner: SYSTEM_CONFIG.currentUser,
        createdAt: SYSTEM_CONFIG.systemStartTime,
        expiresAt: '2026-03-18 09:25:48',
        permissions: ['send-otp', 'verify-otp', 'status', 'health', 'send-custom-mail', 'logs'],
        active: true,
        type: 'primary',
        limiter: primaryLimiter
    },
    [process.env.BACKUP_TOKEN || 'Bearer backup48fsf4s4f8s4d8f48sf']: {
        owner: SYSTEM_CONFIG.currentUser,
        createdAt: SYSTEM_CONFIG.systemStartTime,
        expiresAt: '2026-03-18 09:25:48',
        permissions: ['send-otp', 'verify-otp', 'status', 'health', 'send-custom-mail', 'logs'],
        active: true,
        type: 'backup',
        limiter: backupLimiter
    }
};

const userAttempts = new Map();
const userOTPRequests = new Map();
const otps = new Map();

// SMS API Configuration
const SMS_CONFIG = {
    apiUrl: process.env.SMS_API_URL ,
    apiKey: process.env.SMS_API_KEY 
};

// Flexible SMTP Configuration
const getEmailTransporter = () => {
    // Get email configuration from environment variables
    const service = process.env.SMTP_SERVICE;
    const host = process.env.SMTP_HOST || 'smtp.zoho.com';
    const port = parseInt(process.env.SMTP_PORT || '465');
    const secure = process.env.SMTP_SECURE !== 'false';
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    
    // Log email configuration for debugging
    console.log(`Configuring email with: service=${service || 'none'}, host=${host}, port=${port}, secure=${secure}`);
    
    // Check for required credentials
    if (!user || !pass) {
        console.error("Missing email credentials! Check your .env file.");
    }

    // Create and return the transporter
    if (service) {
        return nodemailer.createTransport({
            service: service,
            auth: {
                user: user,
                pass: pass
            }
        });
    } else {
        return nodemailer.createTransport({
            host: host,
            port: port,
            secure: secure,
            auth: {
                user: user,
                pass: pass
            }
        });
    }
};

const transporter = getEmailTransporter();

// Test email function - uncomment to test
async function testEmailConnection() {
    try {
        console.log("Testing SMTP server connection...");
        console.log(`User: ${process.env.SMTP_USER}`);
        
        // First verify connection
        await new Promise((resolve, reject) => {
            transporter.verify(function(error, success) {
                if (error) {
                    console.log('SMTP Verification Error:', error);
                    
                    // Handle common auth errors
                    if (error.code === 'EAUTH') {
                        console.error('\nAuthentication failed. Possible reasons:');
                        console.error('- Incorrect username or password');
                        console.error('- 2FA is enabled (use app password instead)');
                        console.error('- Account security settings blocking access\n');
                    }
                    
                    reject(error);
                } else {
                    console.log("SMTP connection working correctly!");
                    resolve(success);
                }
            });
        });
        
        // If verification worked, try sending a test email
        console.log("Sending test email...");
        const info = await transporter.sendMail({
            from: process.env.SMTP_USER,
            to: process.env.SMTP_USER, // sending to yourself for testing
            subject: 'SMTP Test Email',
            text: 'If you received this email, your SMTP configuration is working correctly.'
        });
        console.log('Test email sent:', info.messageId);
        
    } catch (error) {
        console.error('Email test failed:', error.message);
    }
}

// Verify transport connection on startup
transporter.verify(function (error, success) {
    if (error) {
        console.error('SMTP server connection error:', error);
        
        // Provide helpful information for common errors
        if (error.code === 'EAUTH') {
            console.error('\nAuthentication failed. Possible reasons:');
            console.error('- Incorrect username or password');
            console.error('- 2FA is enabled (use app password instead)');
            console.error('- Account security settings blocking access');
            console.error('\nCheck your .env file and update the credentials.\n');
        }
    } else {
        console.log('SMTP server connection verified successfully');
        console.log('Server ready to send emails');
    }
});

// Cleanup tracking data every 5 minutes
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
    'http://localhost:5001',
    "https://v-marg2-0.onrender.com"
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || whitelist.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'], // Added POST for /send-custom-mail
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Authorization'],
    credentials: true,
    maxAge: 600
};

const logRequest = (req, res, next) => {
    const start = Date.now();
    req.transactionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);

    res.on('finish', async () => {
        const duration = Date.now() - start;

        // Create log object
        const logData = {
            timestamp: new Date(),
            method: req.method,
            path: req.originalUrl || req.path,
            query: req.query,
            status: res.statusCode,
            duration: duration,
            userAgent: req.headers['user-agent'],
            ip: req.ip,
            owner: req.tokenDetails?.owner || 'anonymous',
            transactionId: req.transactionId
        };

        try {
            // Save log to MongoDB
            await Log.create(logData);
            console.log("Log stored successfully:", logData);
        } catch (err) {
            console.error("Error storing log in MongoDB:", err);
        }
    });

    next();
};

// Fixed validateBearerToken middleware
const validateBearerToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            error: 'Authorization header required',
            message: 'Use Authorization: Bearer YOUR_TOKEN',
            valid: false
        });
    }

    const tokenDetails = API_TOKENS[authHeader];
    if (!tokenDetails) {
        return res.status(401).json({
            error: 'Invalid token',
            message: 'Please provide a valid bearer token',
            valid: false
        });
    }

    if (!tokenDetails.active) {
        return res.status(403).json({ 
            error: 'Token is inactive',
            valid: false 
        });
    }

    const now = new Date();
    const expiryDate = new Date(tokenDetails.expiresAt);
    if (now > expiryDate) {
        return res.status(403).json({ 
            error: 'Token has expired',
            valid: false 
        });
    }

    const endpoint = req.path.substring(1).split('?')[0];
    if (!tokenDetails.permissions.includes(endpoint)) {
        return res.status(403).json({
            error: 'Insufficient permissions',
            allowedEndpoints: tokenDetails.permissions,
            valid: false
        });
    }

    // Store token details in request object
    req.tokenDetails = tokenDetails;
    
    // Apply the pre-created limiter for this token type
    tokenDetails.limiter(req, res, next);
};

// Enhanced email validation
const validateEmail = (email) => {
    const regex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    return regex.test(String(email).toLowerCase());
};

// Add phone number validation
const validatePhoneNumber = (number) => {
    // Simple regex for phone numbers (can be enhanced based on requirements)
    const regex = /^\d{10,15}$/;
    return regex.test(String(number).replace(/\D/g, ''));
};

// Function to send SMS via API
const sendSMS = async (number, message) => {
    try {
        const url = `${SMS_CONFIG.apiUrl}?apikey=${SMS_CONFIG.apiKey}&number=${number}&message=${encodeURIComponent(message)}`;
        const response = await axios.get(url);
        
        if (response.status === 200) {
            return { success: true };
        } else {
            console.error('SMS API error:', response.data);
            return { 
                success: false, 
                error: 'SMS API returned non-200 status code'
            };
        }
    } catch (error) {
        console.error('SMS sending error:', error);
        return { 
            success: false, 
            error: error.message 
        };
    }
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
        uptime: process.uptime(),
        valid: true,
        transactionId: req.transactionId
    });
});

app.get('/send-otp', validateBearerToken, async (req, res) => {
    const { to, type = 'email' } = req.query; // Default to email if type not specified
    const now = Date.now();

    // Check if the OTP delivery type is valid
    if (!['email', 'sms'].includes(type)) {
        return res.json({
            error: 'Invalid OTP delivery type',
            valid: false,
            message: 'Type must be either email or sms',
            transactionId: req.transactionId
        });
    }

    // Validate recipient based on type
    if (type === 'email' && (!to || !validateEmail(to))) {
        return res.json({ 
            error: 'Valid email address required', 
            valid: false, 
            message: 'Please provide a valid email address',
            transactionId: req.transactionId
        });
    } else if (type === 'sms' && (!to || !validatePhoneNumber(to))) {
        return res.json({ 
            error: 'Valid phone number required', 
            valid: false, 
            message: 'Please provide a valid phone number',
            transactionId: req.transactionId
        });
    }

    const userRequests = userOTPRequests.get(to) || { count: 0, resetTime: now + (10 * 60 * 1000) };

    if (userRequests.count >= 10) {
        const timeLeft = Math.ceil((userRequests.resetTime - now) / 1000 / 60);
        return res.json({
            error: 'OTP limit reached',
            message: `Please wait ${timeLeft} minutes`,
            valid: false,
            transactionId: req.transactionId
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    try {
        let sendResult;
        
        if (type === 'email') {
            const mailOptions = {
                from: process.env.SMTP_USER,
                to,
                subject: 'Your OTP Code',
                text: `Your OTP is ${otp}. Valid for 5 minutes.`
            };
            
            await transporter.sendMail(mailOptions);
            sendResult = { success: true };
        } else if (type === 'sms') {
            // Format the SMS message
            const smsMessage = `Your OTP is ${otp}. Valid for 5 minutes.`;
            sendResult = await sendSMS(to, smsMessage);
        }

        if (sendResult.success) {
            userOTPRequests.set(to, {
                count: userRequests.count + 1,
                resetTime: userRequests.resetTime,
                lastRequest: now,
                type // Store the OTP type for reference
            });

            otps.set(to, {
                code: otp,
                expiry: now + (5 * 60 * 1000),
                attempts: 0,
                type // Store the OTP type for reference
            });

            res.json({
                message: `OTP sent successfully via ${type}`,
                validFor: '5 minutes',
                remainingAttempts: 10 - (userRequests.count + 1),
                valid: true,
                transactionId: req.transactionId
            });
        } else {
            throw new Error(sendResult.error || `Failed to send OTP via ${type}`);
        }
    } catch (error) {
        console.error(`${type} error:`, error);
        res.json({ 
            error: `Failed to send OTP via ${type}`,
            valid: false,
            message: `${type === 'email' ? 'Email' : 'SMS'} service error: ${error.message}`,
            transactionId: req.transactionId
        });
    }
});

app.get('/verify-otp', validateBearerToken, (req, res) => {
    const { to, otp } = req.query;
    const now = Date.now();

    if (!to || !otp) {
        return res.json({ 
            error: 'Recipient and OTP required',
            valid: false, 
            message: 'Please provide recipient (email/phone) and OTP',
            transactionId: req.transactionId
        });
    }

    const otpData = otps.get(to);
    if (!otpData) {
        return res.json({ 
            error: 'OTP expired or not found',
            valid: false,
            message: 'OTP expired or not found',
            transactionId: req.transactionId
        });
    }

    if (now > otpData.expiry) {
        otps.delete(to);
        return res.json({ 
            error: 'OTP expired',
            valid: false,
            message: 'OTP expired',
            transactionId: req.transactionId
        });
    }

    if (otpData.attempts >= 3) {
        otps.delete(to);
        return res.json({ 
            error: 'Too many failed attempts',
            valid: false, 
            message: 'Too many failed attempts',
            transactionId: req.transactionId
        });
    }

    if (otpData.code === otp) {
        const otpType = otpData.type || 'email'; // Default to email if type not stored
        otps.delete(to);
        
        // Only send confirmation for email OTPs
        if (otpType === 'email' && validateEmail(to)) {
            const mailOptions = {
                from: process.env.SMTP_USER,
                to,
                subject: 'OTP verified',
                text: 'Your OTP has been verified successfully'
            };

            transporter.sendMail(mailOptions).catch(err => {
                console.error('Error sending verification email:', err);
            });
        }
        
        return res.json({
            message: 'OTP verified successfully',
            timestamp: new Date().toISOString(),
            valid: true,
            transactionId: req.transactionId
        });
    }

    otpData.attempts++;
    otps.set(to, otpData);

    res.json({
        error: 'Invalid OTP',
        remainingAttempts: 3 - otpData.attempts,
        valid: false,
        message: 'Invalid OTP',
        transactionId: req.transactionId
    });
});

app.get('/status', validateBearerToken, (req, res) => {
    const { to } = req.query; // Changed from 'email' to more generic 'to'
    const now = Date.now();

    if (!to) {
        return res.status(400).json({ 
            error: 'Recipient required',
            valid: false,
            transactionId: req.transactionId
        });
    }

    const otpData = otps.get(to);
    const requestData = userOTPRequests.get(to);
    const otpType = otpData?.type || requestData?.type || 'unknown';

    res.status(200).json({
        recipient: to,
        recipientType: otpType,
        otpStatus: otpData ? {
            valid: now < otpData.expiry,
            expiresIn: Math.max(0, Math.ceil((otpData.expiry - now) / 1000)),
            remainingAttempts: 3 - otpData.attempts
        } : null,
        requestLimits: requestData ? {
            remaining: Math.max(0, 10 - requestData.count),
            resetIn: Math.max(0, Math.ceil((requestData.resetTime - now) / 1000 / 60))
        } : { remaining: 10, resetIn: 0 },
        valid: true,
        transactionId: req.transactionId
    });
});

app.get('/send-custom-mail', validateBearerToken, async (req, res) => {
    const { to, type = 'email', subject, body } = req.query;

    // Check if the message delivery type is valid
    if (!['email', 'sms'].includes(type)) {
        return res.status(400).json({ 
            error: 'Invalid message type',
            valid: false,
            message: 'Type must be either email or sms',
            transactionId: req.transactionId
        });
    }

    // Validate recipient based on type
    if (type === 'email' && (!to || !validateEmail(to))) {
        return res.status(400).json({ 
            error: 'Valid email address required',
            valid: false,
            transactionId: req.transactionId
        });
    } else if (type === 'sms' && (!to || !validatePhoneNumber(to))) {
        return res.status(400).json({ 
            error: 'Valid phone number required',
            valid: false,
            transactionId: req.transactionId
        });
    }

    // Validate message content
    if (!body) {
        return res.status(400).json({ 
            error: 'Message body is required',
            valid: false,
            transactionId: req.transactionId
        });
    }

    // Subject is only required for email
    if (type === 'email' && !subject) {
        return res.status(400).json({ 
            error: 'Subject is required for email messages',
            valid: false,
            transactionId: req.transactionId
        });
    }

    try {
        if (type === 'email') {
            // Send email
            const mailOptions = {
                from: process.env.SMTP_USER,
                to,
                subject,
                text: body
            };

            await transporter.sendMail(mailOptions);
            
            res.status(200).json({ 
                message: 'Email sent successfully',
                valid: true,
                transactionId: req.transactionId
            });
        } else if (type === 'sms') {
            const smsMessage = subject ? `${subject}\n\n${body}` : body;
            
            // Send SMS
            const sendResult = await sendSMS(to, smsMessage);
            
            if (sendResult.success) {
                res.status(200).json({ 
                    message: 'SMS sent successfully',
                    valid: true,
                    transactionId: req.transactionId
                });
            } else {
                throw new Error(sendResult.error || 'Failed to send SMS');
            }
        }
    } catch (error) {
        console.error(`${type} sending error:`, error);
        res.status(500).json({ 
            error: `Failed to send ${type}`,
            valid: false,
            message: error.message,
            transactionId: req.transactionId
        });
    }
});
app.get('/logs', validateBearerToken, (req, res) => {
    // Only allow users with specific permissions to access logs
    if (req.tokenDetails.type !== 'primary') {
        return res.status(403).json({ 
            error: 'Insufficient permissions',
            message: 'Only primary token holders can access logs',
            valid: false,
            transactionId: req.transactionId
        });
    }

    fs.readdir(logDir, (err, files) => {
        if (err) {
            return res.status(500).json({ 
                error: 'Failed to read log directory',
                valid: false,
                transactionId: req.transactionId
            });
        }

        const logs = files
            .filter(file => file.endsWith('.log'))
            .map(file => ({
                date: file.replace('.log', ''),
                path: path.join(logDir, file),
                size: fs.statSync(path.join(logDir, file)).size
            }));

        res.status(200).json({
            logs,
            total: logs.length,
            valid: true,
            transactionId: req.transactionId
        });
    });
});

// Added endpoint to view a specific log file
app.get('/logs/:date', validateBearerToken, (req, res) => {
    // Only allow users with specific permissions to access logs
    if (req.tokenDetails.type !== 'primary') {
        return res.status(403).json({ 
            error: 'Insufficient permissions',
            message: 'Only primary token holders can access logs',
            valid: false,
            transactionId: req.transactionId
        });
    }

    const { date } = req.params;
    const logFile = path.join(logDir, `${date}.log`);

    if (!fs.existsSync(logFile)) {
        return res.status(404).json({
            error: 'Log file not found',
            valid: false,
            transactionId: req.transactionId
        });
    }

    fs.readFile(logFile, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({
                error: 'Failed to read log file',
                valid: false,
                transactionId: req.transactionId
            });
        }

        // Parse log entries
        const entries = data.trim().split('\n').map(line => {
            try {
                return JSON.parse(line);
            } catch (e) {
                return { raw: line, error: 'Parse error' };
            }
        });

        res.status(200).json({
            date,
            entries,
            count: entries.length,
            valid: true,
            transactionId: req.transactionId
        });
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
        valid: false,
        transactionId: req.transactionId || 'unknown'
    });
});

app.listen(port, () => {
    console.log(`Server started at ${SYSTEM_CONFIG.systemStartTime}`);
    console.log(`Running on http://localhost:${port}`);
    console.log(`Current user: ${SYSTEM_CONFIG.currentUser}`);
    console.log(`Email configuration: ${process.env.SMTP_SERVICE || 'Direct'} mode with host ${process.env.SMTP_HOST || 'smtp.zoho.com'}`);
    console.log(`SMS configuration: API URL ${SMS_CONFIG.apiUrl}`);
});