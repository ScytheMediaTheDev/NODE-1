const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { format } = require('date-fns');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
require('dotenv').config();

let chalk; // Declare chalk variable

// Dynamically import chalk
import('chalk').then((module) => {
    chalk = module.default;

    // Start the server only after chalk is loaded
    startServer();
}).catch((err) => {
    console.error('Failed to load chalk:', err);
    process.exit(1);
});

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict'
    }
}));

// File paths
const usersFilePath = path.join(__dirname, 'users.json');
const logsFilePath = path.join(__dirname, 'logs', 'logs.json');
const messagesFilePath = path.join(__dirname, 'messages.json');

// Ensure files exist
[usersFilePath, logsFilePath, messagesFilePath].forEach(filePath => {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, filePath.includes('messages') ? JSON.stringify({
            welcomeMessage: "Welcome to our platform!",
            blockedMessage: "Your account has been blocked. Please contact support.",
            loginMessage: "Please log in to access your account."
        }) : JSON.stringify([]));
    }
});

// Winston logger setup with colors
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => {
            const timestamp = chalk.gray(`[${info.timestamp}]`);
            const level = info.level === 'info' ? chalk.green.bold(`[${info.level.toUpperCase()}]`) :
                          info.level === 'warn' ? chalk.yellow.bold(`[${info.level.toUpperCase()}]`) :
                          chalk.red.bold(`[${info.level.toUpperCase()}]`);
            const message = info.message;
            return `${timestamp} ${level} ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' })
    ]
});

// Rate limiter for login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts
    message: 'Too many login attempts, please try again later.'
});

// Middleware to check if user is authenticated and has admin role
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        const users = JSON.parse(fs.readFileSync(usersFilePath));
        const user = users.find(user => user.username === req.session.user);

        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).send('Access denied. You do not have permission to view this page.');
        }
    } else {
        res.status(403).send('Access denied. Please log in.');
    }
}

// Serve static files
app.use(express.static('public'));

// Register endpoint (only for admins)
app.post('/register', ensureAuthenticated, [
    body('username').isLength({ min: 3 }).trim().escape(),
    body('password').isLength({ min: 6 }),
    body('role').optional().isIn(['admin', 'regular'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, role } = req.body;
    const users = JSON.parse(fs.readFileSync(usersFilePath));

    if (users.find(user => user.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userUUID = uuidv4();
        const newUser = {
            username,
            password: hashedPassword,
            uuid: userUUID,
            loginCount: 0,
            ipAddresses: [],
            blocked: false,
            role: role || 'regular'
        };
        users.push(newUser);
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
        res.json({ message: 'Registration successful' });

        logger.info(`User registered successfully. Username: ${username}, Role: ${newUser.role}, Registered By: ${req.session.user}`);
    } catch (error) {
        logger.error(`Error registering user: ${error.message}`);
        res.status(500).json({ error: 'Registration failed. Please try again later.' });
    }
});

// Login endpoint
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(usersFilePath));

    const user = users.find(user => user.username === username);
    if (user) {
        if (user.blocked) {
            const messages = JSON.parse(fs.readFileSync(messagesFilePath));
            res.status(403).json({ error: messages.blockedMessage });
            logger.warn(`Blocked user attempted to log in. Username: ${username}, IP: ${req.ip}`);
            return;
        }

        try {
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                user.loginCount += 1;
                const userIP = req.ip;
                if (!user.ipAddresses.includes(userIP)) {
                    user.ipAddresses.push(userIP);
                }
                fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

                req.session.user = username;
                logger.info(`User logged in successfully. Username: ${username}, IP: ${userIP}, Login Count: ${user.loginCount}`);

                res.json({ message: 'Login successful', redirect: user.role === 'admin' ? '/dashboard' : '/profile' });
            } else {
                res.status(400).json({ error: 'Invalid credentials' });
                logger.warn(`Invalid login attempt. Username: ${username}, IP: ${req.ip}`);
            }
        } catch (error) {
            logger.error(`Error during login: ${error.message}`);
            res.status(500).json({ error: 'Login failed. Please try again later.' });
        }
    } else {
        res.status(400).json({ error: 'Invalid credentials' });
        logger.warn(`Invalid login attempt. Username: ${username}, IP: ${req.ip}`);
    }
});

// Dashboard endpoint (only for admins)
app.get('/dashboard', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Profile endpoint (for regular users)
app.get('/profile', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'profile.html'));
    } else {
        res.status(403).send('Access denied. Please log in.');
    }
});

// Logout endpoint
app.get('/logout', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        const users = JSON.parse(fs.readFileSync(usersFilePath));
        const user = users.find(user => user.username === username);

        logger.info(`User logged out. Username: ${username}, Login Count: ${user.loginCount}`);
    }
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out, please try again' });
        }
        res.redirect('/login.html');
    });
});

// Endpoint to get all users (for dashboard)
app.get('/users', ensureAuthenticated, (req, res) => {
    const users = JSON.parse(fs.readFileSync(usersFilePath));
    res.json(users);
});

// Endpoint to delete a user
app.post('/delete-user', ensureAuthenticated, (req, res) => {
    const { username } = req.body;
    let users = JSON.parse(fs.readFileSync(usersFilePath));

    users = users.filter(user => user.username !== username);
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

    logger.info(`User deleted. Username: ${username}, Deleted By: ${req.session.user}`);
    res.json({ message: 'User deleted successfully' });
});

// Endpoint to block/unblock a user
app.post('/block-user', ensureAuthenticated, (req, res) => {
    const { username, blocked } = req.body;
    const users = JSON.parse(fs.readFileSync(usersFilePath));

    const user = users.find(user => user.username === username);
    if (user) {
        user.blocked = blocked;
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

        logger.info(`User ${blocked ? 'blocked' : 'unblocked'}. Username: ${username}, Action By: ${req.session.user}`);
        res.json({ message: `User ${blocked ? 'blocked' : 'unblocked'} successfully` });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// Endpoint to get messages
app.get('/messages', ensureAuthenticated, (req, res) => {
    const messages = JSON.parse(fs.readFileSync(messagesFilePath));
    res.json(messages);
});

// Endpoint to update messages
app.post('/update-messages', ensureAuthenticated, (req, res) => {
    const { welcomeMessage, blockedMessage, loginMessage } = req.body;
    const messages = JSON.parse(fs.readFileSync(messagesFilePath));

    if (welcomeMessage) messages.welcomeMessage = welcomeMessage;
    if (blockedMessage) messages.blockedMessage = blockedMessage;
    if (loginMessage) messages.loginMessage = loginMessage;

    fs.writeFileSync(messagesFilePath, JSON.stringify(messages, null, 2));

    logger.info(`Messages updated. Action By: ${req.session.user}`);
    res.json({ message: 'Messages updated successfully' });
});

// Endpoint to get logs
app.get('/logs', ensureAuthenticated, (req, res) => {
    try {
        const logs = JSON.parse(fs.readFileSync(logsFilePath, 'utf8'));
        res.json(logs);
    } catch (error) {
        logger.error(`Error reading logs file: ${error.message}`);
        res.status(500).json({ error: 'Failed to read logs' });
    }
});

// Function to start the server
function startServer() {
    app.listen(port, () => {
        logger.info(`Server running at http://localhost:${port}`);
    });
}