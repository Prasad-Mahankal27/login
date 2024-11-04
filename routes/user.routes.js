const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const userModel = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

router.get('/test', (req, res) => {
    res.send('User Test route');
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.post(
    '/register',
    body('email').trim().isEmail().isLength({ min: 13 }),
    body('password').trim().isLength({ min: 5 }),
    body('username').trim().isLength({ min: 3 }),
    body('role').isIn(['government employee', 'project manager', 'admin']).withMessage('Invalid role'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send("Invalid data");
        }

        const { email, username, password, role } = req.body;
        const hashPassword = await bcrypt.hash(password, 10); // bcrypt hash
        const newUser = await userModel.create({
            email,
            username,
            password: hashPassword,
            role
        });
        
        return res.json(newUser); // Return to avoid further execution
    }
);

router.get('/login', (req, res) => {
    res.render('login');
});

router.post(
    '/login',
    body('username').trim().isLength({ min: 3 }),
    body('password').trim().isLength({ min: 5 }),
    body('role').isIn(['government employee', 'project manager', 'admin']).withMessage('Invalid role'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: errors.array(),
                message: 'Invalid data',
            });
        }

        const { username, password, role } = req.body;
        const user = await userModel.findOne({ username });
        if (!user) {
            return res.status(400).json({
                message: 'Username or password is incorrect',
            });
        }

        // Verify if the role matches
        if (user.role !== role) {
            return res.status(403).json({
                message: 'Role mismatch. Access denied.',
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                message: 'Username or password is incorrect',
            });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                username: user.username,
                role: user.role, // Include role in JWT
            },
            process.env.JWT_SECRET,
        );
        
        res.cookie('token', token); // Set JWT as a cookie
        res.send("logged in");
    }
);

module.exports = router;
