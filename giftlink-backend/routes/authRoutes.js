const express = require('express');
const app = express();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Import Pino logger
const logger = pino();  // Create a Pino logger instance
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();
        // Task 2: Access MongoDB collection
        const collection = db.collection("users");
        //Task 3: Check for existing email
        const existingEmail = await collection.findOne({ email: req.body.email });
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;
        //Task 4: Save user details in database
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User registered successfully');
        res.json({authtoken,email});
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();
        // Task 2: Access MongoDB collection
        const collection = db.collection("users");
        //Task 3: Check for existing email
        const email = req.body.email
        const user = await collection.findOne({ email: email });
        if (!user){
            return res.status(401).send('Invalid credentials');
        }
        const correctPassword = await bcryptjs.compare(req.body.password, user.password);
            if (!correctPassword){
                return res.status(401).send('passwords do not match');
            }
            const payload = {
                user: {
                    id: user.insertedId,
                },
            };
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User blogged in successfully');
            res.json({authtoken, email});
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

module.exports = router;