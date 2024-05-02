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
            return res.status(401).send({ error: 'user is not there' });;
        }
        const correctPassword = await bcryptjs.compare(req.body.password, user.password);
            if (!correctPassword){
                logger.error('Passwords do not match');
                return res.status(401).send({ error: 'pasword is not there' });
            }
            const payload = {
                user: {
                    id: user.insertedId,
                },
            };
            const name = user.firstName
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User blogged in successfully');
            res.json({authtoken, email, name});
        } catch (e) {
            return res.status(500).send('Internal server error');
        }
    });
    

    router.put('/update', async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.error('Validation errors in update request', errors.array());
            return res.status(400).json({ errors: errors.array() });
    }
    try {
        const email = req.headers.email;
        
        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({ error: "Email not found in the request headers" });
        }
        const db = await connectToDatabase();
        // Task 2: Access MongoDB collection
        const collection = db.collection("users");
        const existingUser = await collection.findOne({email: email})
        
        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();

    // Task 6: update user credentials in database
    const updatedUser = await collection.findOneAndUpdate(
        { email },
        { $set: existingUser },
        { returnDocument: 'after' }
    );
    // Task 7: create JWT authentication using secret key from .env file
    const payload = {
        user: {
            id: updatedUser._id.toString(),
        },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    res.json({authtoken});

} catch (e) {
     return res.status(500).send('Internal server error');

}
});

module.exports = router;