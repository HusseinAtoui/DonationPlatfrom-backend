// routes/userAuth.js
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
require('dotenv').config();

// AWS setup
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();

const USER_TABLE = process.env.USER_TABLE;      // e.g. 'donors'
const JWT_SECRET = process.env.JWT_SECRET;

// Mailer — keep same pattern as NGO
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_RECEIVER, pass: process.env.EMAIL_PASS }
});

// Create User (issue a JWT for email verification)
router.post('/create', async (req, res) => {
  const { email, phone, name, location, avatarUrl, bio, password } = req.body;

  if (!email || !phone || !name || !password)
    return res.status(400).json({ error: 'Missing required fields.' });

  try {
    // 1) check for existing user
    const { Item } = await ddb.get({ TableName: USER_TABLE, Key: { email } }).promise();
    if (Item) return res.status(409).json({ error: 'User already exists.' });

    // 2) hash password & build user record (no verificationToken field)
    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const newUser = {
      id,
      email,
      phone,
      name,
      location: location || '',
      avatarUrl: avatarUrl || '',
      bio: bio || '',
      passwordHash,
      verified: false
    };

    // 3) write to DynamoDB
    await ddb.put({ TableName: USER_TABLE, Item: newUser }).promise();

    // 4) create a short-lived JWT (1h)
    const verificationJwt = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });

    // 5) send the verification link (NOTE: '/api/user/verify' to match your mount)
    const link = `${process.env.API_URL}/api/user/verify?token=${verificationJwt}`;
    await transporter.sendMail({
      from: process.env.EMAIL_RECEIVER,   // match transporter user
      to: email,
      subject: 'Verify Your Account',
      text: `Click to verify your email: ${link}`
    });

    return res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error('[user/create] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Verify User (validate JWT, then flip `verified` flag)
router.get('/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, email } = decoded;

    await ddb.update({
      TableName: USER_TABLE,
      Key: { email },
      UpdateExpression: 'SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    // issue regular auth JWT (2d)
    const authJwt = jwt.sign({ id, role: 'user', email }, JWT_SECRET, { expiresIn: '2d' });

    return res.json({ token: authJwt });
  } catch (err) {
    console.error('[user/verify] Error:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Login User (same pattern as NGO — keep query logic)
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Missing fields.' });

  try {
    const params = identifier.includes('@')
      ? {
          TableName: USER_TABLE,
          KeyConditionExpression: 'email = :id',
          ExpressionAttributeValues: { ':id': identifier }
        }
      : {
          TableName: USER_TABLE,
          IndexName: 'phone-index',
          KeyConditionExpression: 'phone = :id',
          ExpressionAttributeValues: { ':id': identifier }
        };

    const { Items } = await ddb.query(params).promise();
    if (!Items || !Items.length) return res.status(401).json({ error: 'Invalid credentials.' });

    const user = Items[0];
    if (!user.verified) return res.status(401).json({ error: 'Email not verified.' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

    const jwtTok = jwt.sign(
      { id: user.id, role: 'user', email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token: jwtTok });
  } catch (err) {
    console.error('[user/login] Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Protected profile
router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Forbidden.' });
  try {
    const { Item } = await ddb.get({ TableName: USER_TABLE, Key: { email: req.user.email } }).promise();
    if (!Item) return res.status(404).json({ error: 'User not found.' });
    res.json({ profile: Item });
  } catch (err) {
    console.error('[user/me] Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
