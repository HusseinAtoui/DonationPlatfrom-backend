const express = require('express');
const uRouter = express.Router();
const AWS = require('aws-sdk');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth'); // ✅ Shared middleware
require('dotenv').config();

AWS.config.update({ region: process.env.AWS_REGION });
const ddb = new AWS.DynamoDB.DocumentClient();
const USER_TABLE = process.env.USER_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// Create User Account
uRouter.post('/create', async (req, res) => {
  const { email, phone, name, location, avatarUrl, bio, password } = req.body;
  if (!email || !phone || !name || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
    const existing = await ddb.get({ TableName: USER_TABLE, Key: { email } }).promise();
    if (existing.Item) return res.status(409).json({ error: 'User already exists.' });

    const hashed = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const id = uuidv4();

    const item = {
      id,
      email,
      phone,
      name,
      location: location || '',
      avatarUrl: avatarUrl || '',
      bio: bio || '',
      passwordHash: hashed,
      verified: false,
      verificationToken
    };

    await ddb.put({ TableName: USER_TABLE, Item: item }).promise();

    const link = `${process.env.API_URL}/user/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Account',
      text: `Click to verify your email: ${link}`
    });

    res.status(201).json({ status: 'accepted' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Verify User Account
uRouter.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const { Items } = await ddb.scan({
      TableName: USER_TABLE,
      FilterExpression: 'verificationToken = :t',
      ExpressionAttributeValues: { ':t': token }
    }).promise();

    if (!Items.length) return res.status(400).json({ error: 'Invalid or expired token.' });

    const user = Items[0];

    await ddb.update({
      TableName: USER_TABLE,
      Key: { email: user.email },
      UpdateExpression: 'REMOVE verificationToken SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    const jwtTok = jwt.sign(
      { id: user.id, role: 'user', email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token: jwtTok });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// User Login
uRouter.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

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
    if (!Items.length) return res.status(401).json({ error: 'Invalid credentials.' });

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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Get current user profile (protected)
// GET /user/me
uRouter.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Forbidden: not a user account.' });
  }

  try {
    const { Item } = await ddb.get({
      TableName: USER_TABLE,
      Key: { email: req.user.email }
    }).promise();

    if (!Item) return res.status(404).json({ error: 'User not found.' });

    res.json({ profile: Item });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = uRouter;
