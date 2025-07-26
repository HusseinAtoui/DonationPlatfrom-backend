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

// AWS DynamoDB Config
AWS.config.update({ region: process.env.AWS_REGION });
const ddb = new AWS.DynamoDB.DocumentClient();
const NGO_TABLE = process.env.NGO_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Create NGO Account
router.post('/create', async (req, res) => {
  const {
    email, phone, name, location, password,
    inventorySize, requiredClothing, logoUrl, bio, summary
  } = req.body;

  if (!email || !phone || !name || !location || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
    const existing = await ddb.get({
      TableName: NGO_TABLE,
      Key: { email }
    }).promise();

    if (existing.Item) return res.status(409).json({ error: 'NGO already exists.' });

    const hashed = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const id = uuidv4();

    const item = {
      id,
      email,
      phone,
      name,
      location,
      passwordHash: hashed,
      inventorySize: inventorySize || 0,
      requiredClothing: requiredClothing || '',
      logoUrl: logoUrl || '',
      bio: bio || '',
      summary: summary || '',
      verified: false,
      verificationToken
    };

    await ddb.put({ TableName: NGO_TABLE, Item: item }).promise();

    const link = `${process.env.API_URL}/ngo/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify NGO Account',
      text: `Click to verify: ${link}`
    });

    res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Verify NGO Account
router.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const { Items } = await ddb.scan({
      TableName: NGO_TABLE,
      FilterExpression: 'verificationToken = :t',
      ExpressionAttributeValues: { ':t': token }
    }).promise();

    if (!Items.length) return res.status(400).json({ error: 'Invalid or expired token.' });

    const ngo = Items[0];

    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: ngo.email },
      UpdateExpression: 'REMOVE verificationToken SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    const tokenJwt = jwt.sign(
      { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token: tokenJwt,
      ngo: {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone,
        location: ngo.location,
        role: 'ngo'
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Login NGO
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password)
    return res.status(400).json({ error: 'Missing fields.' });

  try {
    const params = identifier.includes('@')
      ? {
          TableName: NGO_TABLE,
          KeyConditionExpression: 'email = :id',
          ExpressionAttributeValues: { ':id': identifier }
        }
      : {
          TableName: NGO_TABLE,
          IndexName: 'phone-index',
          KeyConditionExpression: 'phone = :id',
          ExpressionAttributeValues: { ':id': identifier }
        };

    const { Items } = await ddb.query(params).promise();
    if (!Items.length) return res.status(401).json({ error: 'Invalid credentials.' });

    const ngo = Items[0];
    if (!ngo.verified) return res.status(401).json({ error: 'Email not verified.' });

    const match = await bcrypt.compare(password, ngo.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    const tokenJwt = jwt.sign(
      { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token: tokenJwt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Example protected route
router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') {
    return res.status(403).json({ error: 'Forbidden: Not an NGO user' });
  }

  try {
    const { Item } = await ddb.get({
      TableName: NGO_TABLE,
      Key: { email: req.user.email }
    }).promise();

    if (!Item) return res.status(404).json({ error: 'NGO not found' });

    res.json({ profile: Item });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
