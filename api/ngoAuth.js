// routes/ngoAuth.js
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

// Configure AWS from .env
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const NGO_TABLE = process.env.NGO_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

// Mailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_RECEIVER, pass: process.env.EMAIL_PASS }
});

// Create NGO
// Create NGO (using a JWT for verification)
router.post('/create', async (req, res) => {
  const { email, phone, name, location, password, inventorySize, requiredClothing, logoUrl, bio, summary } = req.body;
  if (!email || !phone || !name || !location || !password)
    return res.status(400).json({ error: 'Missing required fields.' });

  try {
    // 1) ensure not already registered
    const { Item } = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();
    if (Item) return res.status(409).json({ error: 'NGO already exists.' });

    // 2) hash password & create base item (no verificationToken field)
    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const item = {
      id, email, phone, name, location,
      passwordHash,
      inventorySize: inventorySize||0,
      requiredClothing: requiredClothing||'',
      logoUrl: logoUrl||'',
      bio: bio||'', summary: summary||'',
      verified: false
    };

    // 3) store in DynamoDB
    await ddb.put({ TableName: NGO_TABLE, Item: item }).promise();

    // 4) create a short-lived JWT as verification token
    const verificationJwt = jwt.sign(
      { id, email }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // 5) send verification email
    const link = `${process.env.API_URL}/ngo/verify?token=${verificationJwt}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify NGO Account',
      text: `Please verify your account by clicking: ${link}`
    });

    res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Verify NGO
// Verify NGO (JWT-based)
router.get('/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    // 1) verify & decode the JWT
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, email } = decoded;

    // 2) mark the NGO as verified
    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email },
      UpdateExpression: 'SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    // 3) generate your regular auth‑JWT for the NGO
    const authToken = jwt.sign(
      { id, role: 'ngo', email },
      JWT_SECRET,
      { expiresIn: '2d' }
    );

    res.json({
      token: authToken,
      ngo: { id, email, role: 'ngo', name: decoded.name || null }
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Login NGO
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Missing fields.' });

  try {
    const params = identifier.includes('@')
      ? { TableName: NGO_TABLE, KeyConditionExpression: 'email = :id', ExpressionAttributeValues: { ':id': identifier } }
      : { TableName: NGO_TABLE, IndexName: 'phone-index', KeyConditionExpression: 'phone = :id', ExpressionAttributeValues: { ':id': identifier } };

    const { Items } = await ddb.query(params).promise();
    if (!Items.length) return res.status(401).json({ error: 'Invalid credentials.' });

    const ngo = Items[0];
    if (!ngo.verified) return res.status(401).json({ error: 'Email not verified.' });

    const match = await bcrypt.compare(password, ngo.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    const jwtToken = jwt.sign(
      { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token: jwtToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Protected profile route
router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });
  try {
    const { Item } = await ddb.get({ TableName: NGO_TABLE, Key: { email: req.user.email } }).promise();
    if (!Item) return res.status(404).json({ error: 'NGO not found.' });
    res.json({ profile: Item });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
