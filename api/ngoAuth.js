// routes/ngoAuth.js
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Configure AWS DynamoDB
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
// POST /ngo/create
router.post('/create', async (req, res) => {
  const { email, phone, name, location, password, inventorySize, requiredClothing, logoUrl, bio, summary } = req.body;
  if (!email || !phone || !name || !location || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  try {
    // Check existing by email or phone
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
// GET /ngo/verify?token=
router.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required.' });
  try {
    // Scan to find token match
    const { Items } = await ddb.scan({ TableName: NGO_TABLE, FilterExpression: 'verificationToken = :t', ExpressionAttributeValues: { ':t': token } }).promise();
    if (!Items.length) return res.status(400).json({ error: 'Invalid or expired token.' });
    const ngo = Items[0];
    // Update verified
    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: ngo.email },
      UpdateExpression: 'REMOVE verificationToken SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();
    // Generate JWT
    const tokenJwt = jwt.sign({ id: ngo.id, role: 'ngo' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token: tokenJwt, ngo: { id: ngo.id, name: ngo.name, email: ngo.email, phone: ngo.phone, location: ngo.location, role: 'ngo' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Login NGO
// POST /ngo/login
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Missing fields.' });
  try {
    // Query by email or phone
    const params = identifier.includes('@') ?
      { TableName: NGO_TABLE, KeyConditionExpression: 'email = :id', ExpressionAttributeValues: { ':id': identifier } } :
      { TableName: NGO_TABLE, IndexName: 'phone-index', KeyConditionExpression: 'phone = :id', ExpressionAttributeValues: { ':id': identifier } };
    const { Items } = await ddb.query(params).promise();
    if (!Items.length) return res.status(401).json({ error: 'Invalid credentials.' });
    const ngo = Items[0];
    if (!ngo.verified) return res.status(401).json({ error: 'Email not verified.' });
    const match = await bcrypt.compare(password, ngo.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });
    const tokenJwt = jwt.sign({ id: ngo.id, role: 'ngo' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token: tokenJwt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Protected middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized.' });
  const token = auth.split(' ')[1];
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    req.user = dec;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token.' });
  }
}

// Update NGO Profile
// PATCH /ngo
router.patch('/', authMiddleware, async (req, res) => {
  const updates = req.body;
  delete updates.password; // handle separately if needed
  const expr = [];
  const attrs = {};
  for (let key in updates) { expr.push(`${key} = :${key}`); attrs[`:${key}`] = updates[key]; }
  const UpdateExpression = 'SET ' + expr.join(', ');
  try {
    await ddb.update({ TableName: NGO_TABLE, Key: { email: req.user.email }, UpdateExpression, ExpressionAttributeValues: attrs }).promise();
    res.json({ status: 'updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete NGO Account
// DELETE /ngo
router.delete('/', authMiddleware, async (req, res) => {
  try {
    await ddb.delete({ TableName: NGO_TABLE, Key: { email: req.user.email } }).promise();
    res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;


// routes/userAuth.js
const express = require('express');
const uRouter = express.Router();
const AWS2 = require('aws-sdk');
const crypto2 = require('crypto');
const jwt2 = require('jsonwebtoken');
const bcrypt2 = require('bcrypt');
const nodemailer2 = require('nodemailer');
const { v4: uuid2 } = require('uuid');
require('dotenv').config();

AWS2.config.update({ region: process.env.AWS_REGION });
const ddb2 = new AWS2.DynamoDB.DocumentClient();
const USER_TABLE = process.env.USER_TABLE;
const JWT_SECRET2 = process.env.JWT_SECRET;

const transporter2 = nodemailer2.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// Create User Account
// POST /user/create
uRouter.post('/create', async (req, res) => {
  const { email, phone, name, location, avatarUrl, bio, password } = req.body;
  if (!email || !phone || !name || !password) return res.status(400).json({ error: 'Missing required.' });
  try {
    const existing = await ddb2.get({ TableName: USER_TABLE, Key: { email } }).promise();
    if (existing.Item) return res.status(409).json({ error: 'User exists.' });
    const hashed = await bcrypt2.hash(password, 10);
    const verificationToken = crypto2.randomBytes(32).toString('hex');
    const id = uuid2();
    const item2 = { id, email, phone, name, location: location || '', avatarUrl: avatarUrl || '', bio: bio || '', passwordHash: hashed, verified: false, verificationToken };
    await ddb2.put({ TableName: USER_TABLE, Item: item2 }).promise();
    const link2 = `${process.env.API_URL}/user/verify?token=${verificationToken}`;
    await transporter2.sendMail({ from: process.env.EMAIL_USER, to: email, subject: 'Verify User', text: `Click: ${link2}` });
    res.status(201).json({ status: 'accepted' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Verify User Account
// GET /user/verify?token=
uRouter.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required.' });
  try {
    const { Items } = await ddb2.scan({ TableName: USER_TABLE, FilterExpression: 'verificationToken = :t', ExpressionAttributeValues: { ':t': token } }).promise();
    if (!Items.length) return res.status(400).json({ error: 'Invalid or expired token.' });
    const user = Items[0];
    await ddb2.update({ TableName: USER_TABLE, Key: { email: user.email }, UpdateExpression: 'REMOVE verificationToken SET verified = :v', ExpressionAttributeValues: { ':v': true } }).promise();
    const jwtTok = jwt2.sign({ id: user.id, role: 'user' }, JWT_SECRET2, { expiresIn: '7d' });
    res.json({ token: jwtTok });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// User Login
// POST /user/login
uRouter.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Missing.' });
  try {
    const params2 = identifier.includes('@') ?
      { TableName: USER_TABLE, KeyConditionExpression: 'email = :id', ExpressionAttributeValues: { ':id': identifier } } :
      { TableName: USER_TABLE, IndexName: 'phone-index', KeyConditionExpression: 'phone = :id', ExpressionAttributeValues: { ':id': identifier } };
    const { Items } = await ddb2.query(params2).promise();
    if (!Items.length) return res.status(401).json({ error: 'Invalid.' });
    const user = Items[0];
    if (!user.verified) return res.status(401).json({ error: 'Not verified.' });
    const ok = await bcrypt2.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid.' });
    const jwtUser = jwt2.sign({ id: user.id, role: 'user' }, JWT_SECRET2, { expiresIn: '7d' });
    res.json({ token: jwtUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Auth middleware shared
function auth2(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Unauthorized.' });
  const tk = h.split(' ')[1];
  try { req.user = jwt2.verify(tk, JWT_SECRET2); next(); } catch { res.status(401).json({ error: 'Invalid token.' }); }
}

// Update User Account
// PATCH /user
uRouter.patch('/', auth2, async (req, res) => {
  const up = req.body;
  delete up.password;
  const ex = [], av = {};
  for (let k in up) { ex.push(`${k} = :${k}`); av[`:${k}`] = up[k]; }
  const UE = 'SET ' + ex.join(', ');
  try {
    await ddb2.update({ TableName: USER_TABLE, Key: { email: req.user.email }, UpdateExpression: UE, ExpressionAttributeValues: av }).promise();
    res.json({ status: 'updated' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error.' }); }
});

// Delete User Account
// DELETE /user
uRouter.delete('/', auth2, async (req, res) => {
  try {
    await ddb2.delete({ TableName: USER_TABLE, Key: { email: req.user.email } }).promise();
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = { ngoRouter: router, userRouter: uRouter };
