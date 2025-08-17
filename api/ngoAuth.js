const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const multer = require('multer');

require('dotenv').config();

// Configure AWS from .env
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();
const NGO_TABLE = process.env.NGO_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;
const LOGOS_BUCKET = process.env.LOGOS_BUCKET;

// Multer setup for single logo upload
const upload = multer({ storage: multer.memoryStorage() });

// Mailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_RECEIVER, pass: process.env.EMAIL_PASS }
});
router.get('/ngos', async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: NGO_TABLE }).promise();
    res.json(data.Items);
  } catch (err) {
    console.error('Error fetching NGOs:', err);
    res.status(500).json({ error: 'Server error fetching NGOs' });
  }
});
// Create NGO
router.post('/create', upload.single('logo'), async (req, res) => {
  const { email, phone, name, location, password, inventorySize, requiredClothing, bio, summary } = req.body;
  let { logoUrl } = req.body;

  if (!email || !phone || !name || !location || !password) {
    console.error('Missing required fields:', { email, phone, name, location });
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
    // handle logo upload to S3 if provided
    if (req.file) {
      const key = `logos/${uuidv4()}-${req.file.originalname}`;
      const params = {
        Bucket: LOGOS_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,

      };
      const uploadResult = await s3.upload(params).promise();
      logoUrl = uploadResult.Location;
      console.log('Logo uploaded to S3 at:', logoUrl);
    }

    // 1) ensure not already registered
    const { Item } = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();
    if (Item) {
      console.error('NGO already exists:', email);
      return res.status(409).json({ error: 'NGO already exists.' });
    }

    // 2) hash password & create base item (no verificationToken field)
    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const item = {
      id, email, phone, name, location,
      passwordHash,
      inventorySize: inventorySize || 0,
      requiredClothing: requiredClothing || '',
      logoUrl: logoUrl || '',
      bio: bio || '',
      summary: summary || '',
      verified: false
    };

    console.log('Storing NGO item:', item);
    // 3) store in DynamoDB
    await ddb.put({ TableName: NGO_TABLE, Item: item }).promise();

    // 4) create a short-lived JWT as verification token
    const verificationJwt = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });

    // 5) send verification email
    const link = `${process.env.API_URL}/ngo/verify?token=${verificationJwt}`;
    console.log('Sending verification email with link:', link);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify NGO Account',
      text: `Please verify your account by clicking: ${link}`
    });

    res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error('Error in /create NGO route:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});
// Verify NGO
router.get('/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, email } = decoded;

    // ⚠️ Adjust Key depending on your DynamoDB PK
    // If PK = email, use { email }
    // If PK = id, use { id }
    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email }, // change to { id } if your PK is `id`
      UpdateExpression: 'SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    return res.redirect(`${FRONTEND_URL}/login?verified=1`);
  } catch (err) {
    console.error('Error verifying token:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// ------------------ Login NGO ------------------
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  try {
    let ngo = null;

    if (identifier.includes('@')) {
      // email path (try lowercase first, then raw to support legacy)
      const emailNorm = identifier.trim().toLowerCase();
      const out1 = await ddb.get({ TableName: NGO_TABLE, Key: { email: emailNorm } }).promise();
      ngo = out1.Item || null;

      if (!ngo) {
        const out2 = await ddb.get({ TableName: NGO_TABLE, Key: { email: identifier.trim() } }).promise();
        ngo = out2.Item || null;
      }
    } else {
      // phone path via GSI
      const out = await ddb.query({
        TableName: NGO_TABLE,
        IndexName: 'phone-index',
        KeyConditionExpression: '#p = :id',
        ExpressionAttributeNames: { '#p': 'phone' },
        ExpressionAttributeValues: { ':id': identifier }
      }).promise();
      ngo = (out.Items && out.Items[0]) || null;
    }

    if (!ngo) return res.status(401).json({ error: 'Invalid credentials.' });
    if (!ngo.verified) return res.status(401).json({ error: 'Email not verified.' });

    const match = await bcrypt.compare(password, ngo.passwordHash || '');
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    const jwtToken = jwt.sign(
      { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({ token: jwtToken });
  } catch (err) {
    console.error('[NGO][LOGIN] ERROR:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
}); // <-- this was missing in your file

router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });
  try {
    const { Item } = await ddb.get({ TableName: NGO_TABLE, Key: { email: req.user.email } }).promise();
    if (!Item) return res.status(404).json({ error: 'NGO not found.' });
    res.json({ profile: Item });
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

//Update NGO
router.put('/update/:id', authenticateJWT, upload.single('logo'), async (req, res) => {
  const ngoId = req.params.id;

  // role and NGO checks
  if (req.user.role !== 'ngo' || req.user.id !== ngoId) {
    return res.status(403).json({ error: 'Forbidden. You can only update your own NGO.' });
  }

  try {
    const updateFields = {};
    const allowedFields = ['phone', 'inventorySize', 'requiredClothing', 'bio', 'summary'];

    // collect allowed fields
    for (let field of allowedFields) {
      if (req.body[field] !== undefined) {
        updateFields[field] = req.body[field];
      }
    }

    // handle logo upload if provided
    if (req.file) {
      const key = `logos/${uuidv4()}-${req.file.originalname}`;
      const params = {
        Bucket: LOGOS_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'public-read'
      };
      const uploadResult = await s3.upload(params).promise();
      updateFields.logoUrl = uploadResult.Location;
    }

    // build update expression
    const updateExp = [];
    const expAttrVals = {};
    for (let [k, v] of Object.entries(updateFields)) {
      updateExp.push(`${k} = :${k}`);
      expAttrVals[`:${k}`] = v;
    }

    if (updateExp.length === 0) {
      return res.status(400).json({ error: 'No valid fields provided for update.' });
    }

    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: req.user.email }, // email is the PK
      UpdateExpression: 'SET ' + updateExp.join(', '),
      ExpressionAttributeValues: expAttrVals
    }).promise();

    res.json({ status: 'updated' });
  } catch (err) {
    console.error('Error updating NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

router.delete('/delete/:id', authenticateJWT, async (req, res) => {
  const ngoId = req.params.id;

  // role and NGO checks
  if (req.user.role !== 'ngo' || req.user.id !== ngoId) {
    return res.status(403).json({ error: 'Forbidden. You can only delete your own NGO.' });
  }

  try {
    await ddb.delete({
      TableName: NGO_TABLE,
      Key: { email: req.user.email }
    }).promise();

    res.json({ status: 'deleted' });
  } catch (err) {
    console.error('Error deleting NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
