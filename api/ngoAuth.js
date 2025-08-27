// api/ngoAuth.js
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const multer = require('multer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

// ----- ENV / CONFIG -----
const NGO_TABLE     = process.env.NGO_TABLE;
const JWT_SECRET    = process.env.JWT_SECRET;
const LOGOS_BUCKET  = process.env.LOGOS_BUCKET;
const API_URL       = process.env.API_URL || 'http://localhost:4000';
const FRONTEND_URL  = process.env.FRONTEND_URL || 'http://localhost:3000';
const OAUTH_CALLBACK = `${String(API_URL).replace(/\/+$/,'')}/api/ngo/auth/google/callback`;
console.log('[NGO][Google] Using callback:', OAUTH_CALLBACK);

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const s3  = new AWS.S3();

const upload = multer({ storage: multer.memoryStorage() });

// Mailer (Gmail App Password recommended)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_RECEIVER,
    pass: process.env.EMAIL_PASS
  }
});

/* ---------------- helpers (added) ---------------- */
async function sendVerificationEmail(id, email) {
  const verificationJwt = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });
  const link = `${API_URL}/api/ngo/verify?token=${verificationJwt}`;
  await transporter.sendMail({
    from: process.env.EMAIL_RECEIVER,
    to: email,
    subject: 'Verify NGO Account',
    text: `Please verify your account by clicking: ${link}`
  });
}

async function sendEmailChangeVerification(id, oldEmail, newEmail) {
  const token = jwt.sign(
    { id, oldEmail, newEmail, type: 'ngo_email_change' },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  const link = `${API_URL}/api/ngo/verify-email-change?token=${token}`;
  await transporter.sendMail({
    from: process.env.EMAIL_RECEIVER,
    to: newEmail,
    subject: 'Confirm your new email for TyebeTyebak (NGO)',
    text: `You requested to change your NGO email from ${oldEmail} to ${newEmail}.\n\nConfirm the change by clicking: ${link}\n\nIf you didn't request this, ignore this message.`
  });
}

/* ---------------- Google OAuth (NGO) ---------------- */
router.use(passport.initialize());
passport.use('ngo-google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID1,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET1,
      callbackURL: OAUTH_CALLBACK, // <— use the constant here
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || '').toLowerCase();
        if (!email) return done(new Error('Missing email from Google profile'));

        const out = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();
        let ngo = out.Item || null;

        if (!ngo) {
          // Create NGO record once, mark verified:false, and send verification email
          const id = uuidv4();
          const name =
            profile.displayName ||
            [profile.name?.givenName, profile.name?.familyName].filter(Boolean).join(' ') ||
            'New NGO';
          const logoUrl = profile.photos?.[0]?.value || '';

          const item = {
            id, email, phone: '', name, location: '',
            coordinates: {lat: null, lng: null },
            passwordHash: '',
            inventorySize: 0, requiredClothing: '',
            logoUrl, bio: '', summary: '',
            verified: false, createdAt: Date.now()
          };

          await ddb.put({
            TableName: NGO_TABLE,
            Item: item,
            ConditionExpression: 'attribute_not_exists(email)'
          }).promise();

          try { await sendVerificationEmail(id, email); } catch (e) { console.error('Verify email send failed:', e); }

          // Signal to callback that account is created but unverified
          return done(null, { createdButUnverified: true, email });
        }

        // Existing NGO
        return done(null, ngo);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Kick off Google OAuth
router.get('/auth/google',
  passport.authenticate('ngo-google', { scope: ['profile', 'email'] })
);

// Callback
router.get('/auth/google/callback',
  passport.authenticate('ngo-google', { session: false, failureRedirect: `${FRONTEND_URL}/login` }),
  async (req, res) => {
    try {
      // New user created via Google and still unverified -> redirect to signup with message
      if (req.user && req.user.createdButUnverified) {
        const email = encodeURIComponent(req.user.email);
        return res.redirect(`${FRONTEND_URL}/signup/ngo?email=${email}&created=1&checkEmail=1`);
      }

      const ngo = req.user;

      // Existing but unverified -> redirect to login prompting verification (no JWT)
      if (!ngo.verified) {
        const email = encodeURIComponent(ngo.email);
        return res.redirect(`${FRONTEND_URL}/login?verify=needed&email=${email}`);
      }

      // Only issue JWT if existing and verified
      const jwtToken = jwt.sign(
        { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      const userData = {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone || '',
        location: ngo.location || '',
        logoUrl: ngo.logoUrl || '',
        verified: !!ngo.verified
      };
      const userDataString = encodeURIComponent(JSON.stringify(userData));

      const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
      if (wantsJson) return res.json({ token: jwtToken, user: userData });

      return res.redirect(`${FRONTEND_URL}/login?token=${jwtToken}&user=${userDataString}`);
    } catch (err) {
      console.error('[NGO][GOOGLE CALLBACK] ERROR:', err);
      return res.status(500).json({ error: 'OAuth error' });
    }
  }
);

/* ------------- The rest of your NGO endpoints ------------- */

// List NGOs
router.get('/ngos', async (_req, res) => {
  try {
    const data = await ddb.scan({ TableName: NGO_TABLE }).promise();
    res.json(data.Items || []);
  } catch (err) {
    console.error('Error fetching NGOs:', err);
    res.status(500).json({ error: 'Server error fetching NGOs' });
  }
});

// Create NGO (email/password flow)
router.post('/create', upload.single('logo'), async (req, res) => {
  let {
    email, phone, name, location, password,
    inventorySize, requiredClothing, bio, summary, coordinates
  } = req.body;
  let { logoUrl } = req.body;

  email = (email || '').trim().toLowerCase();
  if (!email || !phone || !name || !location || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
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
      logoUrl = uploadResult.Location;
    }

    const existing = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();
    if (existing.Item) return res.status(409).json({ error: 'NGO already exists.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();

    const item = {
      id, email, phone, name,
      location: (location || '').trim(),
      coordinates: {
        lat: coordinates?.lat !== undefined ? Number(coordinates.lat) : null,
        lng: coordinates?.lng !== undefined ? Number(coordinates.lng) : null
      },
      passwordHash,
      inventorySize: Number(inventorySize) || 0,
      requiredClothing: requiredClothing || '',
      logoUrl: logoUrl || '',
      bio: bio || '',
      summary: summary || '',
      verified: false,
      createdAt: Date.now()
    };

    await ddb.put({
      TableName: NGO_TABLE,
      Item: item,
      ConditionExpression: 'attribute_not_exists(email)'
    }).promise();

    const verificationJwt = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });

    // 5) send verification email
    const link = `${API_URL}/api/ngo/verify?token=${verificationJwt}`;
    console.log('Sending verification email with link:', link);
    await transporter.sendMail({
      from: process.env.EMAIL_RECEIVER,
      to: email,
      subject: 'Verify NGO Account',
      text: `Please verify your account by clicking: ${link}`
    });

    return res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error('Error in /create NGO route:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});


// Verify route (responds to GET /api/ngo/verify?token=...)
router.get('/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const { id, email } = jwt.verify(token, JWT_SECRET);
    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: (email || '').toLowerCase() },
      UpdateExpression: 'SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    // This shows your green “verified” banner on the login page
    return res.redirect(`${FRONTEND_URL}/login?verified=1`);
  } catch (err) {
    console.error('Error verifying token:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Verify email change (GET /api/ngo/verify-email-change?token=...)
router.get('/verify-email-change', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const { id, oldEmail, newEmail, type } = jwt.verify(token, JWT_SECRET);
    if (type !== 'ngo_email_change') {
      return res.status(400).json({ error: 'Invalid token type.' });
    }

    const oldKey = (oldEmail || '').toLowerCase();
    const newKey = (newEmail || '').toLowerCase();

    // New email must still be unused
    const { Item: newExists } = await ddb.get({ TableName: NGO_TABLE, Key: { email: newKey } }).promise();
    if (newExists) {
      return res.status(400).json({ error: 'Email already in use.' });
    }

    const { Item: oldItem } = await ddb.get({ TableName: NGO_TABLE, Key: { email: oldKey } }).promise();
    if (!oldItem || oldItem.id !== id) {
      return res.status(400).json({ error: 'Account not found or mismatch.' });
    }

    // Copy to new PK with verified=true (email confirmed),
    // clean up pending fields, and carry over everything else
    const newItem = {
      ...oldItem,
      email: newKey,
      verified: true,
      previousEmail: oldKey
    };
    delete newItem.pendingEmail;
    delete newItem.pendingEmailRequestedAt;

    await ddb.put({
      TableName: NGO_TABLE,
      Item: newItem,
      ConditionExpression: 'attribute_not_exists(email)'
    }).promise();

    // remove old record
    await ddb.delete({
      TableName: NGO_TABLE,
      Key: { email: oldKey }
    }).promise();

    // Redirect with success banner
    return res.redirect(`${FRONTEND_URL}/login?verified=1&emailChanged=1`);
  } catch (err) {
    console.error('Error verifying email change:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Login NGO
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  try {
    let ngo = null;

    if (identifier.includes('@')) {
      const emailNorm = identifier.trim().toLowerCase();
      const out = await ddb.get({ TableName: NGO_TABLE, Key: { email: emailNorm } }).promise();
      ngo = out.Item || null;
    } else {
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

    return res.json({
      token: jwtToken,
      user: {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone,
        location: ngo.location,
        logoUrl: ngo.logoUrl || '',
        verified: !!ngo.verified
      }
    });
  } catch (err) {
    console.error('[NGO][LOGIN] ERROR:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Me (read)
router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });
  try {
    const { Item } = await ddb.get({
      TableName: NGO_TABLE,
      Key: { email: (req.user.email || '').toLowerCase() }
    }).promise();

    if (!Item) return res.status(404).json({ error: 'NGO not found.' });
    res.json({ profile: Item });
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ error: 'Server error.' });
  }
  
});

// Me (patch) — aligns with your frontend PATCH /ngo/me
router.patch('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });

  try {
    // Accepted fields from your editor
    const {
      name,
      email,          // if different, we trigger email-change flow (reverification)
      phone,
      location,       // can be string or object
      summary,        // maps to summary/bio
      logoUrl,
      coordinates,
    } = req.body;

    // 1) Email change -> initiate reverification flow and return 202
    const currentEmail = (req.user.email || '').toLowerCase();
    if (email && email.toLowerCase() !== currentEmail) {
      const desired = email.toLowerCase();

      // ensure new email not taken
      const { Item: exists } = await ddb.get({ TableName: NGO_TABLE, Key: { email: desired } }).promise();
      if (exists) return res.status(409).json({ error: 'Email already in use.' });

      // mark pending on current record (optional but helpful)
      await ddb.update({
        TableName: NGO_TABLE,
        Key: { email: currentEmail },
        UpdateExpression: 'SET pendingEmail = :pe, pendingEmailRequestedAt = :t',
        ExpressionAttributeValues: {
          ':pe': desired,
          ':t': Date.now()
        }
      }).promise();

      try {
        await sendEmailChangeVerification(req.user.id, currentEmail, desired);
      } catch (e) {
        console.error('Email change verify send failed:', e);
        // Clear pending flags on failure
        await ddb.update({
          TableName: NGO_TABLE,
          Key: { email: currentEmail },
          UpdateExpression: 'REMOVE pendingEmail, pendingEmailRequestedAt'
        }).promise();
        return res.status(500).json({ error: 'Failed to send verification email.' });
      }

      return res.status(202).json({ status: 'verify_new_email_sent' });
    }

    // 2) Normal profile updates (no PK changes)
    const updateFields = {};
    if (name !== undefined) updateFields.name = name;
    if (phone !== undefined) updateFields.phone = phone;
    if (logoUrl !== undefined) updateFields.logoUrl = logoUrl;
    if (summary !== undefined) {
      // keep both summary and bio in sync-ish
      updateFields.summary = summary;
      updateFields.bio = summary;
    }
    if (location !== undefined || coordinates !== undefined) {
      const current = await ddb.get({
        TableName: NGO_TABLE,
        Key: { email: currentEmail }
      }).promise();

      const existing = current.Item || {};

      updateFields.location =
        location !== undefined ? String(location).trim() : existing.location || '';

      updateFields.coordinates = {
        lat: coordinates?.lat !== undefined ? Number(coordinates.lat) : existing?.coordinates?.lat || null,
        lng: coordinates?.lng !== undefined ? Number(coordinates.lng) : existing?.coordinates?.lng || null
      };
    }


    if (Object.keys(updateFields).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided for update.' });
    }

    const setParts = [];
    const exprVals = {};
    const exprNames = {};
    for (const [k, v] of Object.entries(updateFields)) {
      setParts.push(`#${k} = :${k}`);
      exprVals[`:${k}`] = v;
      exprNames[`#${k}`] = k;
    }

    const { Attributes } = await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: currentEmail },
      UpdateExpression: 'SET ' + setParts.join(', '),
      ExpressionAttributeNames: exprNames,
      ExpressionAttributeValues: exprVals,
      ReturnValues: 'ALL_NEW'
    }).promise();

    return res.json({ profile: Attributes });
  } catch (err) {
    console.error('Error updating NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete — new endpoint to match frontend: DELETE /api/ngo/me
router.delete('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });

  try {
    await ddb.delete({
      TableName: NGO_TABLE,
      Key: { email: (req.user.email || '').toLowerCase() }
    }).promise();

    return res.json({ status: 'deleted' });
  } catch (err) {
    console.error('Error deleting NGO (me):', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
