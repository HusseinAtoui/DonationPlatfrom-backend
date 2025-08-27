// routes/userAuth.js
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

require('dotenv').config();

// ----------------------------------------------------------------------------
// Config
// ----------------------------------------------------------------------------
const API_URL = (process.env.API_URL || 'http://localhost:4000').replace(/\/+$/, '');
const FRONTEND_URL = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/+$/, '');
const USER_OAUTH_CALLBACK = `${API_URL}/api/user/auth/google/callback`;

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();

const USER_TABLE = process.env.USER_TABLE; // PK = email (S). Add GSI: phone-index (HASH=phone).
const JWT_SECRET = process.env.JWT_SECRET;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_RECEIVER, pass: process.env.EMAIL_PASS }
});

const nowTs = () => Date.now();

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function issueAuthToken(user) {
  return jwt.sign(
    { id: user.id, role: 'user', email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function sanitizeProfileForClient(u) {
  // Omit sensitive fields
  const {
    passwordHash, verificationToken, pendingNewEmail, pendingEmailToken,
    ...safe
  } = u || {};
  return safe;
}

// ----------------------------------------------------------------------------
// Signup (email verification)
// ----------------------------------------------------------------------------
router.post('/create', async (req, res) => {
  try {
    const { email, phone, name, location, avatarUrl, bio, password } = req.body || {};
    if (!email || !phone || !name || !password) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    const normEmail = String(email).toLowerCase().trim();

    // Check existing by email
    const existing = await ddb.get({ TableName: USER_TABLE, Key: { email: normEmail } }).promise();
    if (existing.Item) return res.status(409).json({ error: 'User already exists.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const newUser = {
      id,
      email: normEmail,
      phone: String(phone).trim(),
      name: String(name).trim(),
      location: location || '',
      avatarUrl: avatarUrl || '',
      bio: bio || '',
      passwordHash,
      verified: false,
      createdAt: nowTs()
    };

    await ddb.put({ TableName: USER_TABLE, Item: newUser }).promise();

    // Email verification token (1h)
    const verificationJwt = jwt.sign({ id, email: normEmail, typ: 'user-email-verify' }, JWT_SECRET, { expiresIn: '1h' });
    const link = `${API_URL}/api/user/verify?token=${encodeURIComponent(verificationJwt)}`;
    await transporter.sendMail({
      from: process.env.EMAIL_RECEIVER,
      to: normEmail,
      subject: 'Verify Your Account',
      text: `Click to verify your email: ${link}`
    });

    return res.status(201).json({ status: 'accepted' });
  } catch (err) {
    console.error('[user/create] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ----------------------------------------------------------------------------
// Verify email from signup
// ----------------------------------------------------------------------------
router.get('/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token required.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== 'user-email-verify') throw new Error('Wrong token type.');
    const { id, email } = decoded;

    await ddb.update({
      TableName: USER_TABLE,
      Key: { email },
      UpdateExpression: 'SET verified = :v',
      ExpressionAttributeValues: { ':v': true }
    }).promise();

    // Issue app JWT and send JSON (you may also redirect to FRONTEND_URL)
    const authJwt = issueAuthToken({ id, email, name: '' });
    return res.json({ token: authJwt });
  } catch (err) {
    console.error('[user/verify] Error:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// ----------------------------------------------------------------------------
// Login (email OR phone via phone-index GSI)
// ----------------------------------------------------------------------------
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password) return res.status(400).json({ error: 'Missing fields.' });

  try {
    const looksEmail = String(identifier).includes('@');
    const params = looksEmail
      ? {
          TableName: USER_TABLE,
          KeyConditionExpression: 'email = :id',
          ExpressionAttributeValues: { ':id': String(identifier).toLowerCase().trim() }
        }
      : {
          TableName: USER_TABLE,
          IndexName: 'phone-index',
          KeyConditionExpression: 'phone = :id',
          ExpressionAttributeValues: { ':id': String(identifier).trim() }
        };

    const result = await ddb.query(params).promise();
    const user = (result.Items || [])[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
    if (!user.verified) return res.status(401).json({ error: 'Email not verified.' });
    if (!user.passwordHash) return res.status(400).json({ error: 'Use Google login for this account.' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

    const token = issueAuthToken(user);
    return res.json({ token });
  } catch (err) {
    console.error('[user/login] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ----------------------------------------------------------------------------
// Protected: Get profile
// ----------------------------------------------------------------------------
router.get('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Forbidden.' });
  try {
    const { Item } = await ddb.get({ TableName: USER_TABLE, Key: { email: req.user.email } }).promise();
    if (!Item) return res.status(404).json({ error: 'User not found.' });
    return res.json({ profile: sanitizeProfileForClient(Item) });
  } catch (err) {
    console.error('[user/me] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ----------------------------------------------------------------------------
// Protected: Update profile
// - If email changes: send confirm link (202) and DO NOT change PK yet
// - Otherwise: update in place (200)
// ----------------------------------------------------------------------------
router.patch('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Forbidden.' });

  const {
    name,
    email: nextEmailRaw,
    phone,
    location,
    avatarUrl,
    bio
  } = req.body || {};

  const currentEmail = req.user.email;

  try {
    // If requesting email change, send confirmation and store pending fields
    if (nextEmailRaw && nextEmailRaw.toLowerCase().trim() !== currentEmail.toLowerCase()) {
      const nextEmail = String(nextEmailRaw).toLowerCase().trim();
      // Create a short-lived token to confirm email change
      const token = jwt.sign(
        { typ: 'user-email-change', id: req.user.id, currentEmail, newEmail: nextEmail },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      // Save "pending" info on the current record
      await ddb.update({
        TableName: USER_TABLE,
        Key: { email: currentEmail },
        UpdateExpression: 'SET pendingNewEmail = :ne, pendingEmailToken = :tk',
        ExpressionAttributeValues: {
          ':ne': nextEmail,
          ':tk': token
        }
      }).promise();

      // Send to NEW email
      const link = `${API_URL}/api/user/confirm-email?token=${encodeURIComponent(token)}`;
      await transporter.sendMail({
        from: process.env.EMAIL_RECEIVER,
        to: nextEmail,
        subject: 'Confirm your new email',
        text: `Click to confirm your new email address: ${link}`
      });

      return res.status(202).json({ status: 'verification_sent' });
    }

    // Build dynamic update for other fields
    const sets = [];
    const names = {};
    const values = {};

    function setField(fieldName, value) {
      const key = `#${fieldName}`;
      const valKey = `:${fieldName}`;
      sets.push(`${key} = ${valKey}`);
      names[key] = fieldName;
      values[valKey] = value;
    }

    if (typeof name === 'string') setField('name', name.trim());
    if (typeof phone === 'string') setField('phone', phone.trim());
    if (typeof location === 'string' || typeof location === 'object') setField('location', location);
    if (typeof avatarUrl === 'string') setField('avatarUrl', avatarUrl.trim());
    if (typeof bio === 'string') setField('bio', bio);

    if (sets.length === 0) {
      return res.json({ profile: { } }); // nothing to update
    }

    const updateParams = {
      TableName: USER_TABLE,
      Key: { email: currentEmail },
      UpdateExpression: `SET ${sets.join(', ')}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW'
    };

    const out = await ddb.update(updateParams).promise();
    return res.json({ profile: sanitizeProfileForClient(out.Attributes) });
  } catch (err) {
    console.error('[user/patch/me] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ----------------------------------------------------------------------------
// Protected: Delete account
// ----------------------------------------------------------------------------
router.delete('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Forbidden.' });
  try {
    await ddb.delete({ TableName: USER_TABLE, Key: { email: req.user.email } }).promise();
    return res.json({ ok: true });
  } catch (err) {
    console.error('[user/delete/me] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ----------------------------------------------------------------------------
// Confirm new email (moves item to new PK)
// - Validates token, copies record to new email, deletes old record
// - Issues fresh JWT, then redirects to frontend with token (+user payload)
// ----------------------------------------------------------------------------
router.get('/confirm-email', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('Token required.');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== 'user-email-change') throw new Error('Wrong token type.');

    const { id, currentEmail, newEmail } = decoded;

    // Load current item and sanity-check
    const { Item: cur } = await ddb.get({ TableName: USER_TABLE, Key: { email: currentEmail } }).promise();
    if (!cur) return res.status(404).send('User not found.');
    if (cur.id !== id) return res.status(400).send('Token/user mismatch.');
    if (cur.pendingNewEmail !== newEmail) return res.status(400).send('No pending change.');

    // Prepare new item
    const { passwordHash, ...rest } = cur; // keep passwordHash if using email/pass login
    const newItem = {
      ...cur,
      email: newEmail,
      verified: true,
      pendingNewEmail: undefined,
      pendingEmailToken: undefined
    };

    // Transact: Put new (if not exists), Delete old
    const transact = {
      TransactItems: [
        {
          Put: {
            TableName: USER_TABLE,
            Item: newItem,
            ConditionExpression: 'attribute_not_exists(email)'
          }
        },
        {
          Delete: {
            TableName: USER_TABLE,
            Key: { email: currentEmail }
          }
        }
      ]
    };
    await ddb.transactWrite(transact).promise();

    const appToken = issueAuthToken(newItem);
    const userData = sanitizeProfileForClient(newItem);
    const userStr = encodeURIComponent(JSON.stringify(userData));

    // Redirect to frontend to store new token
    return res.redirect(`${FRONTEND_URL}/login?token=${appToken}&user=${userStr}`);
  } catch (err) {
    console.error('[user/confirm-email] Error:', err);
    return res.status(400).send('Invalid or expired token.');
  }
});
// Sends the same verification link used for email/password signup
async function sendUserVerificationEmail(id, email) {
  const token = jwt.sign(
    { id, email, typ: 'user-email-verify' },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  const link = `${API_URL}/api/user/verify?token=${encodeURIComponent(token)}`;
  await transporter.sendMail({
    from: process.env.EMAIL_RECEIVER,
    to: email,
    subject: 'Verify Your Account',
    text: `Click to verify your email: ${link}`
  });
}

// ----------------------------------------------------------------------------
// Google OAuth (user)
// ----------------------------------------------------------------------------
router.use(passport.initialize());
// ----------------------------------------------------------------------------
// Google OAuth (user) — require email verification on first SSO
// ----------------------------------------------------------------------------
router.use(passport.initialize());

passport.use(
  'user-google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID_USER || process.env.GOOGLE_CLIENT_ID1,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_USER || process.env.GOOGLE_CLIENT_SECRET1,
      callbackURL: USER_OAUTH_CALLBACK,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || '').toLowerCase();
        if (!email) return done(new Error('Missing email from Google profile'));

        // Try to get user by email (PK=email)
        const { Item } = await ddb.get({ TableName: USER_TABLE, Key: { email } }).promise();
        let user = Item || null;

        // If not found, create a minimal user record and mark unverified
        if (!user) {
          const id = uuidv4();
          const name =
            profile.displayName ||
            [profile.name?.givenName, profile.name?.familyName].filter(Boolean).join(' ') ||
            'New User';
          const avatarUrl = profile.photos?.[0]?.value || '';

          user = {
            id,
            email,
            phone: '',
            name,
            location: '',
            avatarUrl,
            bio: '',
            passwordHash: '',  // SSO-only initially
            verified: false,   // ← must verify by email
            createdAt: nowTs(),
          };

          await ddb.put({
            TableName: USER_TABLE,
            Item: user,
            ConditionExpression: 'attribute_not_exists(email)',
          }).promise();

          try {
            await sendUserVerificationEmail(id, email);
          } catch (e) {
            console.error('[user-google] send verification failed:', e);
          }

          // Signal to callback: account exists but not verified
          return done(null, { createdButUnverified: true, email });
        }

        // Existing but still unverified → re-send verification & block login
        if (!user.verified) {
          try {
            await sendUserVerificationEmail(user.id, user.email);
          } catch (e) {
            console.error('[user-google] resend verification failed:', e);
          }
          return done(null, { createdButUnverified: true, email: user.email });
        }

        // Verified user → proceed
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Start OAuth
router.get('/auth/google',
  passport.authenticate('user-google', { scope: ['profile', 'email'] })
);

// OAuth Callback
router.get(
  '/auth/google/callback',
  passport.authenticate('user-google', {
    session: false,
    failureRedirect: `${FRONTEND_URL}/login`
  }),
  async (req, res) => {
    try {
      // If the strategy told us verification is required, don't issue a token
      if (req.user?.createdButUnverified) {
        const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
        if (wantsJson) {
          return res.status(202).json({
            status: 'verification_sent',
            email: req.user.email
          });
        }
        // Redirect front-end to show "check your email" UI
        return res.redirect(
          `${FRONTEND_URL}/login?verify=1&email=${encodeURIComponent(req.user.email)}`
        );
      }

      // Normal verified login
      const u = req.user;
      const token = issueAuthToken(u);
      const userData = sanitizeProfileForClient(u);
      const userDataString = encodeURIComponent(JSON.stringify(userData));

      const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
      if (wantsJson) return res.json({ token, user: userData });

      return res.redirect(`${FRONTEND_URL}/login?token=${token}&user=${userDataString}`);
    } catch (err) {
      console.error('[user/auth/google/callback] ERROR:', err);
      return res.status(500).json({ error: 'OAuth error' });
    }
  }
);


router.get('/auth/google',
  passport.authenticate('user-google', { scope: ['profile', 'email'] })
);

router.get(
  '/auth/google/callback',
  passport.authenticate('user-google', { session: false, failureRedirect: `${FRONTEND_URL}/login` }),
  async (req, res) => {
    try {
      const u = req.user;
      const token = issueAuthToken(u);
      const userData = sanitizeProfileForClient(u);
      const userDataString = encodeURIComponent(JSON.stringify(userData));

      const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
      if (wantsJson) return res.json({ token, user: userData });

      return res.redirect(`${FRONTEND_URL}/login?token=${token}&user=${userDataString}`);
    } catch (err) {
      console.error('[user/auth/google/callback] ERROR:', err);
      return res.status(500).json({ error: 'OAuth error' });
    }
  }
);

module.exports = router;
