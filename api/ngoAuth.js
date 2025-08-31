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

/* ---------------- ENV / CONFIG ---------------- */
const NGO_TABLE      = process.env.NGO_TABLE;
const JWT_SECRET     = process.env.JWT_SECRET;
const LOGOS_BUCKET   = process.env.LOGOS_BUCKET;
const API_URL_RAW    = process.env.API_URL || 'http://localhost:4000';
const FRONTEND_URL   = process.env.FRONTEND_URL || 'http://localhost:3000';
const API_URL        = String(API_URL_RAW).replace(/\/+$/, '');

// (optional) used by cascade delete helpers; keep defaults safe
const POSTS_TABLE    = process.env.POSTS_TABLE || '';
const REQUESTS_TABLE = process.env.REQUESTS_TABLE || '';
const POSTS_PK       = process.env.POSTS_PK || 'id';
const REQUESTS_PK    = process.env.REQUESTS_PK || 'id';

const NGO_OAUTH_LOGIN_CALLBACK  = `${API_URL}/api/ngo/auth/google/callback/login`;
const NGO_OAUTH_SIGNUP_CALLBACK = `${API_URL}/api/ngo/auth/google/callback/signup`;

console.log('[NGO][Google] Login CB :', NGO_OAUTH_LOGIN_CALLBACK);
console.log('[NGO][Google] Signup CB:', NGO_OAUTH_SIGNUP_CALLBACK);

/* ---------------- AWS ---------------- */
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const s3  = new AWS.S3();

/* ---------------- Upload ---------------- */
const upload = multer({ storage: multer.memoryStorage() });

/* ---------------- Mailer ---------------- */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_RECEIVER,
    pass: process.env.EMAIL_PASS
  }
});

/* ---------------- Avatar helpers ---------------- */
function initialsFromName(name = '') {
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  const first = parts[0]?.[0] || '';
  const last  = parts.length > 1 ? parts[parts.length - 1][0] : (parts[0]?.[1] || '');
  return (first + last).toUpperCase();
}
function colorFromId(id = '') {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  return `hsl(${hue} 70% 70%)`;
}
function buildInitialsSVG({ name, id }) {
  const initials = initialsFromName(name || 'NGO');
  const bg = colorFromId(id || initials);
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <circle cx="128" cy="128" r="128" fill="${bg}"/>
  <text x="50%" y="50%" dominant-baseline="central" text-anchor="middle"
        font-family="Arial, sans-serif" font-size="100" font-weight="bold"
        fill="#1f2937">${initials}</text>
</svg>`;
}
function svgDataUrlFor({ id, name }) {
  const svg = buildInitialsSVG({ id, name });
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}
async function uploadDefaultAvatar({ id, name }) {
  const key = `logos/default-${id}.svg`;
  const svg = buildInitialsSVG({ name, id });
  const params = {
    Bucket: LOGOS_BUCKET,
    Key: key,
    Body: svg,
    ContentType: 'image/svg+xml'
  };
  const out = await s3.upload(params).promise();
  return out.Location;
}
async function ensureLogoUrl(ngo) {
  if (ngo.logoUrl) return ngo.logoUrl;
  if (LOGOS_BUCKET) {
    try {
      const url = await uploadDefaultAvatar({ id: ngo.id, name: ngo.name });
      await ddb.update({
        TableName: NGO_TABLE,
        Key: { email: (ngo.email || '').toLowerCase() },
        UpdateExpression: 'SET logoUrl = :u',
        ExpressionAttributeValues: { ':u': url }
      }).promise();
      return url;
    } catch (e) {
      console.error('[ensureLogoUrl] S3 upload failed, using data URL:', e);
    }
  }
  return svgDataUrlFor({ id: ngo.id, name: ngo.name });
}
function isProfileComplete(ngo) {
  const locOk = typeof ngo.location === 'string' && ngo.location.trim().length > 0;
  const latOk = ngo?.coordinates && typeof ngo.coordinates.lat === 'number';
  const lngOk = ngo?.coordinates && typeof ngo.coordinates.lng === 'number';
  return locOk && latOk && lngOk;
}

/* ---------------- Email helpers ---------------- */
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

/* ---------------- Google OAuth (two-intent) ---------------- */
router.use(passport.initialize());

/** Strategy A: LOGIN intent — never creates. If missing → redirect to signup. */
passport.use('ngo-google-login',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID1,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET1,
      callbackURL: NGO_OAUTH_LOGIN_CALLBACK
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || '').toLowerCase();
        if (!email) return done(new Error('Missing email from Google profile'));

        const { Item: ngo } = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();

        if (!ngo) {
          return done(null, { redirectToSignup: true, email });
        }
        if (!ngo.verified) {
          return done(null, { needsVerify: true, email: ngo.email });
        }
        return done(null, ngo);
      } catch (err) {
        return done(err);
      }
    }
  )
);

/** Strategy B: SIGNUP intent — creates if missing, emails verification. */
passport.use('ngo-google-signup',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID1,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET1,
      callbackURL: NGO_OAUTH_SIGNUP_CALLBACK
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || '').toLowerCase();
        if (!email) return done(new Error('Missing email from Google profile'));

        const { Item: existing } = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();

        if (!existing) {
          const id = uuidv4();
          const name =
            profile.displayName ||
            [profile.name?.givenName, profile.name?.familyName].filter(Boolean).join(' ') ||
            'New NGO';

          let logoUrl = profile.photos?.[0]?.value || '';
          if (!logoUrl) {
            try { logoUrl = await uploadDefaultAvatar({ id, name }); }
            catch (e) { console.error('Default avatar generation failed (OAuth):', e); logoUrl = ''; }
          }

          const item = {
            id, email, phone: '', name, location: '',
            coordinates: { lat: null, lng: null },
            passwordHash: '',
            inventorySize: 0, requiredClothing: '',
            logoUrl, bio: '', summary: '',
            verified: false,
              profileComplete: false,                 // ← NEW
 createdAt: Date.now()
          };

          await ddb.put({
            TableName: NGO_TABLE,
            Item: item,
            ConditionExpression: 'attribute_not_exists(email)'
          }).promise();

          try { await sendVerificationEmail(id, email); } catch (e) { console.error('[NGO signup google] verify send failed:', e); }

          return done(null, { createdButUnverified: true, email });
        }

        if (!existing.verified) {
          try { await sendVerificationEmail(existing.id, existing.email); } catch (_) {}
          return done(null, { createdButUnverified: true, email: existing.email });
        }

        return done(null, existing); // already verified → login behavior
      } catch (err) {
        return done(err);
      }
    }
  )
);

/* ---------------- OAuth entrypoints ---------------- */
router.get('/auth/google/login',
  passport.authenticate('ngo-google-login', { scope: ['profile', 'email'] })
);
router.get('/auth/google/signup',
  passport.authenticate('ngo-google-signup', { scope: ['profile', 'email'] })
);

/* ---------------- OAuth callbacks ---------------- */
router.get('/auth/google/callback/login',
  passport.authenticate('ngo-google-login', { session: false, failureRedirect: `${FRONTEND_URL}/login` }),
  async (req, res) => {
    try {
      if (req.user?.redirectToSignup) {
        const email = encodeURIComponent(req.user.email || '');
        return res.redirect(`${FRONTEND_URL}/signup/ngo?noAccount=1&email=${email}`);
      }
      if (req.user?.needsVerify) {
        const email = encodeURIComponent(req.user.email || '');
        return res.redirect(`${FRONTEND_URL}/login?verify=needed&email=${email}`);
      }

      const ngo = req.user;
      const jwtToken = jwt.sign(
        { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      const ensuredLogo = await ensureLogoUrl(ngo);
      const userData = {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone || '',
        location: ngo.location || '',
        logoUrl: ensuredLogo,
        verified: !!ngo.verified
      };
      const userDataString = encodeURIComponent(JSON.stringify(userData));
      // 🚨 NEW: redirect to onboarding if profile is incomplete
      if (!isProfileComplete(ngo)) {
        return res.redirect(
          `${FRONTEND_URL}/onboarding/ngo/location?token=${jwtToken}&user=${userDataString}`
        );
      }

      const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
      if (wantsJson) return res.json({ token: jwtToken, user: userData });

      return res.redirect(`${FRONTEND_URL}/login?token=${jwtToken}&user=${userDataString}`);
    } catch (err) {
      console.error('[NGO][GOOGLE CALLBACK LOGIN] ERROR:', err);
      return res.status(500).json({ error: 'OAuth error' });
    }
  }
);

router.get('/auth/google/callback/signup',
  passport.authenticate('ngo-google-signup', { session: false, failureRedirect: `${FRONTEND_URL}/signup/ngo` }),
  async (req, res) => {
    try {
      if (req.user?.createdButUnverified) {
        const email = encodeURIComponent(req.user.email || '');
        return res.redirect(`${FRONTEND_URL}/signup/ngo?created=1&checkEmail=1&email=${email}`);
      }

      // If verified already, log in.
      const ngo = req.user;
      const jwtToken = jwt.sign(
        { id: ngo.id, role: 'ngo', email: ngo.email, name: ngo.name },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      const ensuredLogo = await ensureLogoUrl(ngo);
      const userData = {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone || '',
        location: ngo.location || '',
        logoUrl: ensuredLogo,
        verified: !!ngo.verified
      };
      const userDataString = encodeURIComponent(JSON.stringify(userData));

      const wantsJson = req.query.json === '1' || (req.get('accept') || '').includes('application/json');
      if (wantsJson) return res.json({ token: jwtToken, user: userData });

      return res.redirect(`${FRONTEND_URL}/login?token=${jwtToken}&user=${userDataString}`);
    } catch (err) {
      console.error('[NGO][GOOGLE CALLBACK SIGNUP] ERROR:', err);
      return res.status(500).json({ error: 'OAuth error' });
    }
  }
);

/* ---------------- cascade delete helpers ---------------- */
function extractS3KeyFromUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    return decodeURIComponent(u.pathname.replace(/^\/+/, ''));
  } catch {
    return null;
  }
}
async function deleteS3Keys(keys) {
  if (!keys?.length || !LOGOS_BUCKET) return;
  for (let i = 0; i < keys.length; i += 1000) {
    const chunk = keys.slice(i, i + 1000);
    try {
      await s3.deleteObjects({
        Bucket: LOGOS_BUCKET,
        Delete: { Objects: chunk.map(Key => ({ Key })) }
      }).promise();
    } catch (e) {
      console.error('[NGO CASCADE] S3 deleteObjects error:', e);
    }
  }
}
async function batchDelete(table, pkName, ids) {
  if (!table || !ids?.length) return;
  for (let i = 0; i < ids.length; i += 25) {
    const chunk = ids.slice(i, i + 25);
    const RequestItems = {
      [table]: chunk.map(val => ({ DeleteRequest: { Key: { [pkName]: val } } }))
    };
    try {
      await ddb.batchWrite({ RequestItems }).promise();
    } catch (e) {
      console.error(`[NGO CASCADE] batchWrite delete failed for ${table}:`, e);
    }
  }
}
async function scanAllByNgoId(table, ngoId) {
  const items = [];
  if (!table) return items;
  let ExclusiveStartKey;
  do {
    const page = await ddb.scan({
      TableName: table,
      FilterExpression: '#n = :ngo',
      ExpressionAttributeNames: { '#n': 'ngoId' },
      ExpressionAttributeValues: { ':ngo': ngoId },
      ExclusiveStartKey
    }).promise();
    items.push(...(page.Items || []));
    ExclusiveStartKey = page.LastEvaluatedKey;
  } while (ExclusiveStartKey);
  return items;
}
async function cascadeDeleteNgoResources({ ngoId, ngoEmail }) {
  try {
    const [posts, requests, ngoRow] = await Promise.all([
      scanAllByNgoId(POSTS_TABLE, ngoId),
      scanAllByNgoId(REQUESTS_TABLE, ngoId),
      ddb.get({ TableName: NGO_TABLE, Key: { email: (ngoEmail || '').toLowerCase() } }).promise()
        .then(r => r.Item).catch(() => null)
    ]);

    await batchDelete(POSTS_TABLE,    POSTS_PK,    posts.map(p => p[POSTS_PK]).filter(Boolean));
    await batchDelete(REQUESTS_TABLE, REQUESTS_PK, requests.map(r => r[REQUESTS_PK]).filter(Boolean));

    const imageUrls = posts.flatMap(p => Array.isArray(p.images) ? p.images : []);
    const imageKeys = imageUrls.map(extractS3KeyFromUrl).filter(Boolean);

    const logoKey = extractS3KeyFromUrl(ngoRow?.logoUrl);
    const allKeys = [...imageKeys, ...(logoKey ? [logoKey] : [])];

    await deleteS3Keys(allKeys);
  } catch (e) {
    console.error('[NGO CASCADE] Failed to fully cascade delete:', e);
  }
}

/* ---------------- REST: NGO endpoints (kept) ---------------- */

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
        ContentType: req.file.mimetype
      };
      const uploadResult = await s3.upload(params).promise();
      logoUrl = uploadResult.Location;
    }

    const existing = await ddb.get({ TableName: NGO_TABLE, Key: { email } }).promise();
    if (existing.Item) return res.status(409).json({ error: 'NGO already exists.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();

    if (!logoUrl) {
      try {
        logoUrl = await uploadDefaultAvatar({ id, name });
      } catch (err) {
        console.error('Default avatar generation failed:', err);
        logoUrl = '';
      }
    }

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

// Verify route (GET /api/ngo/verify?token=...)
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

    const { Item: newExists } = await ddb.get({ TableName: NGO_TABLE, Key: { email: newKey } }).promise();
    if (newExists) {
      return res.status(400).json({ error: 'Email already in use.' });
    }

    const { Item: oldItem } = await ddb.get({ TableName: NGO_TABLE, Key: { email: oldKey } }).promise();
    if (!oldItem || oldItem.id !== id) {
      return res.status(400).json({ error: 'Account not found or mismatch.' });
    }

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

    await ddb.delete({
      TableName: NGO_TABLE,
      Key: { email: oldKey }
    }).promise();

    return res.redirect(`${FRONTEND_URL}/login?verified=1&emailChanged=1`);
  } catch (err) {
    console.error('Error verifying email change:', err);
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// Login NGO (email/password)
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
    const ensuredLogo = await ensureLogoUrl(ngo);

    return res.json({
      token: jwtToken,
      user: {
        id: ngo.id,
        name: ngo.name,
        email: ngo.email,
        phone: ngo.phone,
        location: ngo.location,
        logoUrl: ensuredLogo,
        verified: !!ngo.verified
      } , needsOnboarding: !isProfileComplete(ngo)  // ← NEW

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

    if (!Item) return res.status(401).json({ error: 'Invalid session.' });
    const ensuredLogo = await ensureLogoUrl(Item);
    res.json({ profile: { ...Item, logoUrl: ensuredLogo } });
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Me (patch)
router.patch('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });

  try {
    const {
      name,
      email,
      phone,
      location,
      summary,
      logoUrl,
      coordinates,
    } = req.body;

    const currentEmail = (req.user.email || '').toLowerCase();

    if (email && email.toLowerCase() !== currentEmail) {
      const desired = email.toLowerCase();
      const { Item: exists } = await ddb.get({ TableName: NGO_TABLE, Key: { email: desired } }).promise();
      if (exists) return res.status(409).json({ error: 'Email already in use.' });

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
        await ddb.update({
          TableName: NGO_TABLE,
          Key: { email: currentEmail },
          UpdateExpression: 'REMOVE pendingEmail, pendingEmailRequestedAt'
        }).promise();
        return res.status(500).json({ error: 'Failed to send verification email.' });
      }

      return res.status(202).json({ status: 'verify_new_email_sent' });
    }

    const updateFields = {};
    if (name !== undefined) updateFields.name = name;
    if (phone !== undefined) updateFields.phone = phone;
    if (logoUrl !== undefined) updateFields.logoUrl = logoUrl;
    if (summary !== undefined) {
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
    // NEW: mark profileComplete if they now have location + coordinates
    const complete = isProfileComplete(Attributes);
    if ((Attributes.profileComplete || false) !== complete) {
      await ddb.update({
        TableName: NGO_TABLE,
        Key: { email: currentEmail },
        UpdateExpression: 'SET profileComplete = :pc',
        ExpressionAttributeValues: { ':pc': complete }
      }).promise();
      Attributes.profileComplete = complete;
    }

    return res.json({ profile: Attributes });
  } catch (err) {
    console.error('Error updating NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Update (legacy route)
router.put('/update/:id', authenticateJWT, upload.single('logo'), async (req, res) => {
  const ngoId = req.params.id;
  if (req.user.role !== 'ngo' || req.user.id !== ngoId) {
    return res.status(403).json({ error: 'Forbidden. You can only update your own NGO.' });
  }

  try {
    const updateFields = {};
    const allowedFields = ['phone', 'inventorySize', 'requiredClothing', 'bio', 'summary'];

    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updateFields[field] = field === 'inventorySize' ? Number(req.body[field]) : req.body[field];
      }
    }

    if (req.file) {
      const key = `logos/${uuidv4()}-${req.file.originalname}`;
      const params = {
        Bucket: LOGOS_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype
      };
      const uploadResult = await s3.upload(params).promise();
      updateFields.logoUrl = uploadResult.Location;
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

    await ddb.update({
      TableName: NGO_TABLE,
      Key: { email: (req.user.email || '').toLowerCase() },
      UpdateExpression: 'SET ' + setParts.join(', '),
      ExpressionAttributeNames: exprNames,
      ExpressionAttributeValues: exprVals
    }).promise();

    res.json({ status: 'updated' });
  } catch (err) {
    console.error('Error updating NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete (by id)
router.delete('/delete/:id', authenticateJWT, async (req, res) => {
  const ngoId = req.params.id;
  if (req.user.role !== 'ngo' || req.user.id !== ngoId) {
    return res.status(403).json({ error: 'Forbidden. You can only delete your own NGO.' });
  }

  try {
    await cascadeDeleteNgoResources({ ngoId: req.user.id, ngoEmail: req.user.email });
    await ddb.delete({
      TableName: NGO_TABLE,
      Key: { email: (req.user.email || '').toLowerCase() }
    }).promise();

    res.json({ status: 'deleted' });
  } catch (err) {
    console.error('Error deleting NGO:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete — self
router.delete('/me', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.status(403).json({ error: 'Forbidden.' });

  try {
    await cascadeDeleteNgoResources({ ngoId: req.user.id, ngoEmail: req.user.email });
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

// Public profile minimal
router.get('/public/:id', async (req, res) => {
  const id = req.params.id;
  if (!id) return res.status(400).json({ error: 'id required' });
  try {
    let ngo = null;
    try {
      const q = await ddb.query({
        TableName: NGO_TABLE,
        IndexName: 'id-index',
        KeyConditionExpression: 'id = :id',
        ExpressionAttributeValues: { ':id': id },
        ProjectionExpression: 'id, #n, logoUrl, avatarUrl',
        ExpressionAttributeNames: { '#n': 'name' },
      }).promise();
      ngo = (q.Items || [])[0] || null;
    } catch (_) {}

    if (!ngo) {
      const s = await ddb.scan({
        TableName: NGO_TABLE,
        FilterExpression: '#i = :id',
        ExpressionAttributeNames: { '#i': 'id', '#n': 'name' },
        ExpressionAttributeValues: { ':id': id },
        ProjectionExpression: 'id, #n, logoUrl, avatarUrl',
      }).promise();
      ngo = (s.Items || [])[0] || null;
    }

    if (!ngo) return res.status(404).json({ error: 'NGO not found' });
    return res.json({
      id: ngo.id,
      name: ngo.name || '',
      logoUrl: ngo.logoUrl || '',
      avatarUrl: ngo.avatarUrl || '',
    });
  } catch (err) {
    console.error('[ngo/public/:id]', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
