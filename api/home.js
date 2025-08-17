const express = require('express');
const router = express.Router();
const multer = require('multer');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorize');

require('dotenv').config();

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ddb = new AWS.DynamoDB.DocumentClient();
const s3  = new AWS.S3();

const POSTS_TABLE    = process.env.POSTS_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;
const IMAGES_BUCKET  = process.env.LOGOS_BUCKET;

// IMPORTANT: drive PK names from env so we never mismatch table schema.
const POSTS_PK    = process.env.POSTS_PK    || 'id';
const REQUESTS_PK = process.env.REQUESTS_PK || 'requestId';

const upload = multer({ storage: multer.memoryStorage() });

/* ---------- S3 upload helper (no ACL; Block Public Access safe) ---------- */
async function uploadImagesToS3(files) {
  const uploads = files.map(async (file) => {
    const key = `posts/${uuidv4()}-${file.originalname}`;
    const params = {
      Bucket: IMAGES_BUCKET,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
      // No ACL here; serve via CloudFront/presigned if you lock bucket public.
    };
    const out = await s3.upload(params).promise();
    return out.Location; // public URL if bucket allows; otherwise use signed urls
  });
  return Promise.all(uploads);
}

/* =======================
   POSTS
   ======================= */

// GET /posts  (public; optional ?ngoId=...)
router.get('/posts', async (req, res) => {
  try {
    const { ngoId } = req.query;

    if (ngoId) {
      // If volume grows, add a GSI: (ngoId HASH, createdAt RANGE) and use Query.
      const data = await ddb.scan({
        TableName: POSTS_TABLE,
        FilterExpression: '#n = :ngo',
        ExpressionAttributeNames: { '#n': 'ngoId' },
        ExpressionAttributeValues: { ':ngo': ngoId },
      }).promise();

      const items = (data.Items || []).sort(
        (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
      );
      return res.json(items);
    }

    const data = await ddb.scan({ TableName: POSTS_TABLE }).promise();
    const items = (data.Items || []).sort(
      (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
    );
    res.json(items);
  } catch (e) {
    console.error('[home][GET /posts]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /posts/:postId  (public)
router.get('/posts/:postId', async (req, res) => {
  try {
    const keyValue = req.params.postId; // FE sends 'postId' value
    const { Item } = await ddb.get({
      TableName: POSTS_TABLE,
      Key: { [POSTS_PK]: keyValue },     // <— use real PK name (e.g., "id")
    }).promise();

    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error('[home][GET /posts/:postId]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /posts  (NGO only)
router.post(
  '/posts',
  authenticateJWT,
  authorizeRoles('ngo'),
  upload.array('images'),
  async (req, res) => {
    try {
      const { id: ngoId } = req.user; // NGO id from JWT
      const { text } = req.body;
      if (!text) return res.status(400).json({ error: 'Text is required.' });

      const postId = uuidv4();

      let imageLinks = [];
      if (req.files?.length) {
        imageLinks = await uploadImagesToS3(req.files);
      }

      // Write both the real PK and convenience fields for FE compatibility
      const item = {
        [POSTS_PK]: postId,       // satisfies table schema (e.g., "id": <uuid>)
        postId,                   // convenience
        id: postId,               // compatibility with any old FE expecting "id"
        ngoId,
        text,
        images: imageLinks,
        createdAt: new Date().toISOString(),
      };

      await ddb.put({ TableName: POSTS_TABLE, Item: item }).promise();
      res.status(201).json({ postId, status: 'ok', images: imageLinks });
    } catch (e) {
      console.error('[home][POST /posts]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// PATCH /posts/:postId  (NGO owns the post)
router.patch(
  '/posts/:postId',
  authenticateJWT,
  authorizeRoles('ngo'),
  upload.array('images'),
  async (req, res) => {
    try {
      const keyValue = req.params.postId;

      const { Item } = await ddb.get({
        TableName: POSTS_TABLE,
        Key: { [POSTS_PK]: keyValue },
      }).promise();

      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      const newText   = req.body.text ?? Item.text;
      const newImages = req.files?.length
        ? await uploadImagesToS3(req.files)
        : Item.images;

      await ddb.update({
        TableName: POSTS_TABLE,
        Key: { [POSTS_PK]: keyValue },
        UpdateExpression: 'SET #t = :t, #i = :i',
        ExpressionAttributeNames: { '#t': 'text', '#i': 'images' },
        ExpressionAttributeValues: { ':t': newText, ':i': newImages },
      }).promise();

      res.json({ status: 'ok', images: newImages });
    } catch (e) {
      console.error('[home][PATCH /posts/:postId]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// DELETE /posts/:postId  (NGO owns the post)
router.delete(
  '/posts/:postId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    try {
      const keyValue = req.params.postId;

      const { Item } = await ddb.get({
        TableName: POSTS_TABLE,
        Key: { [POSTS_PK]: keyValue },
      }).promise();

      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      await ddb.delete({
        TableName: POSTS_TABLE,
        Key: { [POSTS_PK]: keyValue },
      }).promise();

      res.json({ status: 'deleted' });
    } catch (e) {
      console.error('[home][DELETE /posts/:postId]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

/* =======================
   REQUESTS
   ======================= */

// GET /requests (public; optional ?ngoId=...)
router.get('/requests', async (req, res) => {
  try {
    const { ngoId } = req.query;

    if (ngoId) {
      const data = await ddb.scan({
        TableName: REQUESTS_TABLE,
        FilterExpression: '#n = :ngo',
        ExpressionAttributeNames: { '#n': 'ngoId' },
        ExpressionAttributeValues: { ':ngo': ngoId },
      }).promise();

      const items = (data.Items || []).sort(
        (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
      );
      return res.json(items);
    }

    const data = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
    const items = (data.Items || []).sort(
      (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
    );
    res.json(items);
  } catch (e) {
    console.error('[home][GET /requests]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /requests/:requestId (public)
router.get('/requests/:requestId', async (req, res) => {
  try {
    const keyValue = req.params.requestId;
    const { Item } = await ddb.get({
      TableName: REQUESTS_TABLE,
      Key: { [REQUESTS_PK]: keyValue },   // <— use real PK name
    }).promise();

    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error('[home][GET /requests/:requestId]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /requests (NGO only)
router.post(
  '/requests',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    try {
      const { id: ngoId } = req.user;
      const { category, count, gender, status, dateNeeded, location, size, ageRange } = req.body;

      if (!category || !count || !status || !dateNeeded || !location) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const requestId = uuidv4();

      const item = {
        [REQUESTS_PK]: requestId,  // e.g., "requestId": <uuid>
        requestId,                 // convenience for FE
        ngoId,
        category,
        count: Number(count),
        gender,
        status,
        dateNeeded,
        location,
        size,
        ageRange,
        createdAt: new Date().toISOString(),
      };

      await ddb.put({ TableName: REQUESTS_TABLE, Item: item }).promise();
      res.status(201).json({ requestId, status: 'ok' });
    } catch (e) {
      console.error('[home][POST /requests]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// PATCH /requests/:requestId (NGO owns the request)
router.patch(
  '/requests/:requestId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    try {
      const keyValue = req.params.requestId;
      const keys = Object.keys(req.body);
      if (!keys.length) return res.status(400).json({ error: 'No update fields provided' });

      const { Item } = await ddb.get({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: keyValue },
      }).promise();

      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      const updateExp = keys.map((k, i) => `#k${i} = :v${i}`).join(', ');
      const attrNames  = Object.fromEntries(keys.map((k, i) => [`#k${i}`, k]));
      const attrValues = Object.fromEntries(keys.map((k, i) => [`:v${i}`, req.body[k]]));

      await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: keyValue },
        UpdateExpression: `SET ${updateExp}`,
        ExpressionAttributeNames: attrNames,
        ExpressionAttributeValues: attrValues,
      }).promise();

      res.json({ status: 'ok' });
    } catch (e) {
      console.error('[home][PATCH /requests/:requestId]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// DELETE /requests/:requestId (NGO owns the request)
router.delete(
  '/requests/:requestId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    try {
      const keyValue = req.params.requestId;

      const { Item } = await ddb.get({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: keyValue },
      }).promise();

      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      await ddb.delete({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: keyValue },
      }).promise();

      res.json({ status: 'deleted' });
    } catch (e) {
      console.error('[home][DELETE /requests/:requestId]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);// POST /requests/:requestId/donate
router.post(
  '/requests/:requestId/donate',
  authenticateJWT,
  authorizeRoles('volunteer'),
  async (req, res) => {
    try {
      const { quantity } = req.body;
      const { id: donorId } = req.user;
      const requestId = req.params.requestId;

      // Validate quantity
      if (!quantity || quantity <= 0) {
        return res.status(400).json({ error: 'Quantity must be a positive number' });
      }

      // Get current request
      const { Item } = await ddb.get({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: requestId },
      }).promise();

      if (!Item) return res.status(404).json({ error: 'Request not found' });
      if (Item.status === 'completed') {
        return res.status(400).json({ error: 'Request already completed' });
      }

      const remaining = Item.count - (Item.fulfilledCount || 0);
      if (quantity > remaining) {
        return res.status(400).json({ error: `Only ${remaining} items left to fulfill` });
      }

      const newDonor = {
        donorId,
        quantity,
        donatedAt: new Date().toISOString(),
      };

      // Atomic update
      const updateResult = await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: requestId },
        UpdateExpression: `
          SET donors = list_append(if_not_exists(donors, :empty_list), :newDonor),
              fulfilledCount = if_not_exists(fulfilledCount, :zero) + :q,
              #st = if_not_exists(#st, :pending)
        `,
        ConditionExpression: 'if_not_exists(fulfilledCount, :zero) + :q <= #total',
        ExpressionAttributeNames: {
          '#st': 'status',
          '#total': 'count'
        },
        ExpressionAttributeValues: {
          ':newDonor': [newDonor],
          ':q': quantity,
          ':zero': 0,
          ':empty_list': [],
          ':pending': 'in-progress'
        },
        ReturnValues: 'UPDATED_NEW'
      }).promise();

      // Optionally, mark as completed if fulfilledCount equals total count
      const updatedFulfilled = updateResult.Attributes.fulfilledCount;
      if (updatedFulfilled === Item.count) {
        await ddb.update({
          TableName: REQUESTS_TABLE,
          Key: { [REQUESTS_PK]: requestId },
          UpdateExpression: 'SET #st = :completed',
          ExpressionAttributeNames: { '#st': 'status' },
          ExpressionAttributeValues: { ':completed': 'completed' }
        }).promise();
      }

      res.json({ message: 'Donation recorded', donorId, quantity });

    } catch (e) {
      if (e.code === 'ConditionalCheckFailedException') {
        return res.status(400).json({ error: 'Donation exceeds remaining items' });
      }
      console.error('[POST /requests/:requestId/donate]', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// GET /requests/my-requests  (NGO only)
router.get('/requests/my-requests', authenticateJWT, authorizeRoles('ngo'), async (req, res) => {
  try {
    const ngoId = req.user.id;

    const data = await ddb.scan({
      TableName: REQUESTS_TABLE,
      FilterExpression: '#n = :ngo',
      ExpressionAttributeNames: { '#n': 'ngoId' },
      ExpressionAttributeValues: { ':ngo': ngoId },
    }).promise();

    const items = (data.Items || []).sort(
      (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
    );

    res.json(items);
  } catch (e) {
    console.error('[GET /requests/my-requests]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
