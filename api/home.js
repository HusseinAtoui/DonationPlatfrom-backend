const express = require('express');
const router = express.Router();
const multer = require('multer');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorize');
require('dotenv').config();

/* ===== AWS SDK v2 setup ===== */
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ddb = new AWS.DynamoDB.DocumentClient();
const s3  = new AWS.S3();

/* ===== Config ===== */
const POSTS_TABLE    = process.env.POSTS_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;
const IMAGES_BUCKET  = process.env.LOGOS_BUCKET;

// Drive PK names from env so we never mismatch table schema.
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
    };
    const out = await s3.upload(params).promise();
    // Note: out.Location is public ONLY if bucket policy (or ACLs) allow GetObject.
    return out.Location;
  });
  return Promise.all(uploads);
}

/* =========================================================================
   HELPERS FOR REQUESTS / ACCEPTANCES
   ========================================================================= */

async function getRequestById(requestId) {
  const { Item } = await ddb.get({
    TableName: REQUESTS_TABLE,
    Key: { [REQUESTS_PK]: requestId },
  }).promise();
  return Item || null;
}

// Build a “next action” so FE can jump to chat when accepter is a USER
function nextMsgActionFor({ request, accepterRole }) {
  const ngoId = request?.ngoId || '';
  const reqId = request?.[REQUESTS_PK];
  if (accepterRole === 'user') {
    return {
      type: 'message',
      url: `/messages/start?withNgo=${encodeURIComponent(ngoId)}&requestId=${encodeURIComponent(reqId)}`
    };
  }
  // NGO↔NGO chat isn’t supported in your messaging service.
  return { type: 'info' };
}

// Find the request that contains a given acceptance id
async function findRequestByAcceptanceId(acceptanceId, { ngoId, accepterId } = {}) {
  const params = { TableName: REQUESTS_TABLE };

  if (ngoId) {
    params.FilterExpression = '#n = :ngo AND attribute_exists(acceptances)';
    params.ExpressionAttributeNames = { '#n': 'ngoId' };
    params.ExpressionAttributeValues = { ':ngo': ngoId };
  } else if (accepterId) {
    params.FilterExpression = 'attribute_exists(acceptances)';
  } else {
    params.FilterExpression = 'attribute_exists(acceptances)';
  }

  let ExclusiveStartKey;
  do {
    const page = await ddb.scan({ ...params, ExclusiveStartKey }).promise();
    for (const r of page.Items || []) {
      const accs = Array.isArray(r.acceptances) ? r.acceptances : [];
      const idx = accs.findIndex(a => String(a.id) === String(acceptanceId));
      if (idx !== -1) return { request: r, index: idx, acceptance: accs[idx] };
    }
    ExclusiveStartKey = page.LastEvaluatedKey;
  } while (ExclusiveStartKey);

  // broader fallback if initially scoped by ngoId
  if (ngoId) return findRequestByAcceptanceId(acceptanceId, {});
  return null;
}

/* =========================================================================
   POSTS
   ========================================================================= */

// GET /posts  (public; optional ?ngoId=...)
router.get('/posts', async (req, res) => {
  try {
    const { ngoId } = req.query;

    if (ngoId) {
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
    const keyValue = req.params.postId;
    const { Item } = await ddb.get({
      TableName: POSTS_TABLE,
      Key: { [POSTS_PK]: keyValue },
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
      const { id: ngoId } = req.user;
      const { text } = req.body;
      if (!text) return res.status(400).json({ error: 'Text is required.' });

      const postId = uuidv4();

      let imageLinks = [];
      if (req.files?.length) {
        imageLinks = await uploadImagesToS3(req.files);
      }

      const item = {
        [POSTS_PK]: postId,
        postId,
        id: postId,
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
      const newImages = req.files?.length ? await uploadImagesToS3(req.files) : Item.images;

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

/* =========================================================================
   REQUESTS
   ========================================================================= */

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
      Key: { [REQUESTS_PK]: keyValue },
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
      const { category, count, gender, status, dateNeeded, location, size, ageRange, coordinates } = req.body;

      if (!category || !count || !status || !dateNeeded || !location) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const requestId = uuidv4();

      const item = {
        [REQUESTS_PK]: requestId,
        requestId,
        ngoId,
        category,
        count: Number(count),
        gender,
        status,
        dateNeeded,
        location,
        size,
        ageRange,
        pledgedCount: 0,
        fulfilledCount: 0,
        acceptances: [],
        createdAt: new Date().toISOString(),
        coordinates: coordinates || null,
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
);

/* =========================================================================
   DONATE (user only — legacy path)
   ========================================================================= */

// POST /requests/:requestId/donate (user only)
router.post(
  '/requests/:requestId/donate',
  authenticateJWT,
  authorizeRoles('user'),
  async (req, res) => {
    try {
      const { quantity } = req.body;
      const { id: userId } = req.user;
      const requestId = req.params.requestId;

      if (!quantity || quantity <= 0) {
        return res.status(400).json({ error: 'Quantity must be a positive number' });
      }

      const { Item } = await ddb.get({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: requestId },
      }).promise();

      if (!Item) return res.status(404).json({ error: 'Request not found' });
      if (Item.status === 'completed') {
        return res.status(400).json({ error: 'Request already completed' });
      }

      const total = Number(Item.count || 0);
      const currentFulfilled = Number(Item.fulfilledCount || 0);
      const remaining = total - currentFulfilled;
      if (quantity > remaining) {
        return res.status(400).json({ error: `Only ${remaining} items left to fulfill` });
      }

      // fulfilledCount must be <= (total - quantity) BEFORE adding quantity
      const maxBefore = total - quantity;

      const newDonor = {
        userId,
        quantity,
        donatedAt: new Date().toISOString(),
      };

      const updateResult = await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: requestId },
        UpdateExpression: `
          SET donors = list_append(if_not_exists(donors, :empty_list), :newDonor),
              fulfilledCount = if_not_exists(fulfilledCount, :zero) + :q,
              #st = if_not_exists(#st, :pending)
        `,
        ConditionExpression: '(attribute_not_exists(fulfilledCount) OR fulfilledCount <= :maxBefore)',
        ExpressionAttributeNames: { '#st': 'status' },
        ExpressionAttributeValues: {
          ':newDonor': [newDonor],
          ':q': quantity,
          ':zero': 0,
          ':empty_list': [],
          ':pending': 'in-progress',
          ':maxBefore': maxBefore
        },
        ReturnValues: 'UPDATED_NEW'
      }).promise();

      const updatedFulfilled = updateResult.Attributes.fulfilledCount;
      if (updatedFulfilled >= total) {
        await ddb.update({
          TableName: REQUESTS_TABLE,
          Key: { [REQUESTS_PK]: requestId },
          UpdateExpression: 'SET #st = :completed',
          ExpressionAttributeNames: { '#st': 'status' },
          ExpressionAttributeValues: { ':completed': 'completed' }
        }).promise();
      }

      res.json({ message: 'Donation recorded', userId, quantity });

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

/* =========================================================================
   ACCEPTANCES (as list on each Request)
   ========================================================================= */

// GET /acceptances?ngoId=...  (PUBLIC)
router.get('/acceptances', async (req, res) => {
  try {
    const { ngoId } = req.query;
    const params = { TableName: REQUESTS_TABLE };

    if (ngoId) {
      params.FilterExpression = '#n = :ngo AND attribute_exists(acceptances)';
      params.ExpressionAttributeNames = { '#n': 'ngoId' };
      params.ExpressionAttributeValues = { ':ngo': ngoId };
    } else {
      params.FilterExpression = 'attribute_exists(acceptances)';
    }

    let ExclusiveStartKey;
    const flat = [];
    do {
      const page = await ddb.scan({ ...params, ExclusiveStartKey }).promise();
      for (const r of page.Items || []) {
        const reqId = r[REQUESTS_PK];
        for (const a of (r.acceptances || [])) {
          flat.push({ ...a, requestId: reqId, status: a.status || 'accepted' });
        }
      }
      ExclusiveStartKey = page.LastEvaluatedKey;
    } while (ExclusiveStartKey);

    flat.sort((a,b) => new Date(b.createdAt||0) - new Date(a.createdAt||0));
    res.json(flat);
  } catch (e) {
    console.error('[GET /acceptances]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /requests/:requestId/acceptances (PUBLIC)
router.get('/requests/:requestId/acceptances', async (req, res) => {
  try {
    const r = await getRequestById(req.params.requestId);
    if (!r) return res.sendStatus(404);
    const items = (r.acceptances || []).slice().sort(
      (a,b) => new Date(b.createdAt||0) - new Date(a.createdAt||0)
    );
    res.json(items);
  } catch (e) {
    console.error('[GET /requests/:requestId/acceptances]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /requests/:requestId/accept (user OR ngo; blocks owner NGO)
router.post(
  '/requests/:requestId/accept',
  authenticateJWT,
  authorizeRoles('user','ngo'),
  async (req, res) => {
    try {
      const requestId = req.params.requestId;
      const q = Number(req.body.quantity || 0);
      if (!q || q <= 0) return res.status(400).json({ error: 'Quantity must be a positive number' });

      const reqItem = await getRequestById(requestId);
      if (!reqItem) return res.status(404).json({ error: 'Request not found' });

      // Prevent NGO accepting its own request
      if (req.user.role === 'ngo' && reqItem.ngoId === req.user.id) {
        return res.status(403).json({ error: 'You cannot accept your own NGO request.' });
      }

      // Pre-check and compute safe bound for condition (no arithmetic funcs in ConditionExpression)
      const total = Number(reqItem.count || 0);
      const currentPledged = Number(reqItem.pledgedCount || 0);
      const remaining = total - currentPledged;
      if (q > remaining) {
        return res.status(400).json({ error: 'Not enough remaining items to accept this quantity.' });
      }
      const maxBefore = total - q; // pledgedCount must be <= this BEFORE we add q

      const now = new Date().toISOString();
      const acceptanceId = uuidv4();
      const acceptance = {
        id: acceptanceId,
        requestId,
        accepterName: req.user.name || req.user.email || 'Supporter',
        accepterType: req.user.role,     // 'user' | 'ngo'
        accepterId: req.user.id,
        quantity: q,
        status: 'accepted',              // accepted | shipped | received | cancelled
        deliveryMethod: req.body.deliveryMethod || 'dropoff',
        handoffWindow: req.body.handoffWindow || null,
        handoffLocation: req.body.handoffLocation || reqItem.location || null,
        note: req.body.note || null,
        createdAt: now,
        updatedAt: now,
      };

      const upd = await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: requestId },
        UpdateExpression: `
          SET pledgedCount = if_not_exists(pledgedCount, :z) + :q,
              acceptances = list_append(if_not_exists(acceptances, :empty), :newA),
              #st = if_not_exists(#st, :inprog),
              updatedAt = :now
        `,
        ConditionExpression: '(attribute_not_exists(pledgedCount) OR pledgedCount <= :maxBefore)',
        ExpressionAttributeNames: { '#st': 'status' },
        ExpressionAttributeValues: {
          ':z': 0,
          ':q': q,
          ':empty': [],
          ':newA': [acceptance],
          ':inprog': 'in-progress',
          ':now': now,
          ':maxBefore': maxBefore
        },
        ReturnValues: 'ALL_NEW'
      }).promise().catch(err => {
        if (err.code === 'ConditionalCheckFailedException') {
          throw new Error('Not enough remaining items to accept this quantity.');
        }
        throw err;
      });

      const nextAction = nextMsgActionFor({
        request: upd.Attributes,
        accepterRole: req.user.role
      });

      res.status(201).json({
        acceptanceId,
        status: 'accepted',
        request: {
          requestId,
          count: upd.Attributes.count,
          pledgedCount: upd.Attributes.pledgedCount,
          fulfilledCount: upd.Attributes.fulfilledCount || 0
        },
        nextAction
      });
    } catch (e) {
      console.error('[POST /requests/:requestId/accept]', e);
      res.status(400).json({ error: e.message || 'Server error' });
    }
  }
);

// PATCH /acceptances/:id/cancel (accepter or owner NGO)
router.patch(
  '/acceptances/:id/cancel',
  authenticateJWT,
  authorizeRoles('user','ngo'),
  async (req, res) => {
    try {
      const accId = req.params.id;

      const scope = (req.user.role === 'ngo')
        ? { ngoId: req.user.id }
        : { accepterId: req.user.id };
      const found = await findRequestByAcceptanceId(accId, scope);
      if (!found) return res.status(404).json({ error: 'Acceptance not found' });

      const { request, index, acceptance } = found;

      // Only accepter or owner NGO may cancel
      const isOwnerNgo = req.user.role === 'ngo' && req.user.id === request.ngoId;
      const isAccepter = req.user.id === acceptance.accepterId;
      if (!isOwnerNgo && !isAccepter) return res.sendStatus(403);

      const now = new Date().toISOString();
      const idx = index;
      const q   = Number(acceptance.quantity || 0);

      await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: request[REQUESTS_PK] },
        UpdateExpression: `
          SET #acc[${idx}].#aStatus = :cancelled,
              #acc[${idx}].updatedAt = :now,
              pledgedCount = if_not_exists(pledgedCount,:z) - :q,
              updatedAt = :now
        `,
        ConditionExpression: `
          #acc[${idx}].#aStatus <> :received AND
          #acc[${idx}].#aStatus <> :cancelled AND
          attribute_exists(pledgedCount) AND pledgedCount >= :q
        `,
        ExpressionAttributeNames: {
          '#acc': 'acceptances',
          '#aStatus': 'status', // nested status alias
        },
        ExpressionAttributeValues: {
          ':cancelled': 'cancelled',
          ':received': 'received',
          ':z': 0,
          ':q': q,
          ':now': now
        }
      }).promise();

      res.json({ status: 'cancelled' });
    } catch (e) {
      console.error('[PATCH /acceptances/:id/cancel]', e);
      res.status(400).json({ error: e.message || 'Server error' });
    }
  }
);
// PATCH /acceptances/:id/receive (owner NGO)
router.patch(
  '/acceptances/:id/receive',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    try {
      const accId = req.params.id;

      const found = await findRequestByAcceptanceId(accId, { ngoId: req.user.id });
      if (!found) return res.status(404).json({ error: 'Acceptance not found' });

      const { request, index, acceptance } = found;
      if (request.ngoId !== req.user.id) return res.sendStatus(403);

      // Idempotency & clear errors up-front
      if (!Number.isInteger(index) || index < 0) {
        return res.status(409).json({ error: 'Acceptance index not found on request.' });
      }
      if (acceptance.status === 'received') {
        // Idempotent OK: already received — return current progress
        return res.json({
          status: 'received',
          requestProgress: {
            count: request.count,
            pledgedCount: request.pledgedCount || 0,
            fulfilledCount: request.fulfilledCount || 0
          }
        });
      }
      if (acceptance.status === 'cancelled') {
        return res.status(409).json({ error: 'Acceptance already cancelled.' });
      }

      const idx = index;
      const q   = Number(acceptance.quantity || 0);
      const now = new Date().toISOString();

      // Do the conditional update (race-safe)
      const upd = await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { [REQUESTS_PK]: request[REQUESTS_PK] },
        UpdateExpression: `
          SET #acc[${idx}].#aStatus = :received,
              #acc[${idx}].receivedAt = :now,
              #acc[${idx}].updatedAt = :now,
              fulfilledCount = if_not_exists(fulfilledCount, :z) + :q,
              #st = if_not_exists(#st, :inprog),
              updatedAt = :now
        `,
        ConditionExpression: `
          attribute_exists(#acc[${idx}]) AND
          #acc[${idx}].#aStatus <> :received AND
          #acc[${idx}].#aStatus <> :cancelled
        `,
        ExpressionAttributeNames: {
          '#acc': 'acceptances',
          '#aStatus': 'status',   // nested status alias
          '#st': 'status'         // top-level status
        },
        ExpressionAttributeValues: {
          ':received': 'received',
          ':cancelled': 'cancelled',
          ':inprog': 'in-progress',
          ':z': 0,
          ':q': q,
          ':now': now
        },
        ReturnValues: 'ALL_NEW'
      }).promise().catch(async (e) => {
        if (e.code === 'ConditionalCheckFailedException') {
          // Re-fetch to explain precisely
          const refetch = await getRequestById(request[REQUESTS_PK]);
          const current = Array.isArray(refetch?.acceptances) ? refetch.acceptances.find(a => a.id === accId) : null;
          if (!current) {
            return Promise.reject(Object.assign(new Error('Acceptance no longer exists on the request.'), { statusCode: 409 }));
          }
          if (current.status === 'received') {
            // Idempotent success if someone else just marked it
            return { Attributes: { ...refetch } };
          }
          if (current.status === 'cancelled') {
            return Promise.reject(Object.assign(new Error('Acceptance already cancelled.'), { statusCode: 409 }));
          }
          return Promise.reject(Object.assign(new Error('Acceptance could not be updated (conflict).'), { statusCode: 409 }));
        }
        throw e;
      });

      // If we got here with Attributes only from idempotent branch, ensure we have attrs
      const attrs = upd.Attributes || upd; // handle idempotent shortcut above
      if ((attrs.fulfilledCount || 0) >= attrs.count) {
        await ddb.update({
          TableName: REQUESTS_TABLE,
          Key: { [REQUESTS_PK]: request[REQUESTS_PK] },
          UpdateExpression: 'SET #st = :completed, updatedAt = :now',
          ExpressionAttributeNames: { '#st': 'status' },
          ExpressionAttributeValues: { ':completed': 'completed', ':now': new Date().toISOString() }
        }).promise();
      }

      return res.json({
        status: 'received',
        requestProgress: {
          count: attrs.count,
          pledgedCount: attrs.pledgedCount || 0,
          fulfilledCount: attrs.fulfilledCount || 0
        }
      });
    } catch (e) {
      console.error('[PATCH /acceptances/:id/receive]', e);
      if (e.code === 'ConditionalCheckFailedException') {
        return res.status(409).json({ error: 'Acceptance already received/cancelled or not found at index.' });
      }
      if (e.statusCode) {
        return res.status(e.statusCode).json({ error: e.message || 'Server error' });
      }
      return res.status(400).json({ error: e.message || 'Server error' });
    }
  }
);

// GET /inventory?ngoId=...  (public)
router.get('/inventory', async (req, res) => {
  try {
    const { ngoId } = req.query;
    if (!ngoId) return res.status(400).json({ error: 'ngoId is required' });

    const data = await ddb.scan({
      TableName: REQUESTS_TABLE,
      FilterExpression: '#n = :ngo',
      ExpressionAttributeNames: { '#n': 'ngoId' },
      ExpressionAttributeValues: { ':ngo': ngoId },
    }).promise();

    const items = data.Items || [];

    // Summarize like an inventory by (category, size, gender)
    const byKey = {};
    for (const r of items) {
      const key = [r.category, r.size || '', r.gender || ''].join('|');
      if (!byKey[key]) {
        byKey[key] = {
          category: r.category,
          size: r.size || null,
          gender: r.gender || null,
          requested: 0,
          pledged: 0,
          received: 0,
          open: 0,
        };
      }
      byKey[key].requested += Number(r.count || 0);
      byKey[key].pledged   += Number(r.pledgedCount || 0);
      byKey[key].received  += Number(r.fulfilledCount || 0);
    }

    // Compute “open” remaining
    Object.values(byKey).forEach(row => {
      row.open = Math.max(0, row.requested - row.received);
    });

    res.json(Object.values(byKey));
  } catch (e) {
    console.error('[GET /inventory]', e);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
