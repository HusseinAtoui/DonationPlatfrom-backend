// api/messaging.js — AWS SDK v2 (fully fixed)
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
require('dotenv').config();

// ---- AWS SDK v2 setup ----
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ddb = new AWS.DynamoDB.DocumentClient();
const s3  = new AWS.S3();

const CONVERSATIONS_TABLE = process.env.CONVERSATIONS_TABLE; // e.g. conversations
const MESSAGES_TABLE      = process.env.MESSAGES_TABLE;      // e.g. messages
const MESSAGES_BUCKET     = process.env.MESSAGES_BUCKET;     // e.g. your-s3-bucket

// Optional (for stamping names/avatars at creation)
const USER_TABLE          = process.env.USER_TABLE;          // e.g. users
const NGO_TABLE           = process.env.NGO_TABLE;           // e.g. ngos

// ---- hard requirements ----
if (!CONVERSATIONS_TABLE || !MESSAGES_TABLE) {
  throw new Error('[messages] Missing required ENV: CONVERSATIONS_TABLE or MESSAGES_TABLE');
}

// ---------- helpers ----------
function actorFromReq(req) {
  const { id, role } = req.user || {};
  if (!id || !role) throw new Error('Invalid auth payload.');
  return { id, role };
}

async function getConversationById(conversationId) {
  const out = await ddb.get({
    TableName: CONVERSATIONS_TABLE,
    Key: { id: conversationId },
  }).promise();
  return out.Item || null;
}

function canAccess(conv, actor) {
  if (!conv) return false;
  if (actor.role === 'user') return conv.userId === actor.id;
  if (actor.role === 'ngo')  return conv.ngoId === actor.id;
  return false;
}

function safeBase64JsonDecode(b64) {
  try { return JSON.parse(Buffer.from(b64, 'base64').toString('utf8')); }
  catch { return null; }
}
// FIX: alias reserved "name" in both query & scan
async function getUserBasicById(id) {
  if (!USER_TABLE || !id) return null;
  try {
    const q = await ddb.query({
      TableName: USER_TABLE,
      IndexName: 'id-index',
      KeyConditionExpression: '#id = :id',
      ProjectionExpression: '#id, #n, avatarUrl',
      ExpressionAttributeNames: { '#id': 'id', '#n': 'name' },
      ExpressionAttributeValues: { ':id': id },
    }).promise();
    if (q.Items && q.Items[0]) return q.Items[0];
  } catch (_) {}
  try {
    const s = await ddb.scan({
      TableName: USER_TABLE,
      FilterExpression: '#id = :id',
      ProjectionExpression: '#id, #n, avatarUrl',
      ExpressionAttributeNames: { '#id': 'id', '#n': 'name' },
      ExpressionAttributeValues: { ':id': id },
    }).promise();
    return (s.Items && s.Items[0]) || null;
  } catch (_) { return null; }
}

async function getNgoBasicById(id) {
  if (!NGO_TABLE || !id) return null;
  try {
    const q = await ddb.query({
      TableName: NGO_TABLE,
      IndexName: 'id-index',
      KeyConditionExpression: '#id = :id',
      ProjectionExpression: '#id, #n, logoUrl, avatarUrl',
      ExpressionAttributeNames: { '#id': 'id', '#n': 'name' },
      ExpressionAttributeValues: { ':id': id },
    }).promise();
    if (q.Items && q.Items[0]) return q.Items[0];
  } catch (_) {}
  try {
    const s = await ddb.scan({
      TableName: NGO_TABLE,
      FilterExpression: '#id = :id',
      ProjectionExpression: '#id, #n, logoUrl, avatarUrl',
      ExpressionAttributeNames: { '#id': 'id', '#n': 'name' },
      ExpressionAttributeValues: { ':id': id },
    }).promise();
    return (s.Items && s.Items[0]) || null;
  } catch (_) { return null; }
}

async function getNgoBasicById(id) {
  if (!NGO_TABLE || !id) return null;
  // Try id GSI first
  try {
    const q = await ddb.query({
      TableName: NGO_TABLE,
      IndexName: 'id-index',
      KeyConditionExpression: 'id = :id',
      ExpressionAttributeValues: { ':id': id },
      ProjectionExpression: 'id, name, logoUrl, avatarUrl'
    }).promise();
    if (q.Items && q.Items[0]) return q.Items[0];
  } catch (_) {}
  // Fallback scan
  try {
    const s = await ddb.scan({
      TableName: NGO_TABLE,
      FilterExpression: '#i = :id',
      ExpressionAttributeNames: { '#i': 'id' },
      ExpressionAttributeValues: { ':id': id },
      ProjectionExpression: 'id, name, logoUrl, avatarUrl'
    }).promise();
    return (s.Items && s.Items[0]) || null;
  } catch (_) { return null; }
}

// Stamp userName/userAvatar/ngoName/ngoAvatar once on creation
async function maybeStampDisplayFields(conv) {
  try {
    const [u, n] = await Promise.all([
      getUserBasicById(conv.userId),
      getNgoBasicById(conv.ngoId)
    ]);

    const patch = {};
    if (u) {
      if (u.name)      patch.userName = u.name;
      if (u.avatarUrl) patch.userAvatar = u.avatarUrl;
    }
    if (n) {
      if (n.name)                    patch.ngoName = n.name;
      if (n.logoUrl || n.avatarUrl)  patch.ngoAvatar = n.logoUrl || n.avatarUrl;
    }

    if (Object.keys(patch).length) {
      const names = Object.keys(patch);
      const setExp = names.map((k, i) => `#${i} = :${i}`).join(', ');
      const attrNames = {};
      const attrValues = {};
      names.forEach((k, i) => {
        attrNames[`#${i}`] = k;
        attrValues[`:${i}`] = patch[k];
      });

      await ddb.update({
        TableName: CONVERSATIONS_TABLE,
        Key: { id: conv.id },
        UpdateExpression: `SET ${setExp}`,
        ExpressionAttributeNames: attrNames,
        ExpressionAttributeValues: attrValues
      }).promise();

      Object.assign(conv, patch);
    }
  } catch (e) {
    // Non-fatal
    console.warn('[msg/stampDisplay] failed:', e?.message || e);
  }
}

// O(1) exact lookup via GSIs
async function findExistingConversationFast({ userId, ngoId }) {
  // Prefer userNgo-index (PK userId, SK ngoId)
  try {
    const out = await ddb.query({
      TableName: CONVERSATIONS_TABLE,
      IndexName: 'userNgo-index',
      KeyConditionExpression: 'userId = :u AND ngoId = :n',
      ExpressionAttributeValues: { ':u': userId, ':n': ngoId },
      Limit: 1,
    }).promise();
    if (out.Items && out.Items[0]) return out.Items[0];
  } catch (_) {}
  // Fallback the other way (PK ngoId, SK userId)
  try {
    const out = await ddb.query({
      TableName: CONVERSATIONS_TABLE,
      IndexName: 'ngoUser-index',
      KeyConditionExpression: 'ngoId = :n AND userId = :u',
      ExpressionAttributeValues: { ':n': ngoId, ':u': userId },
      Limit: 1,
    }).promise();
    return (out.Items && out.Items[0]) || null;
  } catch (_) { return null; }
  return null;
}

// update last message + unread counter (+ messageCount)
async function bumpConversation(convId, lastMessage, tsISO, senderRole) {
  const updateExp = [
    'lastMessage = :m',
    'lastTimestamp = :t',
    'messageCount = if_not_exists(messageCount, :z) + :one'
  ];
  const exprVals  = { ':m': lastMessage, ':t': tsISO, ':z': 0, ':one': 1 };

  if (senderRole === 'user') {
    updateExp.push('ngoUnread = if_not_exists(ngoUnread, :z) + :one');
  } else {
    updateExp.push('userUnread = if_not_exists(userUnread, :z) + :one');
  }

  await ddb.update({
    TableName: CONVERSATIONS_TABLE,
    Key: { id: convId },
    UpdateExpression: 'SET ' + updateExp.join(', '),
    ExpressionAttributeValues: exprVals,
  }).promise();
}

// ---------- routes ----------

// Start (or fetch) a conversation
// user: body { ngoId } ; ngo: body { userId }
router.post('/conversations/start', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    let userId, ngoId;

    if (actor.role === 'user') {
      userId = actor.id;
      ngoId  = req.body?.ngoId;
    } else if (actor.role === 'ngo') {
      ngoId  = actor.id;
      userId = req.body?.userId;
    } else {
      return res.status(403).json({ error: 'Unsupported role.' });
    }

    if (!userId || !ngoId) {
      return res.status(400).json({ error: 'Missing userId or ngoId.' });
    }

    // quick check
    let conv = await findExistingConversationFast({ userId, ngoId });

    if (!conv) {
      conv = {
        id: uuidv4(),
        userId,
        ngoId,
        participants: [userId, ngoId],
        lastMessage: '',
        lastTimestamp: new Date().toISOString(),
        userUnread: 0,
        ngoUnread: 0,
        messageCount: 0
      };

      // Avoid duplicate creation on race
      try {
        await ddb.put({
          TableName: CONVERSATIONS_TABLE,
          Item: conv,
          ConditionExpression: 'attribute_not_exists(id)'
        }).promise();
      } catch (e) {
        if (e.code === 'ConditionalCheckFailedException') {
          // someone else created it — read again
          conv = await findExistingConversationFast({ userId, ngoId });
        } else {
          throw e;
        }
      }

      // Stamp display fields once (optional but nice)
      if (conv) await maybeStampDisplayFields(conv);
    }

    res.json({ conversation: conv });
  } catch (err) {
    console.error('[msg/start]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// List my conversations
router.get('/conversations', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    let out;

    if (actor.role === 'user') {
      out = await ddb.query({
        TableName: CONVERSATIONS_TABLE,
        IndexName: 'userId-index', // PK: userId, SK: lastTimestamp
        KeyConditionExpression: 'userId = :u',
        ExpressionAttributeValues: { ':u': actor.id },
        ScanIndexForward: false,
      }).promise();
    } else if (actor.role === 'ngo') {
      out = await ddb.query({
        TableName: CONVERSATIONS_TABLE,
        IndexName: 'ngoId-index', // PK: ngoId, SK: lastTimestamp
        KeyConditionExpression: 'ngoId = :n',
        ExpressionAttributeValues: { ':n': actor.id },
        ScanIndexForward: false,
      }).promise();
    } else {
      return res.status(403).json({ error: 'Unsupported role.' });
    }

    res.json({ conversations: out.Items || [] });
  } catch (err) {
    console.error('[msg/list]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Get messages (supports `cursor` token OR `from` ISO)
// GET /conversations/:id/messages?limit=50&cursor=...&from=ISO
router.get('/conversations/:id/messages', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    const conversationId = req.params.id;
    const limit  = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const cursor = req.query.cursor; // base64 LastEvaluatedKey
    const from   = req.query.from;   // ISO lower bound (optional)

    const conv = await getConversationById(conversationId);
    if (!canAccess(conv, actor)) return res.status(403).json({ error: 'Forbidden.' });

    const params = {
      TableName: MESSAGES_TABLE,
      KeyConditionExpression: 'conversationId = :c',
      ExpressionAttributeValues: { ':c': conversationId },
      Limit: limit,
      ScanIndexForward: true, // chronological
    };

    if (from) {
      params.KeyConditionExpression += ' AND createdAtId > :fromId';
      params.ExpressionAttributeValues[':fromId'] = `${from}#`;
    }

    if (cursor) {
      const eks = safeBase64JsonDecode(cursor);
      if (eks) params.ExclusiveStartKey = eks;
    }

    let out;
    try {
      out = await ddb.query(params).promise();
    } catch (e) {
      // If table key schema is wrong, Query may throw ValidationException — fallback to Scan so user isn't blocked
      if (e.code === 'ValidationException') {
        console.warn('[msg/get] Query failed; falling back to Scan. Fix messages table keys.');
        const scanRes = await ddb.scan({
          TableName: MESSAGES_TABLE,
          FilterExpression: 'conversationId = :c',
          ExpressionAttributeValues: { ':c': conversationId }
        }).promise();
        const items = (scanRes.Items || []).sort((a, b) => {
          const ka = a.createdAtId || `${a.createdAt || ''}#${a.id || ''}`;
          const kb = b.createdAtId || `${b.createdAt || ''}#${b.id || ''}`;
          return ka.localeCompare(kb);
        }).slice(0, limit);
        return res.json({ messages: items, nextCursor: null });
      }
      throw e;
    }

    const nextCursor = out.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(out.LastEvaluatedKey), 'utf8').toString('base64')
      : null;

    res.json({ messages: out.Items || [], nextCursor });
  } catch (err) {
    console.error('[msg/get]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Send a message (uses composite SK)
router.post('/conversations/:id/messages', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    const conversationId = req.params.id;
    const { text = '', attachments = [] } = req.body || {};

    if (!text && (!attachments || !attachments.length)) {
      return res.status(400).json({ error: 'Message must have text or attachments.' });
    }

    const conv = await getConversationById(conversationId);
    if (!canAccess(conv, actor)) return res.status(403).json({ error: 'Forbidden.' });

    const createdAt   = new Date().toISOString();
    const id          = uuidv4();
    const createdAtId = `${createdAt}#${id}`;

    const item = {
      conversationId,           // PK
      createdAtId,              // SK (lexical chronological)
      id,                       // message id
      createdAt,                // ISO for display
      senderRole: actor.role,
      senderId: actor.id,
      text: String(text).trim(),
      attachments: Array.isArray(attachments) ? attachments : [],
      readBy: [actor.id],
    };

    // Prevent accidental duplicate writes
    await ddb.put({
      TableName: MESSAGES_TABLE,
      Item: item,
      ConditionExpression: 'attribute_not_exists(createdAtId)'
    }).promise();

    await bumpConversation(
      conversationId,
      item.text || (item.attachments.length ? '[attachment]' : ''),
      createdAt,
      actor.role
    );

    res.status(201).json({ message: item });
  } catch (err) {
    console.error('[msg/send]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Reset unread count for current actor
router.post('/conversations/:id/read', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    const conversationId = req.params.id;

    const conv = await getConversationById(conversationId);
    if (!canAccess(conv, actor)) return res.status(403).json({ error: 'Forbidden.' });

    const updateExp = actor.role === 'user'
      ? 'SET userUnread = :z'
      : 'SET ngoUnread = :z';

    await ddb.update({
      TableName: CONVERSATIONS_TABLE,
      Key: { id: conversationId },
      UpdateExpression: updateExp,
      ExpressionAttributeValues: { ':z': 0 },
    }).promise();

    res.json({ status: 'ok' });
  } catch (err) {
    console.error('[msg/read]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Pre-sign S3 upload (v2)
router.post('/attachments/presign', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    const { filename, contentType, conversationId } = req.body || {};
    if (!filename || !contentType || !conversationId) {
      return res.status(400).json({ error: 'Missing filename/contentType/conversationId.' });
    }

    if (!MESSAGES_BUCKET) {
      return res.status(500).json({ error: 'Server misconfig: MESSAGES_BUCKET is not set.' });
    }

    const conv = await getConversationById(conversationId);
    if (!canAccess(conv, actor)) return res.status(403).json({ error: 'Forbidden.' });

    // sanitize basic filename
    const safeName = String(filename).replace(/[^\w.\-()+@ ]+/g, '_');

    const key = `conversations/${conversationId}/${uuidv4()}-${safeName}`;

    // IMPORTANT: include ACL in the signature so the uploaded object is publicly readable
    const uploadUrl = await s3.getSignedUrlPromise('putObject', {
      Bucket: MESSAGES_BUCKET,
      Key: key,
      ContentType: contentType,
      ACL: 'public-read',
      Expires: 60 * 5,
    });

    // region-safe public URL (us-east-1 uses s3.amazonaws.com)
    const region = process.env.AWS_REGION || 'us-east-1';
    const host = region === 'us-east-1'
      ? `https://${MESSAGES_BUCKET}.s3.amazonaws.com`
      : `https://${MESSAGES_BUCKET}.s3.${region}.amazonaws.com`;
    const publicUrl = `${host}/${encodeURI(key)}`;

    // Tell the client which headers must be included on PUT
    res.json({
      uploadUrl,
      requiredHeaders: { 'Content-Type': contentType, 'x-amz-acl': 'public-read' },
      file: { key, url: publicUrl, contentType }
    });
  } catch (err) {
    console.error('[msg/presign]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
