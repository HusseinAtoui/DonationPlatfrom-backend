// routes/messaging.js
const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
require('dotenv').config();

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ddb = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

const CONVERSATIONS_TABLE = process.env.CONVERSATIONS_TABLE;
const MESSAGES_TABLE = process.env.MESSAGES_TABLE;
const MESSAGES_BUCKET = process.env.MESSAGES_BUCKET;

// ---------- helpers ----------------------------------------------------------

function actorFromReq(req) {
  const { id, role } = req.user || {};
  if (!id || !role) throw new Error('Invalid auth payload.');
  return { id, role };
}

async function getConversationById(conversationId) {
  const { Item } = await ddb.get({
    TableName: CONVERSATIONS_TABLE,
    Key: { id: conversationId },
  }).promise();
  return Item || null;
}

function canAccess(conv, actor) {
  if (!conv) return false;
  if (actor.role === 'user') return conv.userId === actor.id;
  if (actor.role === 'ngo') return conv.ngoId === actor.id;
  return false;
}

// NEW: O(1) exact lookup from either side (needs GSIs below)
async function findExistingConversationFast({ userId, ngoId, startedBy }) {
  if (startedBy === 'user') {
    // GSI: userNgo-index (PK: userId, SK: ngoId)
    const out = await ddb.query({
      TableName: CONVERSATIONS_TABLE,
      IndexName: 'userNgo-index',
      KeyConditionExpression: 'userId = :u AND ngoId = :n',
      ExpressionAttributeValues: { ':u': userId, ':n': ngoId },
      Limit: 1,
    }).promise();
    return (out.Items && out.Items[0]) || null;
  } else {
    // GSI: ngoUser-index (PK: ngoId, SK: userId)
    const out = await ddb.query({
      TableName: CONVERSATIONS_TABLE,
      IndexName: 'ngoUser-index',
      KeyConditionExpression: 'ngoId = :n AND userId = :u',
      ExpressionAttributeValues: { ':n': ngoId, ':u': userId },
      Limit: 1,
    }).promise();
    return (out.Items && out.Items[0]) || null;
  }
}

// update last message + unread counter
async function bumpConversation(convId, lastMessage, tsISO, senderRole) {
  const updateExp = ['lastMessage = :m', 'lastTimestamp = :t'];
  const exprVals = { ':m': lastMessage, ':t': tsISO, ':z': 0, ':one': 1 };

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

// ---------- routes -----------------------------------------------------------

// Start (or fetch) a conversation
// user: body { ngoId } ; ngo: body { userId }
router.post('/conversations/start', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    let userId, ngoId, startedBy;

    if (actor.role === 'user') {
      userId = actor.id;
      ngoId = req.body.ngoId;
      startedBy = 'user';
    } else if (actor.role === 'ngo') {
      ngoId = actor.id;
      userId = req.body.userId;
      startedBy = 'ngo';
    } else {
      return res.status(403).json({ error: 'Unsupported role.' });
    }

    if (!userId || !ngoId) return res.status(400).json({ error: 'Missing userId or ngoId.' });

    // FAST exact match via GSI
    let conv = await findExistingConversationFast({ userId, ngoId, startedBy });

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
      };
      await ddb.put({ TableName: CONVERSATIONS_TABLE, Item: conv }).promise();
    }

    res.json({ conversation: conv });
  } catch (err) {
    console.error('[msg/start]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// List my conversations (still using list GSIs)
router.get('/conversations', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    let out;

    if (actor.role === 'user') {
      // GSI: userId-index (PK: userId, optional SK: lastTimestamp)
      out = await ddb.query({
        TableName: CONVERSATIONS_TABLE,
        IndexName: 'userId-index',
        KeyConditionExpression: 'userId = :u',
        ExpressionAttributeValues: { ':u': actor.id },
        ScanIndexForward: false,
      }).promise();
    } else if (actor.role === 'ngo') {
      // GSI: ngoId-index (PK: ngoId, optional SK: lastTimestamp)
      out = await ddb.query({
        TableName: CONVERSATIONS_TABLE,
        IndexName: 'ngoId-index',
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
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const cursor = req.query.cursor; // base64 LastEvaluatedKey
    const from = req.query.from;     // ISO lower bound (optional)

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
      // composite SK: createdAtId = "<ISO>#<uuid>"
      params.KeyConditionExpression += ' AND createdAtId > :fromId';
      params.ExpressionAttributeValues[':fromId'] = `${from}#`;
    }

    if (cursor) {
      try {
        params.ExclusiveStartKey = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'));
      } catch (_) {}
    }

    const out = await ddb.query(params).promise();

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

    const createdAt = new Date().toISOString();
    const id = uuidv4();
    const createdAtId = `${createdAt}#${id}`;

    const item = {
      conversationId,           // PK
      createdAtId,              // SK (lexical chronological)
      id,                       // message id
      createdAt,                // keep ISO separately for easy display
      senderRole: actor.role,
      senderId: actor.id,
      text: text.trim(),
      attachments: Array.isArray(attachments) ? attachments : [],
      readBy: [actor.id],
    };

    await ddb.put({ TableName: MESSAGES_TABLE, Item: item }).promise();

    await bumpConversation(
      conversationId,
      text || (attachments.length ? '[attachment]' : ''),
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

    const updateExp = actor.role === 'user' ? 'SET userUnread = :z' : 'SET ngoUnread = :z';
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

// Pre-sign S3 upload
router.post('/attachments/presign', authenticateJWT, async (req, res) => {
  try {
    const actor = actorFromReq(req);
    const { filename, contentType, conversationId } = req.body || {};
    if (!filename || !contentType || !conversationId) {
      return res.status(400).json({ error: 'Missing filename/contentType/conversationId.' });
    }

    const conv = await getConversationById(conversationId);
    if (!canAccess(conv, actor)) return res.status(403).json({ error: 'Forbidden.' });

    const key = `conversations/${conversationId}/${uuidv4()}-${filename}`;
    const uploadUrl = await s3.getSignedUrlPromise('putObject', {
      Bucket: MESSAGES_BUCKET,
      Key: key,
      ContentType: contentType,
      Expires: 60 * 5,
    });
    const publicUrl = `https://${MESSAGES_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${encodeURI(
      key
    )}`;

    res.json({ uploadUrl, file: { key, url: publicUrl, contentType } });
  } catch (err) {
    console.error('[msg/presign]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
