const express = require('express');
const router = express.Router();
const multer = require('multer');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');

require('dotenv').config();
AWS.config.update({ region: process.env.AWS_REGION });
const ddb = new AWS.DynamoDB.DocumentClient();

const POSTS_TABLE = process.env.POSTS_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;

// Multer setup for multipart/form-data
const storage = multer.memoryStorage();
const upload = multer({ storage });

router.post('/posts', upload.array('images'), async (req, res) => {
  // 🧪 MOCK USER FOR TESTING
  req.user = { id: 'mock-ngo-id', role: 'ngo' };

  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text is required.' });

  const postId = uuidv4();
  const images = req.files?.map((file, i) => ({
    name: file.originalname,
    buffer: file.buffer.toString('base64'),
    mimetype: file.mimetype
  })) || [];

  const item = {
    postId,
    ngoId: req.user.id,
    text,
    images,
    createdAt: new Date().toISOString()
  };

  try {
    await ddb.put({ TableName: POSTS_TABLE, Item: item }).promise();
    res.status(201).json({ postId, status: 'ok' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});


// 🟡 Read All Posts
router.get('/posts', authenticateJWT, async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: POSTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟡 Get Single Post
router.get('/posts/:postId', authenticateJWT, async (req, res) => {
  const { postId } = req.params;
  try {
    const { Item } = await ddb.get({
      TableName: POSTS_TABLE,
      Key: { postId }
    }).promise();
    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟠 Update Post
router.patch('/posts/:postId', authenticateJWT, upload.array('images'), async (req, res) => {
  const { postId } = req.params;
  const { text } = req.body;
  const images = req.files?.map(file => ({
    name: file.originalname,
    buffer: file.buffer.toString('base64'),
    mimetype: file.mimetype
  })) || [];

  const updateParams = {
    TableName: POSTS_TABLE,
    Key: { postId },
    UpdateExpression: 'SET text = :text, images = :images',
    ExpressionAttributeValues: {
      ':text': text,
      ':images': images
    }
  };

  try {
    await ddb.update(updateParams).promise();
    res.json({ status: 'ok' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🔴 Delete Post
router.delete('/posts/:postId', authenticateJWT, async (req, res) => {
  try {
    await ddb.delete({
      TableName: POSTS_TABLE,
      Key: { postId: req.params.postId }
    }).promise();
    res.json({ status: 'deleted' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟢 Create Donation Request
router.post('/requests', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'ngo') return res.sendStatus(403);

  const {
    category, count, gender, status,
    dateNeeded, location, size, ageRange
  } = req.body;

  if (!category || !count || !status || !dateNeeded || !location)
    return res.status(400).json({ error: 'Missing required fields' });

  const requestId = uuidv4();

  const item = {
    requestId,
    ngoId: req.user.id,
    category,
    count: Number(count),
    gender,
    status,
    dateNeeded,
    location,
    size,
    ageRange,
    createdAt: new Date().toISOString()
  };

  try {
    await ddb.put({ TableName: REQUESTS_TABLE, Item: item }).promise();
    res.status(201).json({ requestId, status: 'ok' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟡 List Requests (with optional filters)
router.get('/requests', authenticateJWT, async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟡 Get Single Request
router.get('/requests/:requestId', authenticateJWT, async (req, res) => {
  try {
    const { Item } = await ddb.get({
      TableName: REQUESTS_TABLE,
      Key: { requestId: req.params.requestId }
    }).promise();
    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟠 Update Request
router.patch('/requests/:requestId', authenticateJWT, async (req, res) => {
  const keys = Object.keys(req.body);
  if (!keys.length) return res.status(400).json({ error: 'No update fields provided' });

  const updateExp = keys.map((key, i) => `#k${i} = :v${i}`).join(', ');
  const attrNames = Object.fromEntries(keys.map((key, i) => [`#k${i}`, key]));
  const attrValues = Object.fromEntries(keys.map((key, i) => [`:v${i}`, req.body[key]]));

  const params = {
    TableName: REQUESTS_TABLE,
    Key: { requestId: req.params.requestId },
    UpdateExpression: `SET ${updateExp}`,
    ExpressionAttributeNames: attrNames,
    ExpressionAttributeValues: attrValues
  };

  try {
    await ddb.update(params).promise();
    res.json({ status: 'ok' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🔴 Delete Request
router.delete('/requests/:requestId', authenticateJWT, async (req, res) => {
  try {
    await ddb.delete({
      TableName: REQUESTS_TABLE,
      Key: { requestId: req.params.requestId }
    }).promise();
    res.json({ status: 'deleted' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

module.exports = router;
