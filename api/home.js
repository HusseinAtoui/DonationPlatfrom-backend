const express = require('express');
const router = express.Router();
const multer = require('multer');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const { authenticateJWT } = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorize');

require('dotenv').config();
AWS.config.update({ region: process.env.AWS_REGION });
const ddb = new AWS.DynamoDB.DocumentClient();

const POSTS_TABLE = process.env.POSTS_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;

// Multer setup for multipart/form-data
const storage = multer.memoryStorage();
const upload = multer({ storage });

// 🟡 Read All Posts (public)
router.get('/posts', async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: POSTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟡 Get Single Post (public)
router.get('/posts/:postId', async (req, res) => {
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

// 🟢 Create Post (ngo only)
router.post(
  '/posts',
  authenticateJWT,
  authorizeRoles('ngo'),
  upload.array('images'),
  async (req, res) => {
    const { id: ngoId } = req.user;
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Text is required.' });

    const postId = uuidv4();
    const images = req.files?.map(file => ({
      name: file.originalname,
      buffer: file.buffer.toString('base64'),
      mimetype: file.mimetype
    })) || [];

    const item = {
      postId,
      ngoId,
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
  }
);

// 🟠 Update Post (same ngo only)
router.patch(
  '/posts/:postId',
  authenticateJWT,
  authorizeRoles('ngo'),
  upload.array('images'),
  async (req, res) => {
    const { postId } = req.params;
    const { text } = req.body;
    const images = req.files?.map(file => ({
      name: file.originalname,
      buffer: file.buffer.toString('base64'),
      mimetype: file.mimetype
    })) || [];

    try {
      // verify ownership
      const { Item } = await ddb.get({ TableName: POSTS_TABLE, Key: { postId } }).promise();
      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      // perform update
      await ddb.update({
        TableName: POSTS_TABLE,
        Key: { postId },
        UpdateExpression: 'SET text = :text, images = :images',
        ExpressionAttributeValues: {
          ':text': text,
          ':images': images
        }
      }).promise();

      res.json({ status: 'ok' });
    } catch (e) {
      console.error(e);
      res.sendStatus(500);
    }
  }
);

// 🔴 Delete Post (same ngo only)
router.delete(
  '/posts/:postId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    const { postId } = req.params;
    try {
      // verify ownership
      const { Item } = await ddb.get({ TableName: POSTS_TABLE, Key: { postId } }).promise();
      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      await ddb.delete({ TableName: POSTS_TABLE, Key: { postId } }).promise();
      res.json({ status: 'deleted' });
    } catch (e) {
      console.error(e);
      res.sendStatus(500);
    }
  }
);

// 🟡 List Requests (public)
router.get('/requests', async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟡 Get Single Request (public)
router.get('/requests/:requestId', async (req, res) => {
  const { requestId } = req.params;
  try {
    const { Item } = await ddb.get({
      TableName: REQUESTS_TABLE,
      Key: { requestId }
    }).promise();
    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// 🟢 Create Donation Request (ngo only)
router.post(
  '/requests',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    const { id: ngoId } = req.user;
    const {
      category, count, gender, status,
      dateNeeded, location, size, ageRange
    } = req.body;

    if (!category || !count || !status || !dateNeeded || !location)
      return res.status(400).json({ error: 'Missing required fields' });

    const requestId = uuidv4();
    const item = {
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
      createdAt: new Date().toISOString()
    };

    try {
      await ddb.put({ TableName: REQUESTS_TABLE, Item: item }).promise();
      res.status(201).json({ requestId, status: 'ok' });
    } catch (e) {
      console.error(e);
      res.sendStatus(500);
    }
  }
);

// 🟠 Update Request (same ngo only)
router.patch(
  '/requests/:requestId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    const { requestId } = req.params;
    const keys = Object.keys(req.body);
    if (!keys.length) return res.status(400).json({ error: 'No update fields provided' });

    try {
      // verify ownership
      const { Item } = await ddb.get({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      // build update expression
      const updateExp = keys.map((key, i) => `#k${i} = :v${i}`).join(', ');
      const attrNames = Object.fromEntries(keys.map((key, i) => [`#k${i}`, key]));
      const attrValues = Object.fromEntries(keys.map((key, i) => [`:v${i}`, req.body[key]]));

      await ddb.update({
        TableName: REQUESTS_TABLE,
        Key: { requestId },
        UpdateExpression: `SET ${updateExp}`,
        ExpressionAttributeNames: attrNames,
        ExpressionAttributeValues: attrValues
      }).promise();

      res.json({ status: 'ok' });
    } catch (e) {
      console.error(e);
      res.sendStatus(500);
    }
  }
);

// 🔴 Delete Request (same ngo only)
router.delete(
  '/requests/:requestId',
  authenticateJWT,
  authorizeRoles('ngo'),
  async (req, res) => {
    const { requestId } = req.params;
    try {
      // verify ownership
      const { Item } = await ddb.get({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
      if (!Item) return res.sendStatus(404);
      if (Item.ngoId !== req.user.id) return res.sendStatus(403);

      await ddb.delete({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
      res.json({ status: 'deleted' });
    } catch (e) {
      console.error(e);
      res.sendStatus(500);
    }
  }
);

module.exports = router;
