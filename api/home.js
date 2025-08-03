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
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

const POSTS_TABLE = process.env.POSTS_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;
const IMAGES_BUCKET = process.env.LOGOS_BUCKET; // Reusing same bucket

const upload = multer({ storage: multer.memoryStorage() });

// Upload images to S3 helper
const uploadImagesToS3 = async (files) => {
  const uploads = files.map(async (file) => {
    const key = `posts/${uuidv4()}-${file.originalname}`;
    const params = {
      Bucket: IMAGES_BUCKET,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
      ACL: 'public-read'
    };
    const result = await s3.upload(params).promise();
    console.log('Uploaded to S3:', result.Location);
    return result.Location;
  });
  return Promise.all(uploads);
};

// GET Posts (public)
router.get('/posts', async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: POSTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

router.get('/posts/:postId', async (req, res) => {
  const { postId } = req.params;
  try {
    const { Item } = await ddb.get({ TableName: POSTS_TABLE, Key: { postId } }).promise();
    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// POST Create Post
router.post('/posts', authenticateJWT, authorizeRoles('ngo'), upload.array('images'), async (req, res) => {
  const { id: ngoId } = req.user;
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text is required.' });

  const postId = uuidv4();
  let imageLinks = [];

  try {
    if (req.files?.length) imageLinks = await uploadImagesToS3(req.files);

    const item = {
      postId,
      ngoId,
      text,
      images: imageLinks,
      createdAt: new Date().toISOString()
    };

    await ddb.put({ TableName: POSTS_TABLE, Item: item }).promise();
    res.status(201).json({ postId, status: 'ok', images: imageLinks });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH Update Post
router.patch('/posts/:postId', authenticateJWT, authorizeRoles('ngo'), upload.array('images'), async (req, res) => {
  const { postId } = req.params;
  const { text } = req.body;

  try {
    const { Item } = await ddb.get({ TableName: POSTS_TABLE, Key: { postId } }).promise();
    if (!Item) return res.sendStatus(404);
    if (Item.ngoId !== req.user.id) return res.sendStatus(403);

    const imageLinks = req.files?.length ? await uploadImagesToS3(req.files) : Item.images;

    await ddb.update({
      TableName: POSTS_TABLE,
      Key: { postId },
      UpdateExpression: 'SET text = :text, images = :images',
      ExpressionAttributeValues: {
        ':text': text,
        ':images': imageLinks
      }
    }).promise();

    res.json({ status: 'ok', images: imageLinks });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// DELETE Post
router.delete('/posts/:postId', authenticateJWT, authorizeRoles('ngo'), async (req, res) => {
  const { postId } = req.params;
  try {
    const { Item } = await ddb.get({ TableName: POSTS_TABLE, Key: { postId } }).promise();
    if (!Item) return res.sendStatus(404);
    if (Item.ngoId !== req.user.id) return res.sendStatus(403);

    await ddb.delete({ TableName: POSTS_TABLE, Key: { postId } }).promise();
    res.json({ status: 'deleted' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// GET Requests (public)
router.get('/requests', async (req, res) => {
  try {
    const data = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
    res.json(data.Items);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

router.get('/requests/:requestId', async (req, res) => {
  const { requestId } = req.params;
  try {
    const { Item } = await ddb.get({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
    if (!Item) return res.sendStatus(404);
    res.json(Item);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

// POST Create Request
router.post('/requests', authenticateJWT, authorizeRoles('ngo'), async (req, res) => {
  const { id: ngoId } = req.user;
  const { category, count, gender, status, dateNeeded, location, size, ageRange } = req.body;

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
});

// PATCH Update Request
router.patch('/requests/:requestId', authenticateJWT, authorizeRoles('ngo'), async (req, res) => {
  const { requestId } = req.params;
  const keys = Object.keys(req.body);
  if (!keys.length) return res.status(400).json({ error: 'No update fields provided' });

  try {
    const { Item } = await ddb.get({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
    if (!Item) return res.sendStatus(404);
    if (Item.ngoId !== req.user.id) return res.sendStatus(403);

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
});

// DELETE Request
router.delete('/requests/:requestId', authenticateJWT, authorizeRoles('ngo'), async (req, res) => {
  const { requestId } = req.params;
  try {
    const { Item } = await ddb.get({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
    if (!Item) return res.sendStatus(404);
    if (Item.ngoId !== req.user.id) return res.sendStatus(403);

    await ddb.delete({ TableName: REQUESTS_TABLE, Key: { requestId } }).promise();
    res.json({ status: 'deleted' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

module.exports = router;
