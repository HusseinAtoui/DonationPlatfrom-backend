const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const { id } = require('zod/v4/locales');
require('dotenv').config();

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
const ddb = new AWS.DynamoDB.DocumentClient();
const NGO_TABLE = process.env.NGO_TABLE;
const REQUESTS_TABLE = process.env.REQUESTS_TABLE;

/* --------------------------------------------------------------------------
   GET /map/ngos
   Returns all NGOs with valid coordinates
-------------------------------------------------------------------------- */
router.get('/ngos', async (req, res) => {
  try {
    const ngosData = await ddb.scan({ TableName: NGO_TABLE }).promise();
    const ngos = (ngosData.Items || []).filter(ngo => 
      ngo.coordinates &&
      typeof ngo.coordinates.lat === 'number' &&
      typeof ngo.coordinates.lng === 'number'
    );

    res.json(ngos);
  } catch (err) {
    console.error('[GET /map/ngos]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* --------------------------------------------------------------------------
   GET /map/requests
   Returns all requests with valid coordinates
   Optional query: ?category=jackets,shoes
-------------------------------------------------------------------------- */
router.get('/requests', async (req, res) => {
  const { category } = req.query;

  try {
    const requestsData = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
    let requests = (requestsData.Items || []).filter(req =>
      req.coordinates &&
      typeof req.coordinates.lat === 'number' &&
      typeof req.coordinates.lng === 'number' &&
      req.status !== 'completed'
    );

    if (category && category !== 'any') {
      const categoryFilter = category
        .split(',')
        .map(cat => cat.trim().toLowerCase());

      requests = requests.filter(req =>
        req.category && categoryFilter.includes(req.category.toLowerCase())
      );
    }

    const ngosData = await ddb.scan({ TableName: NGO_TABLE }).promise();
    const ngos = (ngosData.Items || [])

    const requestsWithNgo = requests.map(req => {
      const ngo = ngos.find(n => n.id === req.ngoId);
      return { ...req, ngo: ngo || null };
    });

    res.json(requestsWithNgo);

  } catch (err) {
    console.error('[GET /map/requests]', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;