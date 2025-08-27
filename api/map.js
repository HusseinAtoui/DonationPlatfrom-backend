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


// GET api/map/ngos?withRequests=true&categories=jackets,shoes
router.get('/ngos', async (req, res) => {
  const { withRequests, categories } = req.query;

  try {
    const ngosData = await ddb.scan({ TableName: NGO_TABLE }).promise();
    let ngos = ngosData.Items;

    // Filter out NGOs with invalid location data
    ngos = ngos.filter(ngo => {
      if (
        ngo.coordinates &&
        typeof ngo.coordinates.lat === 'number' &&
        typeof ngo.coordinates.lng === 'number'
      ) {
        return true;
      }
      return false; // Exclude all other cases
    });

    if (withRequests === 'true') {
      if (!categories) {
        return res.status(400).json({ error: 'Missing "categories" query parameter when withRequests=true' });
      }

      const requestsData = await ddb.scan({ TableName: REQUESTS_TABLE }).promise();
      let requests = requestsData.Items;

      if (categories !== 'any') {
        const categoryFilter = categories
          .split(',')
          .map(cat => cat.trim().toLowerCase());

        requests = requests.filter(req => {
          const category = req.category?.toLowerCase();
          return categoryFilter.includes(category);
        });
      }

      const ngoIdsWithMatchingRequests = new Set(requests.map(r => r.ngoId));
      ngos = ngos.filter(ngo => ngoIdsWithMatchingRequests.has(ngo.id));
    }

    res.json(ngos);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

module.exports = router;