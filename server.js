// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const ngoAuth = require('./api/ngoAuth');
const userAuth = require('./api/userAuth');
const home = require('./api/home'); 
const map = require('./api/map');
const app = express();
app.use(express.json());

app.use(cors());

// Mount routers
app.use('/ngo', ngoAuth);
app.use('/user', userAuth);
app.use('/home', home);
app.use('/map', map)
// Global error handler (fallback)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong.' });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
