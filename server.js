// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const ngoAuth = require('./api/ngoAuth');
const userAuth = require('./api/userAuth');
const home = require('./api/home'); 
const map = require('./api/map');
const app = express();
app.use(cors());               // allow the React dev server
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

// run backend on 4000 (avoid React port)
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 API on http://localhost:${PORT}`);
});
