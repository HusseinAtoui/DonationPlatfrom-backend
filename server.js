// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const ngoAuth = require('./api/ngoAuth');
const userAuth = require('./api/userAuth');
const home = require('./api/home');
const map = require('./api/map')

const messaging = require('./api/messaging');
const app = express();
app.use(cors());               // allow the React dev server
app.use(express.json());

// quick test route
app.get('/api/health', (req, res) => res.json({ ok: true }));

// prefix all routes with /api
app.use('/api/ngo', ngoAuth);
app.use('/api/user', userAuth);
app.use('/api/home', home);
app.use('/api/map', map)

app.use('/api/messaging', messaging);
// error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong.' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 API on http://localhost:${PORT}`);
});

