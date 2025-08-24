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


// ---- helpers ---------------------------------------------------------------


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


async function findExistingConversation(userId, ngoId) {
// Query by user side then filter by NGO
const out = await ddb
.query({
TableName: CONVERSATIONS_TABLE,
IndexName: 'userId-index',
KeyConditionExpression: 'userId = :u',
ExpressionAttributeValues: { ':u': userId },
})
.promise();


return (out.Items || []).find((c) => c.ngoId === ngoId) || null;
}


async function bumpConversation(convId, lastMessage, tsISO, senderRole) {
const updateExp = ['lastMessage = :m', 'lastTimestamp = :t'];
const exprVals = { ':m': lastMessage, ':t': tsISO, ':z': 0, ':one': 1 };


if (senderRole === 'user') {
updateExp.push('ngoUnread = if_not_exists(ngoUnread, :z) + :one');
} else {
updateExp.push('userUnread = if_not_exists(userUnread, :z) + :one');
}


module.exports = router;