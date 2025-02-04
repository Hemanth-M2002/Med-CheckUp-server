const express = require('express');
const jwt = require('jsonwebtoken');
const CheckIn = require('../models/CheckIn');
const crypto = require('crypto');
const router = express.Router();

const algorithm = 'aes-256-ctr';
const secretKey = process.env.SECRET_KEY;

const encrypt = (text) => {
  const cipher = crypto.createCipher(algorithm, secretKey);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

const decrypt = (encryptedText) => {
  const decipher = crypto.createDecipher(algorithm, secretKey);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const authenticate = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

router.post('/', authenticate, async (req, res) => {
  const { data } = req.body;
  try {
    const encryptedData = encrypt(data);
    const checkIn = new CheckIn({ userId: req.userId, encryptedData });
    await checkIn.save();
    res.json({ message: 'Check-in saved' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/', authenticate, async (req, res) => {
  try {
    const checkIns = await CheckIn.find({ userId: req.userId });
    res.json(checkIns.map((entry) => ({ ...entry._doc, data: decrypt(entry.encryptedData) })));
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;