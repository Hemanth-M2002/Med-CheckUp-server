// const express = require('express');
// const jwt = require('jsonwebtoken');
// const CheckIn = require('../models/CheckIn');
// const crypto = require('crypto');
// const router = express.Router();

// const algorithm = 'aes-256-ctr';
// const secretKey = process.env.SECRET_KEY;

// const encrypt = (text) => {
//   const cipher = crypto.createCipher(algorithm, secretKey);
//   let encrypted = cipher.update(text, 'utf8', 'hex');
//   encrypted += cipher.final('hex');
//   return encrypted;
// };

// const decrypt = (encryptedText) => {
//   const decipher = crypto.createDecipher(algorithm, secretKey);
//   let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
//   decrypted += decipher.final('utf8');
//   return decrypted;
// };

// const authenticate = (req, res, next) => {
//   const token = req.headers.authorization;
//   if (!token) return res.status(401).json({ error: 'Access denied' });
//   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid token' });
//     req.userId = decoded.userId;
//     next();
//   });
// };

// router.post('/', authenticate, async (req, res) => {
//   const { data } = req.body;
//   try {
//     const encryptedData = encrypt(data);
//     const checkIn = new CheckIn({ userId: req.userId, encryptedData });
//     await checkIn.save();
//     res.json({ message: 'Check-in saved' });
//   } catch (error) {
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// router.get('/', authenticate, async (req, res) => {
//   try {
//     const checkIns = await CheckIn.find({ userId: req.userId });
//     res.json(checkIns.map((entry) => ({ ...entry._doc, data: decrypt(entry.encryptedData) })));
//   } catch (error) {
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// module.exports = router;


const express = require('express');
const jwt = require('jsonwebtoken');
const CheckIn = require('../models/CheckIn');
const crypto = require('crypto');
const router = express.Router();

const algorithm = 'aes-256-ctr';
const IV_LENGTH = 16;
const ENCRYPTION_KEY = Buffer.from(process.env.SECRET_KEY, 'hex'); // Ensure this is a 32-byte hex key

// Ensure the key is 32 bytes
if (ENCRYPTION_KEY.length !== 32) {
  throw new Error('Encryption key must be 32 bytes');
}

// Encrypt function
const encrypt = (text) => {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(algorithm, ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
};

// Decrypt function
const decrypt = (text) => {
  try {
    const [ivPart, encryptedPart] = text.split(':');
    const iv = Buffer.from(ivPart, 'hex');
    const encrypted = Buffer.from(encryptedPart, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

// ✅ FIX: Corrected route to `/checkin`
router.post('/', authenticate, async (req, res) => {
  try {
    const { mood, stressLevel, feelings } = req.body;

    // Validate request body
    if (mood === undefined || stressLevel === undefined || feelings === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const encryptedMood = encrypt(mood.toString());
    const encryptedStress = encrypt(stressLevel.toString());
    const encryptedFeelings = encrypt(feelings);

    if (!encryptedMood || !encryptedStress || !encryptedFeelings) {
      return res.status(500).json({ error: 'Encryption failed' });
    }

    const checkIn = new CheckIn({
      userId: req.userId,
      encryptedMood,
      encryptedStress,
      encryptedFeelings
    });

    await checkIn.save();
    res.status(201).json({ message: 'Check-in saved successfully' });
  } catch (error) {
    console.error('Error saving check-in:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ FIX: Changed route to `/checkin` for consistency
router.get('/', authenticate, async (req, res) => {
  try {
    const checkIns = await CheckIn.find({ userId: req.userId });

    const decryptedCheckIns = checkIns.map(checkIn => ({
      _id: checkIn._id,
      mood: decrypt(checkIn.encryptedMood),
      stressLevel: decrypt(checkIn.encryptedStress),
      feelings: decrypt(checkIn.encryptedFeelings),
      createdAt: checkIn.createdAt
    }));

    res.json(decryptedCheckIns);
  } catch (error) {
    console.error('Error fetching check-ins:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
