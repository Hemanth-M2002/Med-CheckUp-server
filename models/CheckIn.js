const mongoose = require('mongoose');

const checkInSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, default: Date.now },
    encryptedData: { type: String, required: true },
  });
  module.exports = mongoose.model('CheckIn', checkInSchema);
  