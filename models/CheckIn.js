// const mongoose = require('mongoose');

// const checkInSchema = new mongoose.Schema({
//   userId: String,
//   mood: Number,
//   stressLevel: Number,
//   feelings: String, // Encrypted feelings
//   createdAt: { type: Date, default: Date.now },
// });

//   module.exports = mongoose.model('CheckIn', checkInSchema);


const mongoose = require('mongoose');

const checkInSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  encryptedMood: String,
  encryptedStress: String,
  encryptedFeelings: String,
}, { timestamps: true });

module.exports = mongoose.model('CheckIn', checkInSchema);