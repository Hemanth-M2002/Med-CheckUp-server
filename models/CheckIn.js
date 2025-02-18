const mongoose = require("mongoose");

const checkInSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
    username : {
      type : String,
      required : true,
    },
    encryptedMood: String,
    encryptedStress: String,
    encryptedFeelings: String,
    mood : String,
    stressLevel: String,
    feelings: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("CheckIn", checkInSchema);
