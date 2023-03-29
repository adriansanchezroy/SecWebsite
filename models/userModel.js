const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    min: 6,
    max: 255,
  },
  password: {
    type: String,
    required: true,
    max: 2048,
    min: 6,
  },
  roles: [
    {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role"
    }
  ],
  blocked: {
    type: Boolean,
    default: false,
  },
  passModified: {
    type: Date,
  },
  lastLoginDate: {
    type: Date,
  },
  goodConnexions: {
    type: Number,
    default: 0,
  },
  badConnexions: {
    type: Number,
    default: 0,
  },
});

module.exports = mongoose.model("User", userSchema);