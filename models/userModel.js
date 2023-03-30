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
      type: String,
      enum: ["admin", "residential", "business"],
    },
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
  firstName: {
    type: String,
    min: 2,
    max: 255,
  },
  lastName: {
    type: String,
    min: 2,
    max: 255,
  },
});

module.exports = mongoose.model("User", userSchema);