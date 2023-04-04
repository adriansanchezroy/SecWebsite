const mongoose = require('mongoose');

const passwordSettingsSchema = new mongoose.Schema({
  requireCapital: {
    type: Boolean,
    default: true,
  },
  requireLowercase: {
    type: Boolean,
    default: true,
  },
  requireNumber: {
    type: Boolean,
    default: true,
  },
  requireSpecial: {
    type: Boolean,
    default: true,
  },
  minLength: {
    type: Number,
    default: 8,
  },
  maxLength: {
    type: Number,
    default: 30,
  },
  differentFromXLastPwd: {
    type: Number,
    default: 3,
},
  expireAfterXMinutes: {
    type: Number,
    default: 90,
},
  maxAttempts: {
    type: Number,
    default: 3,
},
  lockoutTime: {
    type: Number,
    default: 3,
},
});

const PasswordSettings = mongoose.model('PasswordSettings', passwordSettingsSchema);

module.exports = PasswordSettings;
