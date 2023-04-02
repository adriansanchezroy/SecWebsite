const mongoose = require('mongoose');

const passwordSettingsSchema = new mongoose.Schema({
  requireCapitalLetter: {
    type: Boolean,
    default: true,
  },
  requireLowercaseLetter: {
    type: Boolean,
    default: true,
  },
  requireNumber: {
    type: Boolean,
    default: true,
  },
  requireSpecialCharacter: {
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
  differentFromXLastPasswords: {
    type: Number,
    default: 3,
},
    expireAfterXDays: {
    type: Number,
    default: 90,
},
});

const PasswordSettings = mongoose.model('PasswordSettings', passwordSettingsSchema);

module.exports = PasswordSettings;
