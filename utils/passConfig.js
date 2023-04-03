const PasswordSettings = require('../models/pwdSettingsModel');

// Helper function to apply the password settings
async function applyPasswordSettings(password) {
    // Retrieve the password settings from the database
    const passwordSettings = await PasswordSettings.findOne();
  
    let regexString = '^';
  
    if (passwordSettings.requireCapital) {
      regexString += '(?=.*[A-Z])';
    }
    if (passwordSettings.requireLowercase) {
      regexString += '(?=.*[a-z])';
    }
    if (passwordSettings.requireNumber) {
      regexString += '(?=.*\\d)';
    }
    if (passwordSettings.requireSpecial) {
      regexString += '(?=.*[@$!%?&])';
    }
  
    regexString += `[A-Za-z\\d@$!%?&]{${passwordSettings.minLength},${passwordSettings.maxLength}}$`;
  
    return new RegExp(regexString).test(password);
  }

module.exports = applyPasswordSettings;