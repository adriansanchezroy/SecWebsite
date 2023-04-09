/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * 
 * Cette classe génère la complexité de mot de passe
 * 
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */


const PasswordSettings = require('../models/pwdSettingsModel');

/**
@description Applique les paramètres de configuration du mot de passe pour valider un mot de passe.
@param {string} password - Le mot de passe à valider.
@returns {boolean} - True si le mot de passe respecte les paramètres de configuration, false sinon.
*/
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