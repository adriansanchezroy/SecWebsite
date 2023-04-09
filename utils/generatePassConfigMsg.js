/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * 
 * Cette classe génère le message de complexité de mot de passe requis
 * 
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */


// Helper function to generate the password settings message

/**
@description Génère un message de configuration de mot de passe à partir des paramètres de configuration de mot de passe
@param {Object} passwordSettings - Les paramètres de configuration de mot de passe
@returns {string} - Le message de configuration de mot de passe généré
*/
async function generatePassConfigMsg(passwordSettings) {
    let passwordSettingsMsg = 'The password must ';

    if (passwordSettings.requireCapital) {
        passwordSettingsMsg += 'have one capital letter, ';
    }
    if (passwordSettings.requireLowercase) {
        passwordSettingsMsg += 'have one lowercase letter, ';
    }
    if (passwordSettings.requireNumber) {
        passwordSettingsMsg += 'have one number, ';
    }
    if (passwordSettings.requireSpecial) {
        passwordSettingsMsg += 'have one special character, ';
    }
    const minLength = passwordSettings.minLength;
    const maxLength = passwordSettings.maxLength;
    
    passwordSettingsMsg += `be between ${minLength} and ${maxLength} characters long`;

    return passwordSettingsMsg;
}

module.exports = generatePassConfigMsg;