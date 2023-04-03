// Helper function to generate the password settings message
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