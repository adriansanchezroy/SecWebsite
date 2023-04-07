const passwordSettingsForm = document.getElementById('password-settings-form');
const configComplexityTab = document.getElementById('configCompTab');
const passwordSettingsFormModif = document.getElementById('password-settings-form-modifyPass');
const configConnexionModif = document.getElementById('connexion-config-form');

/**
@description Fonction qui gère la soumission du formulaire de modification de la configuration de connexion
@param {Object} event - Événement de soumission de formulaire
@returns {Promise<void>} - Une promesse qui ne renvoie aucune valeur
*/
configConnexionModif.addEventListener('submit', async (event) => {
  event.preventDefault();
  
  const form = event.target;
  const formData = new FormData(form);

  const maxAttempts = formData.get('maxAttempts');
  const timeBetweenAttempts = formData.get('timeBetweenAttempts');
  const adminPassword = formData.get('adminPassConnexionModif');
  console.log("Admin password: " + adminPassword);

  const data = {
    maxAttempts,
    timeBetweenAttempts,
    adminPassword,
  };

  try {
    const response = await fetch('/update-connexion-config', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (response.status === 200) {
      alert('Connexion configuration updated successfully');
    } else {
      const error = await response.text();
      alert(error);
    }
  } catch (error) {
    console.error('Error during connexion configuration update:', error);
    alert('An error occurred during connexion configuration update');
  }
});

/**
@description Fonction qui permet de configurer les options de complexité du mot de passe
@param {Event} event - L'événement qui déclenche la fonction (clic sur un élément du DOM)
@returns {void} - Une promesse qui ne renvoie aucune valeur
*/
configComplexityTab.addEventListener('click', async () => {
  try {
    const response = await fetch('/get-password-settings', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 200) {
      const passwordSettings = await response.json();
      // Set the values for the checkboxes
      document.getElementById('requireCapital').checked = passwordSettings.requireCapital;
      document.getElementById('requireLowercase').checked = passwordSettings.requireLowercase;
      document.getElementById('requireNumber').checked = passwordSettings.requireNumber;
      document.getElementById('requireSpecial').checked = passwordSettings.requireSpecial;

    } else {
      const error = await response.text();
      console.error('Error fetching password settings:', error);
    }
  } catch (error) {
    console.error('Error fetching password settings:', error);
  }
});

/**
@description Cette méthode gère la soumission du formulaire de paramètres de mot de passe.
@param {event} event - L'événement de soumission du formulaire.
@returns {void}
@throws {Error} Lance une erreur si une erreur survient lors de la mise à jour des paramètres de mot de passe.
*/
passwordSettingsForm.addEventListener('submit', async (event) => {
    event.preventDefault();
  
    const form = event.target;
    const formData = new FormData(form);
  
    var requireCapital = formData.get('requireCapital') === "on";
    var requireLowercase = formData.get('requireLowercase') === "on";
    var requireNumber = formData.get('requireNumber') === "on";
    var requireSpecial = formData.get('requireSpecial') === "on";
    const minLength = parseInt(formData.get('minLength'));
    const maxLength = parseInt(formData.get('maxLength'));
    const adminPassword = formData.get('adminPassword');
  
    const data = {
      requireCapital,
      requireLowercase,
      requireNumber,
      requireSpecial,
      minLength,
      maxLength,
      adminPassword,
    };
  
    try {
      const response = await fetch('/update-password-settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
  
      if (response.status === 200) {
        alert('Password settings updated successfully');
      } else {
        const error = await response.text();
        alert(error);
      }
    } catch (error) {
      console.error('Error during password settings update:', error);
      alert('An error occurred during password settings update');
    }
  });

/**
@description Gère la soumission du formulaire de modification des paramètres de mot de passe. Récupère les données du formulaire, envoie une requête POST au serveur avec les données et gère la réponse.
@param {Event} event - L'événement de soumission du formulaire
@returns {void} 
@throws {Error} Lance une erreur si une erreur survient lors de la mise à jour des paramètres de mot de passe.
*/
  passwordSettingsFormModif.addEventListener('submit', async (event) => {
    event.preventDefault();
  
    const form = event.target;
    const formData = new FormData(form);
  
    var differentFromXLastPwd = formData.get('differentFromXLastPwd');
    var expireAfterXMinutes = formData.get('expireAfterXMinutes');
    const adminPassword = formData.get('adminPasswordForModif');
  
    const data = {
      differentFromXLastPwd,
      expireAfterXMinutes,
      adminPassword,
    };
  
    try {
      const response = await fetch('/update-password-modification-settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
  
      if (response.status === 200) {
        alert('Password modification settings updated successfully');
      } else {
        const error = await response.text();
        alert(error);
      }
    } catch (error) {
      console.error('Error during password settings update:', error);
      alert('An error occurred during password settings update');
    }
  });
  
  