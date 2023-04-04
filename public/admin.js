const passwordSettingsForm = document.getElementById('password-settings-form');
const configComplexityTab = document.getElementById('configCompTab');
const passwordSettingsFormModif = document.getElementById('password-settings-form-modifyPass');
const configConnexionModif = document.getElementById('connexion-config-form');

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
  
  