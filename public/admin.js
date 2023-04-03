const passwordSettingsForm = document.getElementById('password-settings-form');
const configCompTab = document.getElementById('configCompTab');

configCompTab.addEventListener('click', async () => {
  try {
    const response = await fetch('/get-password-settings', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 200) {
      const passwordSettings = await response.json();
      // Set the values for your checkboxes
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
    console.log(requireCapital);
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
  