document.getElementById('password-settings-form').addEventListener('submit', async (event) => {
    event.preventDefault();
  
    const form = event.target;
    const formData = new FormData(form);
  
    const requireCapital = formData.get('requireCapital') === 'on';
    const requireNonCapital = formData.get('requireNonCapital') === 'on';
    const requireNumber = formData.get('requireNumber') === 'on';
    const requireSpecialChar = formData.get('requireSpecialChar') === 'on';
    const minLength = formData.get('minLength');
    const maxLength = formData.get('maxLength');
    const adminPassword = formData.get('adminPassword');
  
    const data = {
      requireCapital,
      requireNonCapital,
      requireNumber,
      requireSpecialChar,
      minLength,
      maxLength,
      adminPassword,
    };
  
    try {
      const response = await fetch('/admin/password-settings', {
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
  