const changePasswordForm = document.getElementById('change-password-form');
changePasswordForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const formData = new FormData(changePasswordForm);
  const oldPassword = formData.get('oldpassword');
  const newPassword = formData.get('newpassword');
  const confirmPassword = formData.get('confirmpassword');

  if (newPassword === confirmPassword) {
    const data = {
      oldPassword: oldPassword,
      newPassword: newPassword,
      confirmPassword: confirmPassword,
    };

    try {
      const response = await fetch('/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (response.status === 200) {
        alert('Password changed successfully');
        window.location.href = '/login';
      } else {
        const error = await response.text();
        alert(error);
      }
    } catch (error) {
      console.error('Error during change password:', error);
      alert('An error occurred during change password');
    }
  } else {
    alert('New password and confirm password do not match');
  }
});
