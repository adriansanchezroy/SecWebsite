const changePasswordForm = document.getElementById('change-password-form');

// async function fetchPasswordSettings() {
//   try {
//     const response = await fetch('/password-settings');
//     if (response.ok) {
//       return await response.json();
//     }
//   } catch (error) {
//     console.error('Error fetching password settings:', error);
//   }
//   return null;
// }

changePasswordForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  // const passwordSettings = await fetchPasswordSettings();
  // if (!passwordSettings) {
  //   alert('Failed to fetch password settings. Please try again later.');
  //   return;
  // }

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
