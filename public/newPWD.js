/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */

const changePasswordForm = document.getElementById('change-password-form');

/**
 * Gestionnaire d'événements pour le formulaire de changement de mot de passe.
 * @param {Event} event - L'événement déclenché par la soumission du formulaire.
 */
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

      if (response.ok) {
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
