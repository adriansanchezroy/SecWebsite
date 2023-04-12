/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */

const loginForm = document.getElementById('login');
const submitButton = loginForm.querySelector('button[type="submit"]');

/**
@description Fonction pour soumettre les informations de connexion et effectuer une requête POST pour l'authentification.
@param {Event} event - L'événement de soumission du formulaire de connexion.
@returns {void}
*/
loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    // Disable the submit button to prevent repeated login attempts
    submitButton.disabled = true;

    const formData = new FormData(loginForm);
    const username = formData.get('username');
    const password = formData.get('password');

    const data = {
      username: username,
      password: password,
    };

    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (response.status === 200) {
        submitButton.disabled = false;
        window.location.href = '/dashboard';
      } 
      else if (response.status === 203) {
        alert('You need to modify your password');
        window.location.href = '/force-modify-password';
      }
      else {
        alert('Incorrect username or password');
        const jsonResponse = await response.json();
        console.log(jsonResponse);

        submitMessage.innerText = 'Please wait ' + jsonResponse.lockoutTime + ' seconds before trying again.';
        submitMessage.style.display = 'block';

        setTimeout(() => {
          submitButton.disabled = false;
          submitMessage.innerText = '';
          submitMessage.style.display = 'none';
        }, jsonResponse.lockoutTime);
      }
    } catch (error) {
      console.error('Error during login:', error);
      alert('An error occurred during login');
      // Re-enable the submit button if there's an error
      submitButton.disabled = false;
    }
  });