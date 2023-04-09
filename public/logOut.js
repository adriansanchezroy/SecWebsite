/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */

const logoutButton = document.getElementById('logout-form');

/**
@description Fonction qui gère la déconnexion d'un utilisateur en envoyant une requête POST au serveur.
@throws {Error} Une erreur est lancée si la déconnexion échoue.
@returns {void} 
*/
logoutButton.addEventListener('click', async () => {
  try {
    const response = await fetch('/logout', {
      method: 'POST'
    });

    if (response.status === 200) {
      document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      window.location.href = '/login';
    } else {
      alert('Logout failed');
    }
  } catch (error) {
    console.error('Error during logout:', error);
    alert('An error occurred during logout');
  }
});
