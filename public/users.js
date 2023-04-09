/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */

// Get the modal, open modal button, and close button
const addUserModal = document.getElementById("addUserModal");
const openAddUserModalBtn = document.getElementById("openAddUserModal");
const closeAddUserModalBtn = document.querySelector(".close");
const addUserForm = document.getElementById("addUserForm");

const addRoleButtons = document.querySelectorAll(".dropdown-item");
const blockUserButton = document.querySelectorAll(".dropdown-item-block");

// Open the modal when the open modal button is clicked
openAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "block";
};

// Close the modal when the close button is clicked
closeAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "none";
};
// Close the modal when clicking outside of the modal content
window.onclick = (event) => {
  if (event.target === addUserModal) {
    addUserModal.style.display = "none";
  }
};


/**
@description Cette fonction est appelée lorsqu'un formulaire d'ajout d'utilisateur est soumis. 
            Elle récupère les informations du formulaire et effectue une requête API pour créer un nouvel utilisateur. 
            Si la création est réussie, un message de confirmation est affiché et la liste des utilisateurs est rafraîchie.
@param {object} event - L'événement soumis lors de la soumission du formulaire
@returns {void} Retourne une promesse résolue une fois que l'utilisateur a été créé avec succés, ou rejettée avec une erreur si le processus a échoué.
*/
addUserForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const firstName = document.getElementById("firstName").value;
  const lastName = document.getElementById("lastName").value;
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const role = document.getElementById("role").value;

  if (password !== confirmPassword) {
    alert("Passwords do not match.");
    return;
  }
    // Perform the API request to create the user
    try {
        const response = await fetch("/addUser", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            firstName,
            lastName,
            username,
            password,
            role,
          }),
        });
    
        if (response.ok) {
          alert("User created successfully.");
          addUserModal.style.display = "none";
          // Refresh the users list
          window.location.reload();
        } else {
          const error = await response.text();
          alert(error);
        }
      } catch (error) {
        console.error("Error creating user:", error);
      }
    });




/**
@description Ajoute un rôle à un utilisateur lorsqu'un bouton est cliqué.
@param {Object} button - Le bouton cliqué qui déclenche la fonction.
@returns {void} - Retourne une promesse résolue une fois que le rôle a été ajouté avec succès, ou rejettée avec une erreur si le processus a échoué.
*/
addRoleButtons.forEach((button) => {
  button.addEventListener("click", async (event) => {
    event.preventDefault();
    const userId = event.target.dataset.userid;
    const role = event.target.dataset.role;
    try {
      const response = await fetch(`/addRole/${userId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role }),
      });
      if (response.ok) {
        alert(`Role ${role} added successfully.`);
        window.location.reload();
      } else {
        const error = await response.json();
        alert(error.message);
      }
    } catch (error) {
      console.error("Error adding role:", error);
    }
  });
});    

/**
@description Fonction qui gère le blocage/déblocage d'un utilisateur en cliquant sur le bouton correspondant
@param {Object} button - Le bouton cliqué qui déclenche la fonction.
@returns {void} - Retourne une promesse résolue une fois que l'utilisateur est bloqué ou débloqué, ou rejettée avec une erreur si le processus a échoué.
*/
blockUserButton.forEach((button) => {
  button.addEventListener("click", async (event) => {
    event.preventDefault();
    const userId = event.target.dataset.userid;
    try {
      const response = await fetch(`/blockUser/${userId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });
  
      if (response.ok) {
        alert("User blocked/unblocked successfully.");
        window.location.reload();
      } else {
        const error = await response.json();
        alert(error.message);
      }
    } catch (error) {
      console.error("Error blocking user:", error);
    }
  });
});   
