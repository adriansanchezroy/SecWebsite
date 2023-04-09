/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * 
 * Cette classe vérifie si un utilisateur a le rôle requis
 * 
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */


/**
@description Vérifie si le rôle de l'utilisateur correspond au rôle requis.
@param {string} role - Le rôle de l'utilisateur.
@param {string} requiredRole - Le rôle requis.
@returns {boolean} - true si le rôle de l'utilisateur correspond au rôle requis, sinon false.
*/
const hasRole = (role, requiredRole) => {

    return role === requiredRole;
  };
  
module.exports = hasRole;