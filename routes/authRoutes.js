/**
 * Cette classe fait partie du projet GTI619 - Équipe B.
 * 
 * Cette classe gère toutes les pages du projet.
 * 
 * Copyright (c) 2023 Duong Kevin, Adrian Sanchez Roy, Ines Abdelkefi, Corentin Seguin.
 * Tous droits réservés.
 */


const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Role = require('../models/roleModel');
const bcrypt = require('bcryptjs');
const router = express.Router();
const authenticateToken = require('../middleware/auth');
const hasRole = require('../utils/hasRole');
const applyPasswordSettings = require('../utils/passConfig');
const generatePassConfigMsg = require('../utils/generatePassConfigMsg');
const PasswordSettings = require('../models/pwdSettingsModel');


/**
@description Affiche la page de connexion.
@param {object} req - Objet de requête HTTP.
@param {object} res - Objet de réponse HTTP.
@returns {void}
*/
router.get('/login', (req, res) => {
    res.render('login');
  });

/**
@description Affiche le tableau de bord de l'utilisateur connecté.
@param {object} req - Objet de requête HTTP.
@param {object} res - Objet de réponse HTTP.
@returns {void}
*/
router.get('/dashboard',authenticateToken, (req, res) => {
  res.render('dashboard');
});

/**
@description Affiche la page de modification de mot de passe forcé.
@param {object} req - Objet de requête HTTP.
@param {object} res - Objet de réponse HTTP.
@returns {void}
*/
router.get('/force-modify-password', (req, res) => {
  res.render('forceModifyPass');
});

// Post the login form and authenticate the user
/**
@description Cette fonction gère la requête POST pour la page Login.
@param {Object} req - L'objet représentant la requête HTTP.
@param {Object} res - L'objet représentant la réponse HTTP.
@returns {Object} L'objet représentant la réponse HTTP avec un éventuel message d'erreur.
@throws {Error} Affiche un message d'erreur si les paramètres de sécurité ne sont pas respectés (bon identifiant, bon mot de passe, compte non bloqué, etc).
*/
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let user;
  let passwordSettings;
  try {
    user = await User.findOne({ username });
  } catch (error) {
    console.error('Error fetching user:', error);
    return res.status(500).json({ message: 'An error occurred during authentication.' });
  }
  if (!user) {
    await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
    return res.status(401).json({ message: 'Incorrect username or password.', lockoutTime: passwordSettings.lockoutTime  });
  }
  try {
    passwordSettings = await PasswordSettings.findOne();
  } catch (error) {
    console.error('Error fetching password settings:', error);
    return res.status(500).json({ message: 'An error occurred during authentication.' });
  }


  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    if(user.badConnexions >= passwordSettings.maxAttempts){

      await User.updateOne({ username: req.body.username }, { $set: { blocked: true } });
      return res.status(401).json({ message: 'Too many attempts. Your account has been blocked.' });
    
    }else{
      await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
      return res.status(401).json({ message: 'Incorrect username or password.', lockoutTime: passwordSettings.lockoutTime  });
    }
  }

  if (user.blocked) {
    return res.status(401).json({ message: 'Your account has been blocked. Please contact admin.' });
  }


  user.lastLoginDate = new Date();
  await user.save();

  const roles = user.roles;

  const payload = {
    id: user._id,
    username: user.username,
    roles: roles,
  };

  const date = new Date().getTime();
  const lastPassModifyDate = new Date(user.passModified).getTime();
  const expireDate = lastPassModifyDate + (passwordSettings.expireAfterXMinutes * 60 * 1000); // Expire date in milliseconds

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
  req.session.token = accessToken;
  await User.updateOne({ username: req.body.username }, { $set: { badConnexions: 0 } }); // Reset bad connexions counter

  if(date >= expireDate){
    return res.status(203).json({ message: 'You need to modify your password', accessToken: accessToken });
  }
  
  res.json({ accessToken: accessToken });
});

// Get the users from the database and render the users page
/**
@description Affiche la page Utilisateurs en vérifiant bien à l'aide du token d'authentification que l'utilisateur actuel a le bon rôle.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@return {void} - Donne les accès.
@throws {error} - Affiche un message d'erreur si l'utilisateur n'est pas dans la base de données.
@throws {error} - Affiche un message d'erreur si l'utilisateur n'a pas le bon rôle.
@throws {error} - Affiche un message d'erreur si le token a expiré ou est invalide.
*/
router.get('/users', authenticateToken, async (req, res) => {
  var username;
  var roles;
  token = req.session.token;
  try {
    // Decode the token using the secret
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    // Access the relevant payload data (username, role)
    username = decoded.username;
    roles = decoded.roles[0];

  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }

  if (hasRole(roles, 'admin')) { // Check if the user has the required admin role
  try {
    const users = await User.find();
    res.render('users', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
  }}
  else{
    res.status(403).send('Access denied. You do not have the required role.');
  }
});

// Add a new user to the database
/**
@description Ajoute un nouvel utilisateur avec les informations fournies dans le corps de la requête.
@param {Object} req - L'objet requête http contenant les informations de l'utilisateur à ajouter.
@param {Object} res - L'objet réponse http.
@returns {void} - Affiche un message confirmant la création de l'utilisateur.
@returns {void} - Si la validation de mot de passe échoue, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si une erreur s'est produite lors de la création d'un utilisateur.
*/
router.post("/addUser", authenticateToken, async (req, res) => {
  const { firstName, lastName, username, password, role } = req.body;
  const passwordSettings = await PasswordSettings.findOne();
  const isPasswordValid = await applyPasswordSettings(password);

  if (!isPasswordValid) {
    const passConfigErrMsg = await generatePassConfigMsg(passwordSettings);
    return res.status(400).json({ error: passConfigErrMsg });
  }

  // Validate and create the user
  try {
    let hashedPassword = password;

    hashedPassword = await bcrypt.hash(hashedPassword, 10);

    const newUser = new User({
      firstName,
      lastName,
      username,
      password: hashedPassword,
      roles: role,
      passModified: Date.now(),
    });

    await newUser.save();
    res.status(200).json({ message: "User created successfully." });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "An error occurred while creating the user." });
  }
});

/**
@description Ajoute un rôle à l'utilisateur spécifié.
@param {string} userId - L'ID de l'utilisateur auquel ajouter le rôle.
@param {string} role - Le nouveau rôle à ajouter.
@returns {void} - Affiche un message confirmant que le rôle a été ajouté avec succès.
@returns {void} - Si l'utilisateur n'est pas retrouvé dans la database, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si une erreur s'est produite lors de l'ajout du rôle.
*/
router.post("/addRole/:userId", async (req, res) => {
  const userId = req.params.userId;
  const role = req.body.role;

  try {
    // Fetch the user from the database
    const user = await User.findById(userId);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    // Add the new role to the user's roles array, if it doesn't already exist
    if (!user.roles.includes(role)) {
      user.roles.push(role);
    }

    // Save the updated user
    await user.save();
    res.status(200).json({ message: "Role added successfully." });
  } catch (error) {
    console.error("Error adding role:", error);
    res.status(500).json({ message: "An error occurred while adding the role." });
  }
});

/**
@description Bloque ou débloque un utilisateur spécifique.
@param {string} userId - L'ID de l'utilisateur auquel ajouter le rôle.
@returns {void} - Affiche un message confirmant que l'utiliateur a été bloqué ou débloqué avec succès.
@returns {void} - Si l'utilisateur n'est pas retrouvé dans la database, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si une erreur s'est produite lors du blocage/déblocage de l'utilisateur.
*/
router.post("/blockUser/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    // Fetch the user from the database
    const user = await User.findById(userId);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    if(user.blocked){
      user.blocked = false;
    }else{
      user.blocked = true;
    }

    // Save the updated user
    await user.save();
    res.status(200).json({ message: "User blocked/unblocked successfully." });
  } catch (error) {
    console.error("Error blocking user:", error);
    res.status(500).json({ message: "An error occurred while blocking the user." });
  }
});

// Get the users from the database and render the users page
/**
@description Affiche la page Clients Affaires en vérifiant bien à l'aide du token d'authentification que l'utilisateur actuel a le bon rôle.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@return {void} - Donne les accès.
@returns {void} - Si l'utilisateur n'a pas le bon rôle, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si l'utilisateur n'est pas dans la base de données.
*/
router.get('/business', authenticateToken, async (req, res) => {
  try {
   //Permet le blocage si le role n est pas admin ou business
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    if (decoded.roles[0] == 'residential') {
      return res.status(403).send('Access denied');
    }

    const users = await User.find();
    res.render('usersA', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
  }
});

// Get the users from the database and render the users page
/**
@description Affiche la page Clients Résidentiels en vérifiant bien à l'aide du token d'authentification que l'utilisateur actuel a le bon rôle.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@return {void} - Donne les accès.
@returns {void} - Si l'utilisateur n'a pas le bon rôle, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si l'utilisateur n'est pas dans la base de données.
*/
router.get('/residential', authenticateToken, async (req, res) => {
  try {
  //Permet le blocage si le role n est pas admin ou residentiel
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    if (decoded.roles[0] == 'business') {
      return res.status(403).send('Access denied');
    }

    const users = await User.find();
    res.render('usersR', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
  }
});

// Get the users from the database and render the users page
/**
@description Affiche la page Administration en vérifiant bien à l'aide du token d'authentification que l'utilisateur actuel a le bon rôle.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@return {void} - Donne les accès.
@returns {void} - Si l'utilisateur n'a pas le bon rôle, un message d'erreur est envoyé.
@throws {error} - Affiche un message d'erreur si l'utilisateur n'est pas dans la base de données.
*/
router.get('/admin', authenticateToken, async (req, res) => {
  try {
   //Permet le blocage si le role n est pas admin
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    if (decoded.roles[0] != 'admin') {
      return res.status(403).send('Access denied');
    }

    const users = await User.find();
    res.render('admin', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
  }
});

/**
@description Récupère les paramètres de mot de passe actuels de l'application
@param {Object} req - L'objet requête express
@param {Object} res - L'objet réponse express
@returns {Object} - Les paramètres de mot de passe actuels
@throws {error} - Affiche un message d'erreur s'il y a un problème lors de la récupération des paramètres.
*/
router.get('/get-password-settings', async (req, res) => {
  try {
    const passwordSettings = await PasswordSettings.findOne();
    if (passwordSettings) {
      res.json(passwordSettings);
    } else {
      res.status(404).json({ error: 'Password settings not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while fetching the password settings' });
  }
});

// Routes for updating password settings
/**
@description Cette fonction gère la requête POST pour mettre à jour les paramètres de modification du mot de passe.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@returns {Object} - La réponse HTTP contenant le résultat de l'opération ou une erreur.
@returns {void} - Si la validation de mot de passe échoue, un message d'erreur est envoyé.
@throws {Error} - Affiche un message d'erreur si le jeton est invalide ou expiré
*/
router.post('/update-password-settings', async (req, res) => {
  var username;
  const { requireCapital, requireLowercase, requireNumber,
    requireSpecial, minLength, maxLength, adminPassword } = req.body;

  try {
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);
    username = decoded.username;
    var user = await User.findOne({ username });
    const passwordMatch = await bcrypt.compare(adminPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password.' });
    }
  } catch (error) {
    console.error('Error with token:', error);
    res.status(401).send('Invalid or expired token');
    return;
  }

  try {
    // Check if password settings already exist
    let passwordSettings = await PasswordSettings.findOne();

    if (passwordSettings) {
      // Update existing password settings
      passwordSettings.requireCapital = requireCapital;
      passwordSettings.requireLowercase = requireLowercase;
      passwordSettings.requireNumber = requireNumber;
      passwordSettings.requireSpecial = requireSpecial;
      passwordSettings.minLength = minLength;
      passwordSettings.maxLength = maxLength;
    } else {
      // Create new password settings if none exist
      passwordSettings = new PasswordSettings({
        requireCapital,
        requireLowercase,
        requireNumber,
        requireSpecial,
        minLength,
        maxLength,
      });
    }

    // Save the updated password settings
    await passwordSettings.save();

    res.status(200).json({ message: 'Password settings saved successfully.' });
  } catch (error) {
    console.error('Error saving password settings:', error);
    res.status(500).json({ message: 'An error occurred while saving the password settings.' });
  }
});

/**
@description Cette fonction gère la requête POST pour mettre à jour les paramètres de modification du mot de passe.
@param {Object} req - L'objet requête http.
@param {Object} res - L'objet réponse http.
@returns {Void} - Renvoie un objet JSON contenant un message de confirmation ou une erreur.
@throws {Error} - Affiche un message d'erreur si la validation du mot de passe administrateur a échoué.
*/
router.post('/update-password-modification-settings', async (req, res) => {
  var username;
  const { differentFromXLastPwd, expireAfterXMinutes, adminPassword } = req.body;

  try {
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);
    username = decoded.username;
    var user = await User.findOne({ username });
    const passwordMatch = await bcrypt.compare(adminPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password.' });
    }
  } catch (error) {
    console.error('Error with token:', error);
    res.status(401).send('Invalid or expired token');
    return;
  }

  try {
    // Check if password settings already exist
    let passwordSettings = await PasswordSettings.findOne();

    if (passwordSettings) {
      // Update existing password settings
      passwordSettings.differentFromXLastPwd = differentFromXLastPwd;
      passwordSettings.expireAfterXMinutes = expireAfterXMinutes;

    } 
    // Save the updated password settings
    await passwordSettings.save();

    res.status(200).json({ message: 'Password modification settings saved successfully.' });
  } catch (error) {
    console.error('Error saving password modification settings:', error);
    res.status(500).json({ message: 'An error occurred while saving the password modification settings.' });
  }
});

/**
@description Cette fonction gère la requête POST pour mettre à jour la configuration de connexion.
@param {Object} req - L'objet représentant la requête HTTP.
@param {Object} res - L'objet représentant la réponse HTTP.
@returns {Object} L'objet représentant la réponse HTTP avec un éventuel message d'erreur.
@throws {Error} Affiche un message d'erreur si le token est invalide ou a expiré.
*/
router.post('/update-connexion-config', async (req, res) => {
  var username;
  const { maxAttempts, timeBetweenAttempts, adminPassword } = req.body;

  try {
    const token = req.session.token;
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);
    username = decoded.username;
    var user = await User.findOne({ username });
    const passwordMatch = await bcrypt.compare(adminPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password.' });
    }
  } catch (error) {
    console.error('Error with token:', error);
    res.status(401).send('Invalid or expired token');
    return;
  }

  try {
    // Check if password settings already exist
    let passwordSettings = await PasswordSettings.findOne();

    if (passwordSettings) {
      // Update existing password settings
      passwordSettings.maxAttempts = maxAttempts;
      passwordSettings.lockoutTime = timeBetweenAttempts;

    } 
    // Save the updated password settings
    await passwordSettings.save();

    res.status(200).json({ message: 'Connexion configuration saved successfully.' });
  } catch (error) {
    console.error('Error saving connexion configuration:', error);
    res.status(500).json({ message: 'An error occurred while saving the connexion configuration.' });
  }
});


// Change the password route
/**
@description Cette fonction gère la requête POST pour mettre à jour le mot de passe.
@param {Object} req - L'objet représentant la requête HTTP.
@param {Object} res - L'objet représentant la réponse HTTP.
@returns {Object} L'objet représentant la réponse HTTP avec un éventuel message d'erreur.
@throws {Error} Affiche un message d'erreur si le mot de passe ne correspond ou s'il ne repond pas aux paramètres en place.
*/
router.post('/change-password', async (req, res) => {
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;
  const confirmNewPassword = req.body.confirmPassword;
  const passwordSettings = await PasswordSettings.findOne();

  const token = req.session.token;
  const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);
  const username = decoded.username;

  let user = await User.findOne({username});

  const passwordMatch = await bcrypt.compare(oldPassword, user.password);
  const isPasswordValid = await applyPasswordSettings(newPassword);

  if (!passwordMatch) {
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  if (!isPasswordValid) {
    const passConfigErrMsg = await generatePassConfigMsg(passwordSettings);
    return res.status(400).json({ error: passConfigErrMsg });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ error: 'Les nouveaux mots de passe ne correspondent pas.' });
  }

  // Check if the new password is different from the last X passwords
  const pastPasswords = user.pastPasswords.slice(-passwordSettings.differentFromXLastPwd);
  const isNewPasswordDifferent = await Promise.all(pastPasswords.map(async (pastPassword) => {
    return !(await bcrypt.compare(newPassword, pastPassword));
  })).then((results) => results.every((result) => result));

  if (!isNewPasswordDifferent) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit être différent des ' + passwordSettings.differentFromXLastPwd + ' derniers mots de passe.' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  console.log(hashedPassword);
  user.password = hashedPassword;
  user.pastPasswords.push(hashedPassword);
  user.passModified = Date.now();
  
  await user.save();
  res.status(200).json({ message: 'Password modified successfully.' });
});

// Log out avec clear des cookies + redirect vers la page de login
/**
@description Cette fonction gère la requête POST pour renvoyer sur la page Login après une déconnexion.
@param {Object} req - L'objet représentant la requête HTTP.
@param {Object} res - L'objet représentant la réponse HTTP.
@throws {Error} Affiche un message d'erreur si un problème survient lors de la déconnexion.
*/
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error logging out:', err);
      res.status(500).send('Error logging out');
    } else {
      res.clearCookie('connect.sid');
      res.redirect('/login');
    }
  });
});

module.exports = router;