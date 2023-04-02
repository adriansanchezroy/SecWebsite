const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Role = require('../models/roleModel');
const bcrypt = require('bcryptjs');
const router = express.Router();
const authenticateToken = require('../middleware/auth');
const hasRole = require('../utils/hasRole');
const decodeToken = require('../utils/decodeToken');

// Get the login page and render it
router.get('/login', (req, res) => {
    res.render('login');
  });

// Get the dashboard page and render it
router.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

// Post the login form and authenticate the user
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let user;
  try {
    user = await User.findOne({ username });
  } catch (error) {
    console.error('Error fetching user:', error);
    return res.status(500).json({ message: 'An error occurred during authentication.' });
  }
  if (!user) {
    await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  if(user.badConnexions >= 3){
    await User.updateOne({ username: req.body.username }, { $set: { blocked: true } });
    return res.status(403).json({ message: 'Too many attempts. Your account has been blocked.' });
  }

  if (user.blocked) {
    return res.status(403).json({ message: 'Your account has been blocked. Please contact admin.' });
  }

  user.lastLoginDate = new Date();
  await user.save();

  const roles = user.roles;

  const payload = {
    id: user._id,
    username: user.username,
    roles: roles,
  };

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
  req.session.token = accessToken;
  res.json({ accessToken: accessToken });
});

// Get the users from the database and render the users page
router.get('/users', authenticateToken, async (req, res) => {
  token = req.session.token;

  try {
    var decoded = decodeToken(token);
  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }
  
  var roles = decoded.roles[0];

  if (hasRole(roles, 'admin')) {
    try {
      const users = await User.find();
      res.render('users', { users});
      
    } catch (err) {
      console.error(err);
      res.status(500).send('Error retrieving users from the database.');
    }
  }
  else{
    res.status(403).send('Access denied. You do not have the required role.');
  }
});

// Get the users from the database and render the users page
router.get('/clients/business', authenticateToken, async (req, res) => {
  token = req.session.token;

  try {
    var decoded = decodeToken(token);
  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }
  
  var roles = decoded.roles[0]; // TODO: make it work with multiple roles

  if (hasRole(roles, 'business' || 'admin')) {
    try {
      const users = await User.find();
      res.render('usersA', { users});
      
    } catch (err) {
      console.error(err);
      res.status(500).send('Error retrieving users from the database.');
    }
  }
  else{
    res.status(403).send('Access denied. You do not have the required role.');
  }
});

// Get the users from the database and render the users page
router.get('/clients/residential', authenticateToken, async (req, res) => {
  token = req.session.token;

  try {
    var decoded = decodeToken(token);
  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }
  
  var roles = decoded.roles[0];

  if (hasRole(roles, 'residential' || 'admin')) {
    try {
      const users = await User.find();
      res.render('usersR', { users});
      
    } catch (err) {
      console.error(err);
      res.status(500).send('Error retrieving users from the database.');
    }
  }
  else{
    res.status(403).send('Access denied. You do not have the required role.');
  }
});

// Get the users from the database and render the users page
router.get('/admin', authenticateToken, async (req, res) => {
  token = req.session.token;

  try {
    var decoded = decodeToken(token);
  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }
  
  var roles = decoded.roles[0];

  if (hasRole(roles, 'admin')) {
    try {
      const users = await User.find();
      res.render('admin', { users});
      
    } catch (err) {
      console.error(err);
      res.status(500).send('Error retrieving users from the database.');
    }
  }
  else{
    res.status(403).send('Access denied. You do not have the required role.');
  }
});

// Add a new user to the database
router.post("/addUser", authenticateToken, async (req, res) => {
  const { firstName, lastName, username, password, role } = req.body;

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
    });

    await newUser.save();
    res.status(200).json({ message: "User created successfully." });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "An error occurred while creating the user." });
  }
});

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









module.exports = router;