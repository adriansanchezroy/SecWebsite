const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Role = require('../models/roleModel');
const bcrypt = require('bcryptjs');
const router = express.Router();
const authenticateToken = require('../middleware/auth');
const hasRole = require('../utils/hasRole');

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
    user = await User.findOne({ username }).populate("roles");
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
    if(user.badConnexions >= 10){

      await User.updateOne({ username: req.body.username }, { $set: { blocked: true } });
      return res.status(401).json({ message: 'Too many attempts. Your account has been blocked.' });
    
    }else{

      return res.status(401).json({ message: 'Incorrect username or password.' });
    }
  }

  if (user.blocked) {
    return res.status(401).json({ message: 'Your account has been blocked. Please contact admin.' });
  }


  user.lastLoginDate = new Date();
  await user.save();

  const roles = user.roles;
  console.log(roles);

  const payload = {
    id: user._id,
    username: user.username,
    role: roles,
  };

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
  req.session.token = accessToken;
  res.json({ accessToken: accessToken });
});

// Get the users from the database and render the users page
router.get('/users', authenticateToken, async (req, res) => {
  let username = '';
  let role = '';
  token = req.session.token;
  try {
    // Decode the token using the secret
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    // Access the relevant payload data (username, role)
    username = decoded.username;
    role = decoded.role[0];

  } catch (err) {
    // Handle the error (invalid token, expired token, etc.)
    res.status(401).send('Invalid or expired token');
  }

  if (hasRole(role, 'admin')) { // Check if the user has the required admin role
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
router.post("/addUser", authenticateToken, async (req, res) => {
  const { username, password, role } = req.body;

  // Validate and create the user
  try {
    let hashedPassword = password;

    hashedPassword = await bcrypt.hash(hashedPassword, 10);

    const newUser = new User({
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


module.exports = router;