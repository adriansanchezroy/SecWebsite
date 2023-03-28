const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Role = require('../models/roleModel');
const bcrypt = require('bcryptjs');
const router = express.Router();
const authenticateToken = require('../middleware/auth');

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
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const roleName = user.roles[0].name;

  const payload = {
    id: user._id,
    username: user.username,
    role: roleName,
  };

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
  req.session.token = accessToken;
  res.json({ accessToken: accessToken });
});

// Get the users from the database and render the users page
router.get('/users', authenticateToken, async (req, res) => {
  try {
   
    const users = await User.find().populate("roles");
    res.render('users', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
  }
});

module.exports = router;