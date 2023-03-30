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
    await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    await User.updateOne({ username: req.body.username }, { $inc: { badConnexions: 1 } });
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }
  await User.updateOne({ username: req.body.username }, { $inc: { goodConnexions: 1 } });

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
  try {
   
    const users = await User.find().populate("roles");
    res.render('users', { users});
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving users from the database.');
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