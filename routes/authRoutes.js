const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const router = express.Router();

// Get the login page and render it
router.get('/login', (req, res) => {
    res.render('login');
  });

// Get the users from the database and render the users page
router.get('/users', checkRole('admin'), (req, res) => {
  db.collection('users').find().toArray((err, users) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error retrieving users from the database.');
      return;
    }
    res.render('users', { users, admin: req.user.role === 'admin' });
  });
});  

// Verifies that the checkedRole is the same as the user's role
function checkRole(checkedRole) {
    return (req, res, next) => {
        if (req.user.role === checkedRole) {
            next();
        } else {
            res.status(401).send('You are not authorized to view this page.');
        }
    };
}

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
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const payload = {
    id: user._id,
    username: user.username,
  };

  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.header("auth-token", token).send(token);
  res.status(200).json({
    message: 'Login successful',
    token: `Bearer ${token}`,
  });
});

module.exports = router;