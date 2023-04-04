const express = require("express");
const fs = require('fs');
const https = require('https');
const app = express();
<<<<<<< Updated upstream
=======
const PORT = 2000;
>>>>>>> Stashed changes
const AuthRoutes = require("./routes/authRoutes");
const dotenv = require("dotenv");
const ejs = require('ejs');
const cors = require("cors");
const mongoose = require("mongoose");

dotenv.config();

const options = {
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./certificate.pem')
};

var corsOptions = {
    origin: "http://localhost:3000"
  };

app.set('view engine', 'ejs'); // set up ejs for templating 
app.use(cors(corsOptions)); 
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use("/api/user", AuthRoutes);
app.use(express.static('public')); // for serving static files

// Connect to mongoDB
mongoose.connect(
    process.env.DB_CONNECTION, {
        useUnifiedTopology: true,
        useNewUrlParser: true
    },
    () => console.log("Connected to DB")
);

// Get the login page and render it
app.get('/login', (req, res) => {
    res.render('login');
  });

// Get the users from the database and render the users page
app.get('/users', checkRole('admin'), (req, res) => {
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

<<<<<<< Updated upstream
app.listen(PORT, () => console.log(`Running server on port: ${PORT}`));
=======
https.createServer(options, app).listen(PORT, () => {
  console.log(`Running server on https://localhost:${PORT}`);
});

//app.use('/', login);
//app.listen(PORT, () => console.log(`Running server on port: ${PORT}`));
>>>>>>> Stashed changes
