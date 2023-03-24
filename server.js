const express = require("express");
const app = express();
const PORT = 5000;
const AuthRoutes = require("./routes/authRoutes");
const dotenv = require("dotenv");
const ejs = require('ejs');
const cors = require("cors");
const mongoose = require("mongoose");
const passport = require('passport');
const User = require('./models/userModel');
const initializePassport = require('./passport-config');
const login = require('./routes/authRoutes');

dotenv.config();

var corsOptions = {
    origin: "http://localhost:5000"
  };

app.set('view engine', 'ejs'); // set up ejs for templating 
app.use(cors(corsOptions)); 
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use("/api/user", AuthRoutes);
app.use(express.static('public')); // for serving static files

// Connect to mongoDB
mongoose.connect(
    process.env.DB_CONNECTION_URI,
    () => console.log("Connected to DB")
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(passport.initialize());
initializePassport(passport);

app.use('/', login);
app.listen(PORT, () => console.log(`Running server on port: ${PORT}`));