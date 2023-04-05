const express = require("express");
const https = require("https");   //Added https
const fs = require("fs"); //Added https
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
const session = require('express-session');
const MongoStore = require('connect-mongo');

dotenv.config();

var corsOptions = {
    origin: "http://localhost:5000"
  };

app.set('view engine', 'ejs'); // set up ejs for templating 
app.use(cors(corsOptions)); 
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(express.static(__dirname + '/public')); // for serving static files

// Connect to mongoDB
mongoose.connect(
    process.env.DB_CONNECTION_URI,
    () => console.log("Connected to DB")
);

app.use(passport.initialize());
initializePassport(passport);

// Stores session in MongoDB
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.DB_CONNECTION_URI })
}));

 //Added https
const options = {
  key: fs.readFileSync("./cert/CA/localhost/localhost.decrypted.key"),
  cert: fs.readFileSync("./cert/CA/localhost/localhost.crt"),
};

app.use('/', login);

 //Added https
// https
//   .createServer(options, app)
//   .listen(PORT, () => console.log(`Running server on port: ${PORT}`));


app.listen(PORT, () => console.log(`Running server on port: ${PORT}`));