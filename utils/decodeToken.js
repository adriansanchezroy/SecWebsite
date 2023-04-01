const jwt = require('jsonwebtoken');

const decodeToken = (token) => {
    // Decode the token using the secret
    const decoded = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET);

    return decoded;
  };
  
  module.exports = decodeToken;