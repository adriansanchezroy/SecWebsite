const jwt = require("jsonwebtoken");

/**
@description Fonction pour authentifier le token d'accès
@param {object} req - L'objet requête HTTP contenant les informations de la requête
@param {object} res - L'objet réponse HTTP qui sera renvoyé au client
@param {function} next - Fonction middleware qui permet de passer à la requête suivante
@returns {void}
*/
const authenticateToken = (req, res, next) => {
  const token = req.session.token;;
  if (token == null) return res.sendStatus(401);

  // Token is valid, so we can get the user from the database
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // 403 for invalid token
    req.user = user;
    next();
  });

};

module.exports = authenticateToken;