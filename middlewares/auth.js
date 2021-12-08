const jwt = require("jsonwebtoken");
const fs = require('fs');

module.exports = function (req, res, next){
  if (!req.headers.authorization){
    return res.status(401).send({ status: 401, message: "Missing authorization header" });
  }

  const publicKEY = fs.readFileSync('./public.pub', 'utf8');

  try {
    jwt.verify(req.headers.authorization, publicKEY, { algorithm: ["RS256"] });
  } catch (error) {
    return res.status(500).send(error.message);
  }
  next();
}
