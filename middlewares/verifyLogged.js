const jwt = require("jsonwebtoken");
const fs = require('fs');

module.exports = function (req, res, next){
  const publicKEY = fs.readFileSync('./public.pub', 'utf8');

  if (req.headers.authorization && jwt.verify(req.headers.authorization, publicKEY, { algorithm: ["RS256"] })) {
    if (req.query.redirect_url) return res.redirect(req.query.redirect_url);    // njsscan-ignore: express_open_redirect
    else return res.send({ "message": "You already are logged. To receive a new token, logout first" });
  }
    
  next();
}
