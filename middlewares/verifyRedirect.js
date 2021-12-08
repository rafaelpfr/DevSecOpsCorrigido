module.exports = function (req, res, next){
  let validPaths = ['/audience', '/speakers']

  if (req.query.redirect_url && validPaths.indexOf(req.query.redirect_url) === -1) 
    return res.status(404).send('Invalid Path');

    next();
}
