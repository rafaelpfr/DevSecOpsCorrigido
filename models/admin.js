const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const adminSchema = mongoose.Schema({
    name: {type: String},
    email: {type: String},
    password: {type: String}
});

adminSchema.methods.generateAuthToken = function(){
  let buff = Buffer.from(process.env.APP_PRIVATE_KEY, 'base64');
  let APP_PRIVATE_KEY = buff.toString('ascii');
  const token = jwt.sign({name: this.name}, APP_PRIVATE_KEY, { algorithm:  "RS256" });
  return token;
}
  
const Admin = mongoose.model('Admin', adminSchema);

exports.Admin = Admin;
