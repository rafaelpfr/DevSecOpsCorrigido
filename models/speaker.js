const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name: {type: String},
	email: {type: String},
	password: {type: String},
    topic: {type: String}
});

mongoose.model('Speaker', userSchema);
