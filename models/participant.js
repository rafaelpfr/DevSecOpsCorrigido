const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name: {type: String},
	email: {type: String},
	password: {type: String},
	job: {type: String}
});

mongoose.model('Participant', userSchema);
