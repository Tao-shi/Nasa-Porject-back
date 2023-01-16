const mongoose = require('../config/mongoose');

var userSchema = mongoose.Schema({
  fullname: {
    type: String,
    required: true
  },
  email: {
    type: String,
    unique: true,
    required: true
  },
  createdAt: {
    type: Date
  },
  password: {
    type: String,
    required: true
  },
});

const User = mongoose.model('users', userSchema);
module.exports = User;