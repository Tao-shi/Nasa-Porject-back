const mongoose = require('mongoose');
var config = require('./config');

mongoose.Promise = global.Promise;
mongoose.connect(config.dbURL, {useUnifiedTopology: true, useNewUrlParser: true, useCreateIndex: true, useFindAndModify: false })

module.exports = mongoose;