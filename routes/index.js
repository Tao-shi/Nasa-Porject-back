var express = require('express');
var router = express.Router();
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken')
var appDetails = require('../config/appdetails.json')
const User = require('../models/userModel');

function sanitizeUser(user) {
  const userChecked = user
  userChecked.password = undefined
  return userChecked
}

async function auth(req, res, next) {
  var token = req.header("authorization");
  if (token) {
    var data = jwt.decode(token, appDetails.jwtSecret);
    User.findById(data.tity).then((user) => {
      req.user = user._id
      next();
    }).catch((err) => {
      res.status(400).json({
        err: "Please login to continue"
      })
    })
  } else {
    res.status(400).json({
      err: "Please login to continue"
    })
  }
}

/* GET home page. */
router.get('/', function (req, res, next) {
  res.send({
    success: true
  });
});


router.post('/signup', function (req, res, next) {
  const { fullname, email, password, phone } = req.body
  User.findOne({ email }).then((data) => {
    if (data !== null) {
      res.status(400).send({
        err: 'Email or Phone already exists'
      })
    } else {
      bcrypt.hash(password, 10).then((hash) => {
        User.create({
          fullname,
          email,
          password: hash,
          createdAt: Date.now(),
        }).then((data) => {
          // sign up email
          data.password = null
          var token = jwt.sign(JSON.stringify({ tity: data.id }), appDetails.jwtSecret)
          res.status(200).send({
            success: true,
            message: 'User authenticated successfully',
            token,
            data: sanitizeUser(data)
          })
        }).catch((err) => {
          res.status(400).send({
            err: 'Something went wrong!'
          })
        })
      }).catch((err) => {
        res.status(400).send({
          err: 'Something went wrong!'
        })
      })
    }
  }).catch((err) => {
    res.status(400).send({
      err: 'Something went wrong!'
    })
  })
});

router.post('/getuser', function (req, res, next) {
  const { id } = req.body
  User.findOne({ _id: id }).then((data) => {
    data.password = null
    res.status(200).send({
      success: true,
      data: sanitizeUser(data)
    })
  }).catch((err) => {
    res.status(400).send({
      err: 'Something went wrong!'
    })
  })
});

router.post('/signin', function (req, res, next) {
  const { email, password } = req.body
  User.findOne({ email }).then((data) => {
    if (data !== null) {
      bcrypt.compare(password, data.password).then((valid) => {
        if (valid) {
          data.password = null
          var token = jwt.sign(JSON.stringify({ tity: data.id }), appDetails.jwtSecret)
          res.status(200).send({
            success: true,
            message: 'User authenticated successfully',
            token,
            data: sanitizeUser(data)
          })
        } else {
          res.status(400).send({
            err: 'Login Failed!'
          })
        }
      }).catch((err) => {
        res.status(400).send({
          err: 'Something went wrong!'
        })
      })
    } else {
      res.status(400).send({
        err: 'Login Failed!'
      })
    }
  }).catch((err) => {
    res.status(400).send({
      err: 'Something went wrong!'
    })
  })
});


router.post('/updatepassword', auth, function (req, res, next) {
  const { password, email, newpassword } = req.body
  User.findOne({ email }).then((data) => {
    if (data !== null) {
      bcrypt.compare(password, data.password).then((valid) => {
        if (valid) {
          if (password === newpassword) {
            res.status(400).send({
              err: 'Old password must not be the same as new password!'
            })
          } else {
            bcrypt.hash(newpassword, 10).then((hash) => {
              var lastestPassword = hash
              User.findByIdAndUpdate({ _id: data._id }, {
                password: lastestPassword
              }).then((data) => {
                res.status(200).send({
                  success: true,
                  message: 'User password updated successfully!'
                })
              }).catch((err) => {
                res.status(400).send({
                  err: 'Something went wrong!'
                })
              })
            }).catch((err) => {
              res.status(400).send({
                err: 'Something went wrong!'
              })
            })
          }
        } else {
          res.status(400).send({
            err: 'Incorrect old password!'
          })
        }
      }).catch((err) => {
        res.status(400).send({
          err: 'Something went wrong!'
        })
      })
    } else {
      res.status(400).send({
        err: 'Something went wrong!'
      })
    }
  }).catch((err) => {
    res.status(400).send({
      err: 'Something went wrong!'
    })
  })
});


module.exports = router;