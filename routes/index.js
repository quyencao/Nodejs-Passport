var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/register', function(req, res, next) {
  res.render('register', { title: 'Registration' });
});

router.post('/register', function (req, res, next) {
   const db = require('./../db');

   const username = req.body.username;
   const email = req.body.email;
   const password = req.body.password;

   db.query('INSERT INTO users(username, email, password) VALUES(?,?,?)',
        [username, email, password], function (error, results, fields) {
           if(error) throw error;

           res.render('register', { title: 'Registration Complete' });
       });
});

module.exports = router;
