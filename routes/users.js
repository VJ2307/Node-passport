const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');


// User Model
const User = require('../models/User');
const { route } = require('.');

// Login Page
router.get('/login',(req,res) => res.render('login'));

// Register Page
router.get('/register', (req,res) => res.render('register'));

// Register Handle
router.post('/register', (req,res) =>{
    // console.log(req.body)
    // res.send('Details Recieved');
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Check required fields
    if(!name || !email || !password || !password2){
        errors.push({msg: 'Please fill in all the required fields'});
    }

    // Check passwords match
    if(password !== password2){
        errors.push({msg: 'Passwords do not match'});
    }

    // Check password length
    if(password.length <6){
        errors.push({msg:'Password should be at least 6 characters'});
    }

    if(errors.length>0){
        res.render('register',{
           errors,
           name,
           email,
           password,
           password2 
        });
    }else{
        // Validation Pass
        User.findOne({email:email})
        .then(user =>{
            if(user){
                // User Exists
                errors.push({msg: 'Email is already registered!! Try something different.'});
                res.render('register',{
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else{
                const newUser = new User({
                    name,
                    email,
                    password
                });

                // Encrypting a password
                bcrypt.genSalt(10,(err,salt) => 
                    bcrypt.hash(newUser.password,salt,(err,hash)=>{
                        if(err) throw err;
                        // Setting the password to encrypted hash
                        newUser.password = hash;
                        // Save the user
                        newUser.save()
                        .then(user => {
                            req.flash('success_msg','You are now registered and can login to the application');
                            res.redirect('/users/login');
                        })
                        .catch(error => console.log(error));
                }));

                // console.log(newUser);
                // res.send('New User Registered');
            }
        });
    }

});

// Login Handle

router.post('/login', (req, res,next)=> {
    passport.authenticate('local',{
        successRedirect:'/dashboard',
        failureRedirect:'/users/login',
        failureFlash: true
    })(req, res,next);
});

// Logout Handle

router.get('/logout',(req,res) =>{
    req.logout();
    req.flash('success_msg','You are successfully logged out.');
    res.redirect('/users/login');
});

module.exports = router;