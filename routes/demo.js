const express = require('express');
const bcrypt = require('bcryptjs')

const db = require('../data/database');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: ''
    };
  }

  req.session.inputData = null; // clear the session

  res.render('signup', { inputData: sessionInputData });
});

router.get('/login', function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      password: ''
    };
  }

  req.session.inputData = null;
  res.render('login', { inputData: sessionInputData });
});

router.post('/signup', async function (req, res) {
  const userData = req.body
  const enteredEmail = userData.email
  const enteredConfirmEmail = userData['confirm-email']
  const enteredPassword = userData.password

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.trim() < 6 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.includes('@')
  ) {
    // console.log('Incorrect data')
    req.session.inputData = {
      hasError: true,
      message: 'Invalid input - please check your data.',
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    req.session.save(function () {
      res.redirect('/signup');
    });
    return;
    // return res.render('signup');

  }

  const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail })

  if (existingUser) {
    console.log('User exists already')
    req.session.inputData = {
      hasError: true,
      message: 'User exists already!',
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    req.session.save(function () {
      res.redirect('/signup')
    })
    return
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12)

  const user = {
    email: enteredEmail,
    password: hashedPassword
  }

  await db.getDb().collection('users').insertOne(user)

  res.redirect('/login')
});

router.post('/login', async function (req, res) {
  const userData = req.body
  const enteredEmail = userData.email
  const enteredPassword = userData.password

  const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail }) // if no email is found it will return null

  if (!existingUser) {
    console.log('Could not log in!')
    req.session.inputData = {
      hasError: true,
      message: 'Could not log in - please check your credentials!',
      email: enteredEmail,
      password: enteredPassword,
    };
    req.session.save(function () {
      res.redirect('/login')
    })
    return
  }

  const passwordsAreEqual = await bcrypt.compare(enteredPassword, existingUser.password)


  if (!passwordsAreEqual) {
    console.log('Could not log in - passwords are not equal!')
    req.session.inputData = {
      hasError: true,
      message: 'Could not log you in - please check your credentials!!',
      email: enteredEmail,
      password: enteredPassword,
    };
    req.session.save(function () {
      res.redirect('/login')
    })
    return
  }

  // console.log('User is authenticated')
  req.session.user = { id: existingUser._id, email: existingUser.email }  //update session
  req.session.isAuthenticated = true
  req.session.save(function () { // save the session then redirect
    res.redirect('/profile') // redirect work faster so we need to include in tha callback to ensure that the data is save before redirecting to a specific page!
  })


});

router.get('/admin', async function (req, res) {
  if (!req.session.isAuthenticated) {
    return res.status(401).render('401')
  }

  const user = await db.getDb().collection('users').findOne({ _id: req.session.user.id })
  if (!user || !user.isAdmin) {
    return res.status(403).render('403');  // status 403 if for users that are authenticated but they do not have authorization
  }
  res.render('admin');
});

router.get('/profile', function (req, res) {
  if (!req.session.isAuthenticated) {
    // if (!req.session.user)
    return res.status(401).render('401');
  }
  res.render('profile');
});

router.post('/logout', function (req, res) {
  req.session.user = null
  req.session.isAuthenticated = false // we update the data but we do not delete the session
  res.redirect('/')
});

module.exports = router;
