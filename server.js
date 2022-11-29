const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
const { verify } = require('crypto');
const PORT = 3000;

const config = {
  CLIENT_ID: '425982821596-l2c683uo8ivvn2r3klbkjh110ura031u.apps.googleusercontent.com',
  CLIENT_SECRET: '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',
  COOKIE_KEY_1: 'abc',
  COOKIE_KEY_2: 'dbf',
}

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

const app =express();

app.use(helmet());
app.use(cookieSession({
  name: 'session',
  maxAge: 24* 60*60*1000,
  keys: ['secret ket key for rotation']
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));
passport.serializeUser((user, done) => {
  done(null, user.id);
});
 passport.deserializeUser((id, done)=> {
  done(null, id);
 })
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);
  done(null, profile);
}

function checkLoggedIn(req, res, next) { // req.user
  console.log('Current user is', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user; // TODO
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must be logged in'
    });
  }
  next();
}


app.get('/auth/google', passport.authenticate('google', {
  scope: ['email'],
}));

app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }), (req, res) => {
    console.log('Google call us back!');
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout();
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Your personal secret value is 42!')
});

app.get('/failure', (req, res) => {
  return res.send('Failed to log in!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer({
  cert: fs.readFileSync('cert.pem'),
  key: fs.readFileSync('key.pem'),
}, app).listen(PORT, () => {
  console.log(`Listen on ${PORT}...`);
}); //