'use strict';

/* *************** Отлавливаем необработанные исключения *************** */
process.on('uncaughtException', (err) => {
    console.error('Неотловленное исключение: ');
    console.error(err);
});

/* *************** Express *************** */
let express        = require('express');
let app            = express();

/* *************** Express Middleware *************** */
let cookieParser    = require('cookie-parser');
let bodyParser      = require('body-parser');
let gaikan          = require('gaikan');
let session         = require('express-session');
let flash           = require('connect-flash');
let MemoryStore     = require('session-memory-store')(session);
let cookieSession   = require('cookie-session');

app.use(flash());
app.use( cookieParser() )
app.use(cookieSession({
    maxAge: 30*60*1000, //30 mins
    httpOnly: true,
    keys: ['key1', 'key2']
}));
app.use( bodyParser.urlencoded({ extended: false }) );
app.use(session({
    resave: true,
    saveUninitialized: true,
    secret: 'SECRET',
    store: new MemoryStore()
}));

/* *************** Express Routes *************** */
app.engine('html', gaikan);
app.set('view engine', '.html');
app.set('views', './views');
app.use(express.static('public'));

function isAuthenticated(req) {
    if (req.session && req.session.passport 
        && req.session.passport.user !== undefined) {
        return true
    }
    return false;
}

app.get('/logout', (req, res) => {
    if (isAuthenticated(req)) {
        req.session = null;
        req.logout();
        return res.redirect('/');
    }
    res.send('Вы не вошли');
});

app.get('/', (req, res) => {
    if (isAuthenticated(req)) {
        return res.render('index', {email: req.session.passport.user});
    }
    return res.render('login_signup');
});

app.get('/login', (req, res) => {
    if (req.session && req.session.passport && req.session.passport.user) {
        res.redirect('/');
    } else {
        res.render('login', { message: req.flash("error")[0] });
    }
});

app.get('/signup', (req, res) => {
    if (req.session && req.session.passport && req.session.passport.user) {
        res.redirect('/');
    } else {
        res.render('signup', { message: req.flash("error")[0] });
    }
});

app.listen(8000, () => {
    console.log('Server listening on port 8000!');
});


/* *************** Passport *************** */
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy;

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use('local-login', new LocalStrategy(
    {
        passReqToCallback : true,
        usernameField: 'email',
        passwordField: 'password'
    },
    (req, email, password, done) => {
        findUser(email, (err, user) => {
            if (err) {
                return done(null, false, { message: err });
            }
            if (user.email == email && user.password == password) {
                return done(null, email)
            }
            return done(null, false, { message: 'Неверный пароль' });
        })
    }
));

passport.use('local-signup', new LocalStrategy(
    {
        passReqToCallback : true,
        usernameField: 'email',
        passwordField: 'password'
    },
    (req, email, password, done) => {
        // process.nextTick(function() {
            Users.findOne({'email': email}, (err, user) => {
                if (err) {
                    done(err);
                } else {
                    if (user && user.email && user.password) {
                        return done(null, false, { message: 'Такой пользователь уже есть' });
                    }
                    addUser(req.body.email, req.body.password, (err, user) => {
                        if (err) {
                            return done(err)
                        }
                        return done(null, email)
                    })
                }
            });
        // });
    }
));

app.use( passport.initialize() );
app.use( passport.session() );

app.post('/login', passport.authenticate('local-login', { 
    successRedirect: '/' ,
    failureRedirect: '/login',
    failureFlash: true
}));

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect : '/',
    failureRedirect : '/signup',
    failureFlash : true
}));



/* *************** Database *************** */
function findUser(email, cb) {
    Users.findOne({'email': email}, (err, user) => {
        if (err) {
            return cb(err);
        }
        if (user && user.email && user.password) {
            return cb(null, user);
        }
        return cb('Такой пользователь не существует');
    });
}

let mongoose = require('mongoose');
let userSchema = mongoose.Schema({
    email: {
        type: String,
        index: true,
        unique: true
    },
    password: String
});
let Users = mongoose.model('Users', userSchema);

mongoose.connect('', function (err) {
    if (err) throw err;
    console.log('Mongoose successfully connected');
});

function addUser(email, password, cb) {
    let user = new Users({
        email: email,
        password: password
    })
    user.save((err) => {
        if (err) return cb(err)
        console.log('User create ', user.email, ':', user.password, ' successfully saved');
        return cb(null, user)
    });
}