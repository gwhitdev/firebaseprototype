const express = require('express'),
    csrf = require('csurf'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    admin  = require('firebase-admin'),
    app = express();

const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://computer-freedom-club.firebaseio.com'
});


const csrfMiddleware = csrf({ cookie: true });

const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');

app.use(express.static('static'));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrfMiddleware);

app.all('*', (req, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken());
    next();
});
app.get('/', (req, res) => {
    res.render('index');
})
app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/profile', (req, res) => {
    const sessionCookie = req.cookies.session || "";

    admin.auth()
    .verifySessionCookie(sessionCookie, true /** checkRevoked */)
    .then(() => {
        res.render('profile');
    })
    .catch((error) => {
        res.redirect('/login');
    });
    
});

app.post('/sessionLogin', (req, res) => {
    const idToken = req.body.idToken.toString();

    const expiresIn = 60*60*24*5 *1000;

    admin
    .auth()
    .createSessionCookie(idToken, { expiresIn })
    .then(
        (sessionCookie) => {
            const options = { maxAge: expiresIn, httpOnly: true };
            res.cookie('session', sessionCookie, options);
            res.end(JSON.stringify({ status: 'success' }));
        },
        (error) => {
            res.status(401).send('Unavailable request');
        }
    );
});

app.get('/sessionLogout', (req, res)=> {
    res.clearCookie('session');
    res.redirect('/login');
});

app.listen(PORT, () => {
    console.log('server running on port: ', PORT);
})