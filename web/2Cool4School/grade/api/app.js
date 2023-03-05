const express = require('express');
const {validateTicket, setup, authenticated} = require('./auth');
const app = express();
const crypto = require('crypto');
const cookieParser = require("cookie-parser");
const sessions = require('cookie-session');
const { getConnection } = require('./db')

let got = undefined

const grades = require('./grades');
const profile = require('./profile');

const port = 3000

const oneDay = 1000 * 60 * 60 * 24;
app.use(sessions({
    secret: "cd11dd374686a2638038a2bdfc11a9d120738638c134f54e393e4dea2747c502",//crypto.randomBytes(32).toString('hex'),
    resave: false,
    name: 'grade-session',
    saveUninitialized: true,
    cookie: {
        maxAge: oneDay,
        httpOnly: true,
     }
}));

app.use(cookieParser());
app.use(express.json({limit: '50mb'}));
app.use(express.static('public'));

app.use('/api/grades', grades);
app.use('/api/profile', profile);

app.get('/login', async (req, res) => {
    let { ticket } = req.query
    if (!ticket) {
        res.redirect("http://sso."+process.env.BASEURL+'/login?service=http://grade.'+process.env.BASEURL+'/login')
        return
    }
    let user = await validateTicket(ticket, got)
    if (!user) {
        res.redirect('/error?message=Invalid+ticket')
        return
    }
    req.session.user = user
    res.redirect('/')
})

app.post('/logout', async (req, res) => {
    req.session.user = undefined
    res.redirect('/')
})

app.post('/whine', authenticated, async (req, res) => {
    //TODO: Add a captcha
    await got.post(`http://teacher:3000/read?id=${req.session.user.id}`)
    res.send('Nah, no mistakes were made. Git good.')
})

app.get('/flag', authenticated, async (req, res) => {
    try {
        let conn = await getConnection();
        const rows = await conn.query('SELECT grades.grade FROM grades, courses WHERE courses.id = grades.course and courses.name = \'Fundamentals of Cyber Security\' and grades.student = ?', [req.session.user.id]);
        if (conn) conn.release()
        if (rows[0]['grade'] === 'A') {
            res.json(process.env.FLAG)
        } else {
            res.status(400).send("You don't have an A in Fundamentals of Cyber Security yet!")
        }
    } catch {
        res.status(500).send("You did something weird")
    }
})

app.get('*', async (req, res) => {
    res.sendFile(__dirname+'/public/index.html')
})

import('got').then(g => got = g.default).then(() => {setup()}).then(() => {
    app.listen(port, async () => {})
})