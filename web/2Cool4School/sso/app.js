const express = require('express')
const {validateTicket, generateTicket, newUser, login, setup} = require('./auth')
const app = express()
const crypto = require('crypto')
const cookieParser = require("cookie-parser");
const sessions = require('cookie-session');

const port = 3000

const oneDay = 1000 * 60 * 60 * 24;
app.use(sessions({
    secret: "5df6518e6b284016f0a53b4301c4134862eecbeec1fa56a330cfa1e3f9255e2e",//crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    name: 'sso-session',
    cookie: {
        maxAge: oneDay,
        httpOnly: true
     }
}));
app.use(cookieParser());
app.use(express.urlencoded({extended:false}));
app.use(express.static('static'));

const xml = (data) => 
`<?xml version="1.0"?>
<response>
    ${data}
</response>
`

app.get('/validate', async (req, res) => {
    res.header("Content-Type", "application/xml")
    const { ticket, service } = req.query
    if (!ticket || !service  || typeof(ticket) != "string") {
        res.status(400).send(xml('<error>Missing ticket or service</error>'))
        return
    } else if (!ticket.startsWith('TGT-')){
        res.status(401).send(xml('<error>Ticket is invalid</error>'))
        return
    }
    let data = xml(await validateTicket(ticket, service))
    
    res.status(200).send(data)
})

app.post('/register', async (req, res) => {
    //TODO: Add a captcha
    res.json(await newUser())
})

app.post('/logout', async (req, res) => {
    req.session.user = undefined
    res.send('OK')
})

app.get('/', (req, res) => {
    if (!req.session.username) {
        res.redirect('/login')
        return
    }
    res.sendFile(__dirname+'/index.html');
})

app.get('/login', async (req, res) => {
    let { service } = req.query
    if (!service) {
        service = '/sso'
    }
    if (req.session.username) {
        const ticket = await generateTicket(req.session.username, service)
        res.redirect(`${service}?ticket=${ticket}`)
        return
    }
    res.sendFile(__dirname+'/login.html');
})

app.post('/login', async (req, res) => {
    let { service } = req.query
    if (!service) {
        service = '/sso'
    }
    const { username, password } = req.body
    const ticket = await login(username, password, service)
    if (!ticket) {
        res.status(401).send('Invalid username or password')
        return
    }
    req.session.username = username
    res.redirect(`${service}?ticket=${ticket}`)
})

app.listen(port, async () => {
    await setup()
})