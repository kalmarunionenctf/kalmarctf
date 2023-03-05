const {getConnection} = require('./db')
const bcrypt = require('bcrypt')
const crypto = require('crypto')

async function validateTicket(ticket, service){
    let conn
    try {
        conn = await getConnection();
        let rows = await conn.query('SELECT username FROM tickets WHERE ticket = ? AND service = ?', [ticket, service]);
        if (rows.length == 1){
            let username = rows[0].username
            await conn.query('DELETE FROM tickets WHERE ticket = ?', ticket)
            rows = await conn.query('SELECT id,username FROM users WHERE username = ?', username)
            if (conn) conn.release();
            return `<authenticationSuccess><id>${rows[0].id}</id><username>${username}</username></authenticationSuccess>`
        } else {
            if (conn) conn.release();
            return `<authenticationFailure>Ticket ${ticket} is invalid for service ${service}</authenticationFailure>`
        }
    } catch (e) {
        console.error(e);
        return '<authenticationFailure>Internal server error</authenticationFailure>'
    }  finally {
        if (conn) conn.end();
    }
}

async function newUser(){
    let conn
    try {
        conn = await getConnection();
        let username = 'student'+crypto.randomInt(10000, 99999)
        let password = crypto.randomBytes(16).toString('hex')
        const hash = bcrypt.hashSync(password, 10)
        await conn.query('INSERT INTO users (username, hash) VALUES (?, ?)', [username, hash])
        if (conn) conn.release();
        return {username, password}
    } catch (e) {
        console.error(e);
    } finally {
        if (conn) conn.end();
    }
}

async function login(username, password, service){
    let conn
    try {
        conn = await getConnection();
        const rows = await conn.query('SELECT hash FROM users WHERE username = ?', username);
        if (conn) conn.release();
        if (rows.length == 1 && bcrypt.compareSync(password, rows[0].hash)) {
            return generateTicket(username, service)
        } else {
            return undefined;
        }
    } catch (e) {
        console.error(e);
    } finally {
        if (conn) conn.end();
    }
}

async function generateTicket(username, service){
    let conn
    try {
        conn = await getConnection();
        let ticket = 'TGT-'+crypto.randomBytes(32).toString('hex')
        await conn.query('INSERT INTO tickets (ticket, username, service) VALUES (?, ?, ?)', [ticket, username, service])
        if (conn) conn.release();
        return ticket;
    } catch (e) {
        console.error(e);
    } finally {
        if (conn) conn.end();
    }
}

async function setup(){
    let conn
    try {
        conn = await getConnection();
        let username = process.env.TEACHER_USERNAME
        let password = process.env.TEACHER_PASSWORD
        const rows = await conn.query('SELECT hash FROM users WHERE username = ?', username);
        if (rows.length == 1 ){
            return
        }
        const hash = bcrypt.hashSync(password, 10)
        await conn.query('INSERT INTO users (id, username, hash) VALUES (?, ?, ?)', [process.env.TEACHER_ID, username, hash])
        if (conn) conn.release();
    } catch (e) {
        console.error(e);
    }  finally {
        if (conn) conn.end();
    }
}

module.exports = {
    validateTicket,
    generateTicket,
    newUser,
    login,
    setup
}