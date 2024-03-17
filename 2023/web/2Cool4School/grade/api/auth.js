const service = "http://grade." + process.env.BASEURL + '/login'
const { getConnection } = require('./db')
const xml2js = require('xml2js')

const defaultGrades = [['Algebra', 'B', 'Fair'], ['Algorithms and Datastructures', 'D', 'Get better or no job for you (in a US-company)'], ['Object Oriented Programming', 'C-', 'Do you really want to do python and js for life?'], ['Fundamentals of Cyber Security', 'F', 'Oh so you are one of those devs that are giving CyberSec-people job security? Huh...']]
const defaultCourses = ['Algebra', 'Algorithms and Datastructures', 'Object Oriented Programming', 'Fundamentals of Cyber Security'];

async function validateTicket(ticket, got) {
    try {
        let response = await got.get(`http://sso:3000/validate?ticket=${ticket}&service=${service}`)
        let data = await response.body
        let xml = await xml2js.parseStringPromise(data, { explicitArray: false })
        return xml.response ? xml.response.authenticationSuccess : undefined
    } catch {
        return undefined
    }
}

async function adminOnly(req, res, next) {
    if (!req.session.user || !req.session.user.id) {
        res.sendStatus(403)
        return true
    }
    try {
        const conn = await getConnection()
        const count = await conn.query('SELECT userid FROM teachers WHERE userid = ?', [req.session.user.id]);
        if (conn) conn.release();
        if (count.length === 1) {
            next()
            return
        } else {
            res.sendStatus(403)
        }
    } catch (e) {
        console.error(e)
        res.sendStatus(500)
    }
}

async function authenticated(req, res, next) {
    if (!req.session.user || !req.session.user.id) {
        res.sendStatus(403)
        return
    }
    next()
}

async function isNewStudent(id) {
    let conn = await getConnection();
    const count = await conn.query('SELECT student FROM grades WHERE student = ?', [id]);
    if (conn) conn.release()
    return count.length === 0
}

async function addStudent(id) {
    let conn = await getConnection();
    await conn.query('INSERT INTO students (userid) VALUES (?)', [id]);
    defaultGrades.forEach(async element => {
        let course = element[0]
        let grade = element[1]
        let comment = element[2]
        await conn.query('INSERT INTO grades (student, course, grade, notes) VALUES (?, (select id from courses where name = ?) , ?, ?)', [id, course, grade, comment]);
    });

    if (conn) conn.release()
    return
}

async function setup() {
    let conn = await getConnection()
    const rows = await conn.query('SELECT userid FROM teachers WHERE userid = ?', [process.env.TEACHER_ID]);
    if (rows.length == 1) {
        return
    }
    await conn.query('INSERT INTO teachers (userid) VALUES (?)', [process.env.TEACHER_ID])
    defaultCourses.forEach(async element => {
        await conn.query('INSERT INTO courses (name, teacher) VALUES (?, ?)', [element, process.env.TEACHER_ID]);
    });

    if (conn) conn.release();
}

module.exports = {
    validateTicket,
    adminOnly,
    authenticated,
    setup,
    isNewStudent,
    addStudent
}