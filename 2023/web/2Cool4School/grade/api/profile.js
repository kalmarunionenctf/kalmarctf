const express = require('express');

const { authenticated, adminOnly, isNewStudent, addStudent} = require('./auth')
const { getConnection } = require('./db')
const router = express.Router();

router.get('/isNew', authenticated, async (req, res) => {
    return res.json(await isNewStudent(req.session.user.id))
})

router.post('/echo', authenticated, async (req, res) => {
    res.json(req.body)
})

router.post('/new', authenticated, async (req, res) => {
    const id = req.session.user.id
    if (!(await isNewStudent(id))){
        return res.status(400).send('use /api/profile/update to create a new profile')
    }
    await addStudent(id);
    let { name, picture } = req.body
    if (!name || !picture){
        return res.status(400).send('name or profile missing')
    }
    let conn = await getConnection();
    const count = await conn.query('SELECT userid FROM teachers WHERE userid = ?', [req.session.user.id]);
    if (count.length === 1) {
        return res.status(400).send('Teachers cannot change their profile')
    }
    await conn.query('INSERT INTO profiles (id, name, picture) values (?, ?, ?)', [id, name, picture]);
    if (conn) conn.release()
    res.send("ok")
})

router.put('/', authenticated, async (req, res) => {
    const id = req.session.user.id
    if (await isNewStudent(id)){
        return res.status(400).send('use /api/profile/new to create a new profile')
    }
    let { name, picture } = req.body
    let conn = await getConnection();
    const count = await conn.query('SELECT userid FROM teachers WHERE userid = ?', [req.session.user.id]);
    if (conn) conn.release();
    if (count.length === 1) {
        return res.status(400).send('Teachers cannot change their profile')
    }
    if (name) {
        await conn.query('UPDATE profiles SET name = ? WHERE id = ?', [name, id]);
    }
    if (picture) {
        await conn.query('UPDATE profiles SET picture = ? WHERE id = ?', [picture, id]);
    }
    if (conn) conn.release()
    res.send("ok")
})

router.get('/role', authenticated, async (req, res) => {
    const conn = await getConnection()
    const count = await conn.query('SELECT userid FROM teachers WHERE userid = ?', [req.session.user.id]);
    if (conn) conn.release();
    if (count.length === 1) {
        return res.json({role: 'teacher'})
    } else {
        return res.json({role: 'student'})
    }
})

router.get('/', authenticated, async (req, res) => {
    const id  = req.session.user.id;
    let conn = await getConnection();
    const rows = await conn.query('SELECT name, picture FROM profiles WHERE id = ?', [id]);
    if (conn) conn.release()
    if (rows.length == 0) {
        res.status(404).send('no profile found')
        return
    }
    res.send(rows[0])
})

router.get('/:id', adminOnly, async (req, res) => {
    const { id } = req.params
    let conn = await getConnection();
    const rows = await conn.query('SELECT name, picture FROM profiles WHERE id = ?', [id]);
    if (conn) conn.release()
    if (rows.length == 0) {
        res.status(404).send('no profile found')
        return
    }
    res.send(rows[0])
})

module.exports = router