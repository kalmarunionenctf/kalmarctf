const express = require('express');
const { adminOnly, authenticated } = require('./auth')
const { getConnection } = require('./db')
const router = express.Router();

router.get('/', authenticated, async (req, res) => {
    res.send(await getGrades(req.session.user.id))
})

router.get('/:id', adminOnly, async (req, res) => {
    const { id } = req.params
    res.send(await getGrades(id))
})

router.put('/:id', adminOnly, async (req, res) => {
    const { id } = req.params
    let conn = await getConnection();
    try {
        let params = req.body
        if (!id){
            return res.status(400).send('missing id')
        }
        if (!params.name){
            return res.status(400).send('missing coursename')
        }
        if (params.values.length == 0) {
            return res.status(400).send('no body provided')
        }
        if (params.values.grade){
            return res.status(400).send('grade is not allowed')
        }
        await conn.query(`UPDATE grades SET ${Object.keys(params.values).map(p => conn.escapeId(p)+' = ?').join(', ')} WHERE student = ? and course = (select id from courses where name = ?)`, Object.values(params.values).concat(id).concat(params.name));
        res.sendStatus(200)
    } catch (error) {
        res.status(400).send(error)
    } finally {
        if (conn) conn.release()
    }
})

async function getGrades(id) {
    let conn = await getConnection();
    const rows = await conn.query('SELECT courses.name, grades.grade, grades.notes FROM grades, courses WHERE courses.id = grades.course and grades.student = ?', [id]);
    if (conn) conn.release()
    return rows
}

module.exports = router