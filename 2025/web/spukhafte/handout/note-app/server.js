const express = require('express');
const bodyParser = require('body-parser');
const app = express();

// pretend this is a real database or something
const notes = {};

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.post('/note', (req, res) => {
  const { uuid, note } = req.body;
  if (!uuid.match(UUID_REGEX)) {
    res.status(400);
    res.json({ success: false });
    return;
  }
  notes[uuid] = note;
  res.json({ success: true });
});

app.get('/note/:uuid', (req, res) => {
  const uuid = req.params.uuid;
  if (!uuid.match(UUID_REGEX)) {
    res.status(400);
    res.json({ success: false });
    return;
  }

  if (!notes[uuid]) {
    res.status(404);
    return res.json({ success: false });
  }
  const note = notes[uuid] || 'Note not found';
  res.json({ note });
});

app.listen(8080, () => {
  console.log('Note app listening on port 8080');
});