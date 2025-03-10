const express = require('express');
const app = express();

app.get('/', (req, res) => {
  html = req.query.html?.toString() || '<h1>Hello World!</h1>'

  // we're so nice :)
  res.send(html);
});

app.listen(8080, () => {
  console.log('Free XSS app started');
});