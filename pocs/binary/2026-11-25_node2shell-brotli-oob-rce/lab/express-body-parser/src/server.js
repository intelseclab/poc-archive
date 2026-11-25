'use strict';

const express = require('express');

const app = express();
app.get('/health', (_request, response) => response.end('PONG\n'));
app.post(
  '/upload',
  express.json(),
  (_request, response) => response.end('DONE\n'),
);
app.use((error, _request, response, _next) => {
  response.status(400).end(`ERR ${error.code || error.type || error.message}\n`);
});
app.listen(3000, '0.0.0.0');
