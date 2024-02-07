// app.js
const express = require('express');
const bodyParser = require('body-parser');
const userRoutes = require('./userRoutes');
//const { secretKey } = require('../secretkey/secret');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Mount user routes
app.use('/users', userRoutes);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
