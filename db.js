// db.js
const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'PrelimOutput'
});

db.connect((err) => {
  if (err) {
    console.error("error connecting to mysql: ", err)
  } else {
    console.log("connected to mysql")
  }
});

module.exports = db;
 

