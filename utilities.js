const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const dotenv = require("dotenv");
dotenv.config();

const authenticateToken = (req, res, next) => {
  // Get the auth header value
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // if there isn't any token

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // invalid token

    req.user = user; // { username: "user1" } Assuming the payload has a username field
    next(); // pass the execution off to whatever request the client intended
  });
};

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = {
  authenticateToken,
  pool,
};
