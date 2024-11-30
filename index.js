const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());
const port = 3000;

app.use(bodyParser.json());

const db = new sqlite3.Database("./mBank.db", (err) => {
  if (err) {
    console.error("Could not connect to database", err);
  } else {
    console.log("Connected to database");
  }
});

app.get("/users", (req, res) => {
  db.all("SELECT * FROM User;", (err, rows) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    } else {
      res.json({
        message: "success",
        data: rows,
      });
    }
  });
});

app.get("/users/:id", (req, res) => {
  const id = req.params.id;
  db.get(`SELECT * FROM User WHERE id = ${id};`, (err, row) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    } else {
      res.json({
        message: "success",
        data: row,
      });
    }
  });
});

app.post("/login", (req, res) => {
  const { accountNum, password } = req.body;
  // const hashed_password = bcrypt.hashSync(password, 12);
  db.get(
    'SELECT * FROM User WHERE account_number = ?',
    [accountNum],
    (err, row) => {
      if (err) {
        res.status(400).json({ error: err.message });
        return;
      }
      if (row && bcrypt.compareSync(password, row.password)) {
        res.json({
          message: 'success',
          userData: row,
        });
      } else {
        res.status(401).json({ message: 'Invalid account number or password' });
      }
    }
  );
  
  
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
