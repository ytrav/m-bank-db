const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const { v4: uuidv4 } = require("uuid");

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
    "SELECT * FROM User WHERE account_number = ?",
    [accountNum],
    (err, row) => {
      if (err) {
        res.status(400).json({ error: err.message });
        return;
      }
      if (row && bcrypt.compareSync(password, row.password)) {
        res.json({
          message: "success",
          userData: row,
        });
      } else {
        res.status(401).json({ message: "Invalid account number or password" });
      }
    }
  );
});

app.post("/generate-invite", (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  db.get("SELECT * FROM User WHERE id = 1", (err, row) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error: " + err.message });
    }
    if (!row) {
      return res.status(404).json({ error: "User not found" });
    }

    if (bcrypt.compareSync(password, row.password)) {
      const inviteCode = uuidv4();
      db.run(
        "INSERT INTO Invite_Codes (code) VALUES (?)",
        [inviteCode],
        (err) => {
          if (err) {
            console.error("Database error:", err);
            return res
              .status(500)
              .json({ error: "Database error: " + err.message });
          }
          return res.status(200).json({ inviteCode });
        }
      );
    } else {
      return res.status(401).json({ error: "Invalid password" });
    }
  });
});

app.post("/transfer", (req, res) => {
  const { sender, receiver, amount } = req.body;

  if (!sender || !receiver || !amount) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // Check if sender account exists
  db.get(
    "SELECT * FROM User WHERE account_number = ?",
    [sender],
    (err, senderRow) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Database error: " + err.message });
      }
      if (!senderRow) {
        return res.status(404).json({ error: "Sender account not found" });
      }
      if (senderRow.balance < amount) {
        return res.status(400).json({ error: "Insufficient balance" });
      }

      // Check if receiver account exists
      db.get(
        "SELECT * FROM User WHERE account_number = ?",
        [receiver],
        (err, receiverRow) => {
          if (err) {
            return res
              .status(500)
              .json({ error: "Database error: " + err.message });
          }
          if (!receiverRow) {
            return res
              .status(404)
              .json({ error: "Receiver account not found" });
          }

          // Deduct amount from sender
          db.run(
            "UPDATE User SET balance = balance - ? WHERE account_number = ?",
            [amount, sender],
            (err) => {
              if (err) {
                return res
                  .status(500)
                  .json({ error: "Database error: " + err.message });
              }

              // Add amount to receiver
              db.run(
                "UPDATE User SET balance = balance + ? WHERE account_number = ?",
                [amount, receiver],
                (err) => {
                  if (err) {
                    return res
                      .status(500)
                      .json({ error: "Database error: " + err.message });
                  }

                  // Log outgoing transaction for sender
                  db.run(
                    `INSERT INTO Transaction (sender_account_number, receiver_account_number, amount, type, description)
                    VALUES (?, ?, ?, 'outgoing', 'Transfer to account ${receiver}')`,
                    [sender, receiver, amount],
                    (err) => {
                      if (err) {
                        return res
                          .status(500)
                          .json({ error: "Database error: " + err.message });
                      }

                      // Log incoming transaction for receiver
                      db.run(
                        `INSERT INTO Transaction (sender_account_number, receiver_account_number, amount, type, description)
                        VALUES (?, ?, ?, 'incoming', 'Received from account ${sender}')`,
                        [sender, receiver, amount],
                        (err) => {
                          if (err) {
                            return res.status(500).json({
                              error: "Database error: " + err.message,
                            });
                          }

                          return res
                            .status(200)
                            .json({ message: "Transfer successful" });
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
