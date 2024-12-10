const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const dotenv = require("dotenv");
dotenv.config({ path: ".env.local" });

const secretKey = process.env.SECRET_KEY;
const refreshSecretKey = process.env.REFRESH_SECRET_KEY;

const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(
  cors({
    credentials: true,
    origin: "https://bank.maevetopia.fun",
  })
);
app.use(express.json());
app.use(cookieParser());
const port = 3000;

app.use(bodyParser.json());

const db = new sqlite3.Database("./mBank.db", (err) => {
  if (err) {
    console.error("Could not connect to database", err);
  } else {
    console.log("Connected to database");
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token missing" });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

const authenticateRefreshToken = (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(403).json({ error: "Refresh token missing" });
  }

  jwt.verify(refreshToken, refreshSecretKey, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Invalid or expired refresh token" });
    }
    req.user = user;
    next();
  });
};

const getUserData = (identifier, type = "id") => {
  return new Promise((resolve, reject) => {
    const column = type === "id" ? "id" : "account_number";
    db.get(
      `SELECT u.*,
        c.number AS card_number,
        c.expiry_date AS card_expiry_date
      FROM User u
        LEFT JOIN Card c ON u.id = c.owner_id
      WHERE u.${column} = ?`,
      [identifier],
      (err, userRow) => {
        if (err) {
          reject(new Error(`Database error: ${err.message}`));
        } else if (!userRow) {
          reject(new Error("User not found"));
        } else {
          db.all(
            `SELECT *,
              CASE
                WHEN sender_account_number = ? THEN 'SUBTRACTION'
                WHEN receiver_account_number = ? THEN 'ADDITION'
              END AS transaction_type
             FROM "Transaction"
             WHERE sender_account_number = ? OR receiver_account_number = ?`,
            [
              userRow.account_number,
              userRow.account_number,
              userRow.account_number,
              userRow.account_number,
            ],
            (txErr, transactionRows) => {
              if (txErr) {
                reject(new Error(`Database error: ${txErr.message}`));
              } else {
                resolve({
                  id: userRow.id,
                  f_name: userRow.f_name,
                  l_name: userRow.l_name,
                  account_number: userRow.account_number,
                  gender: userRow.gender,
                  balance: userRow.balance,
                  card: {
                    number: userRow.card_number,
                    expiry_date: userRow.card_expiry_date,
                  },
                  transactions: transactionRows.reverse().map((tx) => ({
                    ...tx,
                    personal_type:
                      tx.sender_account_number === userRow.account_number
                        ? "subtraction"
                        : "addition",
                  })),
                });
              }
            }
          );
        }
      }
    );
  });
};

const getUserPassword = (account_number) => {
  return new Promise((resolve, reject) => {
    db.get(
      "SELECT password FROM User WHERE account_number = ?",
      [account_number],
      (err, row) => {
        if (err) {
          reject(new Error(`Database error: ${err.message}`));
        } else if (!row) {
          reject(new Error("User not found"));
        } else {
          resolve(row.password);
        }
      }
    );
  });
};

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

app.get("/user", authenticateToken, async (req, res) => {
  try {
    const user = await getUserData(req.user.id, "id");
    res.json({ message: "success", data: user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  const { accountNum, password, remember } = req.body;

  try {
    const user = await getUserData(accountNum, "account_number");
    // console.log('user: ', user.id, user.account_number);

    const hashedPassword = await getUserPassword(accountNum);

    if (bcrypt.compareSync(password, hashedPassword)) {
      const accessToken = jwt.sign(
        { id: user.id, account_number: user.account_number },
        secretKey,
        { expiresIn: "1h" }
      );
      const refreshToken = jwt.sign(
        { id: user.id, account_number: user.account_number },
        refreshSecretKey,
        { expiresIn: remember ? "7d" : "1h" }
      );
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : null,
      });
      res.json({ message: "success", accessToken, user });
    } else {
      res.status(401).json({ error: "Invalid account number or password" });
    }
  } catch (error) {
    console.log("error: ", error);
    // console.log(accountNum, password, user.id, user.account_number);

    res.status(500).json({ error: error.message });
  }
});

app.post("/refresh", authenticateRefreshToken, (req, res) => {
  const user = req.user;

  const newAccessToken = jwt.sign(
    { id: user.id, account_number: user.account_number },
    secretKey,
    { expiresIn: "1h" }
  );
  res.json({ accessToken: newAccessToken });
});

app.post("/logout", (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
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

app.post("/register", async (req, res) => {
  const { f_name, l_name, gender, inviteCode, password, remember } = req.body;

  if (!f_name || !l_name || !gender || !inviteCode || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Check if the invite code is valid
    const inviteCodeRow = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM Invite_Codes WHERE code = ? AND is_used = 0",
        [inviteCode],
        (err, row) => {
          if (err) reject(new Error(`Database error: ${err.message}`));
          else if (!row) reject(new Error("Invalid or used invite code"));
          else resolve(row);
        }
      );
    });

    const hashedPassword = bcrypt.hashSync(password, 12);
    const newAccountNumber = Math.floor(Math.random() * 1e8)
      .toString()
      .padStart(8, "0");

    // Insert the new user
    const userId = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO User (f_name, l_name, gender, account_number, password) VALUES (?, ?, ?, ?, ?)",
        [f_name, l_name, gender, newAccountNumber, hashedPassword],
        function (err) {
          if (err) reject(new Error(`Database error: ${err.message}`));
          else resolve(this.lastID);
        }
      );
    });

    // Mark the invite code as used
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE Invite_Codes SET is_used = 1 WHERE code = ?",
        [inviteCode],
        (err) => {
          if (err) reject(new Error(`Database error: ${err.message}`));
          else resolve();
        }
      );
    });

    // Fetch the complete user data
    const user = await getUserData(newAccountNumber, "account_number");

    // Generate tokens
    const accessToken = jwt.sign(
      { id: user.id, account_number: user.account_number },
      secretKey,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign(
      { id: user.id, account_number: user.account_number },
      refreshSecretKey,
      { expiresIn: remember ? "7d" : "1h" }
    );

    // Set the refresh token in a cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : null, // 7 days or session-based
    });

    res
      .status(200)
      .json({ message: "Registration successful", accessToken, user });
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({ error: error.message });
  }
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
        return res.status(404).json({
          error:
            "There seems to be a problem with reading your account information. Try to sign out and back in and try again",
        });
      }
      if (senderRow.balance < amount) {
        return res
          .status(400)
          .json({ error: "Insufficient funds for the transaction" });
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
            return res.status(404).json({
              error:
                "Account with provided number doesn't exist. Make sure you typed in the account number correctly",
            });
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

                  const timestamp = new Date().toISOString();

                  const receiver_f_name = receiverRow.f_name;
                  const receiver_l_name = receiverRow.l_name;

                  // Log transaction
                  db.run(
                    `INSERT INTO "Transaction" (sender_account_number, receiver_account_number, amount, timestamp, type, description)
                    VALUES (?, ?, ?, ?, 'outgoing', 'Direct mvBank transfer to ${receiver_f_name} ${receiver_l_name}')`,
                    [sender, receiver, amount, timestamp],
                    (err) => {
                      if (err) {
                        return res
                          .status(500)
                          .json({ error: "Database error: " + err.message });
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
});

app.listen(port, () => {
  console.log(`mvBank Database server is running on port ${port}`);
});
