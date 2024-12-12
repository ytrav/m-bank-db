const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const { Pool } = require("pg");
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
app.use(bodyParser.json());
const port = 3000;
const allowedOrigins = ["https://bank.maevetopia.fun", "http://localhost:5173"];

app.use(
  cors({
    credentials: true,
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
  })
);
app.use(express.json());
app.use(cookieParser());
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect((err) => {
  if (err) {
    console.error("Could not connect to PostgreSQL database", err);
  } else {
    console.log("Connected to PostgreSQL database");
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

const getUserData = async (identifier, type = "id") => {
  const column = type === "id" ? "id" : "account_number";

  try {
    // Get user and card data
    const userResult = await db.query(
      `SELECT u.*,
              c.number AS card_number,
              c.expiry_date AS card_expiry_date
       FROM "User" u
       LEFT JOIN "card" c ON u.id = c.owner_id
       WHERE u.${column} = $1`,
      [identifier]
    );

    const userRow = userResult.rows[0];

    if (!userRow) {
      throw new Error(
        "Incorrect credentials, make sure you entered the correct account number and password"
      );
    }

    // Get transaction data
    const transactionResult = await db.query(
      `SELECT *,
              CASE
                WHEN sender_account_number = $1 THEN 'SUBTRACTION'
                WHEN receiver_account_number = $1 THEN 'ADDITION'
              END AS transaction_type
       FROM "Transaction"
       WHERE sender_account_number = $1 OR receiver_account_number = $1`,
      [userRow.account_number]
    );

    return {
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
      transactions: transactionResult.rows.reverse().map((tx) => ({
        ...tx,
        personal_type:
          tx.sender_account_number === userRow.account_number
            ? "subtraction"
            : "addition",
      })),
    };
  } catch (err) {
    throw new Error(`Database error: ${err.message}`);
  }
};

const getUserPassword = async (account_number) => {
  try {
    const result = await db.query(
      'SELECT password FROM "User" WHERE account_number = $1',
      [account_number]
    );

    if (result.rows.length === 0) {
      throw new Error(
        "Incorrect credentials, make sure you entered the correct account number and password"
      );
    }

    return result.rows[0].password;
  } catch (err) {
    throw new Error(`Database error: ${err.message}`);
  }
};

app.get("/users", async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM "User"');

    res.json({
      message: "success",
      data: result.rows,
    });
  } catch (err) {
    res.status(400).json({ error: `Database error: ${err.message}` });
  }
});

app.get("/users/:id", async (req, res) => {
  const id = req.params.id;
  try {
    const result = await db.query("SELECT * FROM User WHERE id = $1", [id]);

    res.json({
      message: "success",
      data: result.rows,
    });
  } catch (err) {
    res.status(400).json({ error: `Database error: ${err.message}` });
  }
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
    res.status(500).json({ error: error.message });
  }
});

// Updated /refresh route
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

app.post("/generate-invite", async (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const result = await db.query('SELECT * FROM "User" WHERE id = $1', [1]);
    const row = result.rows[0];

    if (!row) {
      return res.status(404).json({ error: "User not found" });
    }

    if (bcrypt.compareSync(password, row.password)) {
      const inviteCode = uuidv4();
      await db.query(
        'INSERT INTO "invite_codes" (code) VALUES ($1) RETURNING id',
        [inviteCode]
      );
      res.status(200).json({ inviteCode });
    } else {
      res.status(401).json({ error: "Invalid password" });
    }
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

app.post("/register", async (req, res) => {
  const { f_name, l_name, gender, inviteCode, password, remember } = req.body;

  if (!f_name || !l_name || !gender || !inviteCode || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Check if the invite code is valid
    const inviteCodeResult = await db.query(
      'SELECT * FROM "invite_codes" WHERE code = $1 AND is_used = false',
      [inviteCode]
    );

    if (inviteCodeResult.rows.length === 0) {
      throw new Error(
        "Invite code you enter is either invalid or has been used already"
      );
    }

    const hashedPassword = bcrypt.hashSync(password, 12);
    const newAccountNumber = Math.floor(Math.random() * 1e8)
      .toString()
      .padStart(8, "0");

    // Insert the new user
    const userResult = await db.query(
      'INSERT INTO "User" (f_name, l_name, gender, account_number, password) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [f_name, l_name, gender, newAccountNumber, hashedPassword]
    );

    const userId = userResult.rows[0].id;

    // Mark the invite code as used
    await db.query('UPDATE "invite_codes" SET is_used = true WHERE code = $1', [
      inviteCode,
    ]);

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

app.post("/transfer", async (req, res) => {
  const { sender, receiver, amount } = req.body;

  if (!sender || !receiver || !amount) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Check if sender account exists
    const senderResult = await db.query(
      'SELECT * FROM "User" WHERE account_number = $1',
      [sender]
    );

    const senderRow = senderResult.rows[0];
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
    const receiverResult = await db.query(
      'SELECT * FROM "User" WHERE account_number = $1',
      [receiver]
    );

    const receiverRow = receiverResult.rows[0];
    if (!receiverRow) {
      return res.status(404).json({
        error:
          "Account with provided number doesn't exist. Make sure you typed in the account number correctly",
      });
    }

    // Start transaction
    await db.query("BEGIN");

    // Deduct amount from sender
    await db.query(
      'UPDATE "User" SET balance = balance - $1 WHERE account_number = $2',
      [amount, sender]
    );

    // Add amount to receiver
    await db.query(
      'UPDATE "User" SET balance = balance + $1 WHERE account_number = $2',
      [amount, receiver]
    );

    const timestamp = new Date().toISOString();
    const description = `Direct mvBank transfer to ${receiverRow.f_name} ${receiverRow.l_name}`;

    // Log transaction
    await db.query(
      `INSERT INTO "Transaction" (sender_account_number, receiver_account_number, amount, timestamp, type, description)
       VALUES ($1, $2, $3, $4, 'outgoing', $5) RETURNING id`,
      [sender, receiver, amount, timestamp, description]
    );

    // Commit transaction
    await db.query("COMMIT");

    res.status(200).json({ message: "Transfer successful" });
  } catch (error) {
    await db.query("ROLLBACK");
    console.error("Transfer error:", error.message);
    res.status(500).json({ error: `Database error: ${error.message}` });
  }
});

app.listen(port, () => {
  console.log(`mvBank Database server is running on port ${port}`);
});
