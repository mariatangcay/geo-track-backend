require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
const SECRET_KEY = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// ✅ In-memory user (Vercel-safe)
const users = [
  {
    id: 1,
    email: "test@example.com",
    password: bcrypt.hashSync("password123", 10),
  },
];

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// Protected route
app.get("/api/home", authenticateToken, async (req, res) => {
  try {
    const response = await axios.get("https://ipinfo.io/geo");
    res.json(response.data);
  } catch {
    res.status(500).json({ message: "Failed to fetch IP info" });
  }
});

module.exports = app; // ✅ REQUIRED for Vercel
