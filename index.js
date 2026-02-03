require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

const app = express();
const SECRET_KEY = process.env.JWT_SECRET;

if (!SECRET_KEY) {
  console.error("Error: JWT_SECRET is not defined in .env!");
  process.exit(1);
}

app.use(cors());
app.use(express.json());

// Load users from users.json
const usersFile = path.join(__dirname, "users.json");
let users = [];

if (fs.existsSync(usersFile)) {
  const data = fs.readFileSync(usersFile);
  users = JSON.parse(data);
} else {
  console.error("No users.json found! Run seed.js first.");
  process.exit(1);
}

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Login route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  const validPassword = user ? await bcrypt.compare(password, user.password) : false;

  if (!user || !validPassword) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// Protected Home route
app.get("/api/home", authenticateToken, async (req, res) => {
  try {
    const response = await axios.get("https://ipinfo.io/geo");
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch IP info", error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
