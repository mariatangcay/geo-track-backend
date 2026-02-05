const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";

app.use(cors());
app.use(express.json());

// ===== USER SEEDER =====
const users = [
  {
    id: 1,
    email: "test@example.com",
    password: bcrypt.hashSync("password123", 10),
  },
];

// ===== AUTH MIDDLEWARE =====
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

// ===== LOGIN API =====
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


// ===== HOME API (CLIENT IP GEOLOCATION) =====
app.get("/api/home", authenticateToken, async (req, res) => {
  try {
    // Try to get IP from standard headers first (works on Vercel & proxies)
    const forwarded = req.headers["x-forwarded-for"];
    let clientIp = forwarded ? forwarded.split(",")[0] : null;

    // Fallback to connection remote address
    if (!clientIp) {
      clientIp = req.socket.remoteAddress;
    }

    // If using curl or localhost, ipinfo may require 'json' endpoint for private IPs
    const ipQuery = clientIp === "::1" || clientIp.startsWith("127.") ? "" : clientIp;

    const response = await axios.get(`https://ipinfo.io/${ipQuery}/geo?token=YOUR_IPINFO_TOKEN`);

    // Return client IP info
    res.json(response.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch IP info" });
  }
});


/* ===== LOCAL SERVER START (ONLY FOR LOCAL TESTING) =====
if (require.main === module) {
  const PORT = process.env.PORT || 8000;
  app.listen(PORT, () => {
    console.log(`Server running locally on http://localhost:${PORT}`);
  });
}
*/

// ===== VERCEL SERVERLESS EXPORT =====
module.exports = (req, res) => {
  app(req, res);
};
