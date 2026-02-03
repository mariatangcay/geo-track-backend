const fs = require('fs');
const bcrypt = require('bcrypt');

// Example: create a users.json database file
const users = [
  {
    email: "test@example.com",
    password: bcrypt.hashSync("password123", 10) // hashed password
  }
];

// Save to users.json
fs.writeFileSync('users.json', JSON.stringify(users, null, 2));

console.log("Seeder complete. User created:", users[0].email);
