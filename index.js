const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    methods: ['GET', 'POST'],
  })
);
console.log(process.env.FRONTEND_URL);
const PORT = process.env.PORT || 3000;
app.use(express.json());

// Set up a database connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Test the database connection
async function testDbConnection() {
  try {
    const [rows] = await db.execute('SELECT 1');
    console.log('Database connection successful:', rows);
  } catch (error) {
    console.error('Database connection failed:', error.message);
  }
}

// Configure nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

async function sendTestEmail() {
  try {
    const info = await transporter.sendMail({
      from: '"Terminal-D" <yno-reply@dewaldbreed.co.za>', // Sender's email address
      to: 'dewaldbreed@gmail.com', // Replace with recipient's email
      subject: 'Test Email',
      text: 'This is a test email from your SMTP configuration.',
      html: '<p>This is a test email from your SMTP configuration.</p>',
    });

    console.log('Test email sent successfully:', info.messageId);
  } catch (error) {
    console.error('Error sending test email:', error);
  }
}

// Register new user
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString('hex');

  try {
    await db.execute(
      'INSERT INTO users (email, password_hash, verification_token) VALUES (?, ?, ?)',
      [email, hashedPassword, verificationToken]
    );

    // Send verification email
    const verificationLink = `${process.env.FRONTEND_URL}/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Verify your email',
      text: `Click the following link to verify your account: ${verificationLink}`,
    });

    res.status(201).json({
      message: `Registration successful. A verification email has been sent to ${email}. Please verify your email before logging in.`,
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ message: 'Email already exists.' });
    } else {
      res.status(500).json({ message: 'Internal server error.' });
    }
  }
});

// Verify user email
app.get('/verify', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: 'Verification token is required.' });
  }

  try {
    // Check if the token exists and is valid
    const [result] = await db.execute(
      'SELECT id FROM users WHERE verification_token = ? AND is_verified = 0',
      [token]
    );

    if (result.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired verification token.' });
    }

    // Update the user's status to verified
    await db.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', [
      result[0].id,
    ]);

    res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Login existing user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Both Email and password are required.' });
  }

  const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ message: 'Incorrect username or password.' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });

  const id = user.id;

  res.json({ token, id, email });
});

// Get User data from token
app.get('/user', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Query user data based on the decoded token
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
    const user = rows[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Exclude sensitive information like password_hash
    const { id, email } = user;
    res.json({ id, email });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
});

// Start the server
async function startServer() {
  // Call the test function
  await testDbConnection();
  // Call the function to send the test email
  sendTestEmail();
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
}

// Define a simple route
app.get('/test', (req, res) => {
  res.send('Hello, Node.js with MySQL!');
});

startServer();
