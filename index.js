import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config();

const app = express();
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

    res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ message: 'Email already exists.' });
    } else {
      res.status(500).json({ message: 'Internal server error.' });
    }
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
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });

  res.json({ token });
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
