import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';

// Initialize dotenv and environment variables
dotenv.config();

// Initialize Express and cors
const app = express();

const corsOptions = {
  origin: JSON.parse(process.env.FRONTEND_URL),
  credentials: true,
};

app.use(cors(corsOptions));

// Handle preflight (OPTIONS) requests
app.options('*', cors(corsOptions));

app.use(express.json());

// View engine for response pages
app.set('view engine', 'ejs');
app.set('views', path.join('views'));

// Set up a database connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Define the port to run the app
const PORT = process.env.PORT || 3000;

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

// test SMTP
async function sendTestEmail() {
  try {
    const info = await transporter.sendMail({
      from: '"Terminal-D" <noreply@dewaldbreed.co.za>', // Sender's email address
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
// #region FUNCTIONS

// Register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate inputs
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      data: null,
      error: { message: 'Email and password are required.' },
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      success: false,
      data: null,
      error: { message: 'Password must be at least 8 characters long.' },
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString('hex');

  try {
    // Insert new user into the database
    await db.execute(
      'INSERT INTO users (email, password_hash, verification_token) VALUES (?, ?, ?)',
      [email, hashedPassword, verificationToken]
    );

    // Send verification email
    const verificationLink = `${process.env.API_URL}/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Verify your email',
      text: `Click the following link to verify your account: ${verificationLink}`,
    });

    return res.status(201).json({
      success: true,
      data: {
        message: `Registration successful. A verification email has been sent to ${email}. Please verify your email before logging in.`,
      },
      error: null,
    });
  } catch (error) {
    console.error('Error during registration:', error);

    // Handle duplicate email error
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({
        success: false,
        data: null,
        error: { message: 'Email already exists.' },
      });
    }

    // Handle SMTP or other internal errors
    return res.status(500).json({
      success: false,
      data: null,
      error: { message: 'Internal server error. Please try again later.' },
    });
  }
});

// Verify user email
app.get('/verify', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).render('error', { message: 'Verification token is required.' });
  }

  try {
    // Check if the token exists and is valid
    const [result] = await db.execute(
      'SELECT id FROM users WHERE verification_token = ? AND is_verified = 0',
      [token]
    );

    if (result.length === 0) {
      return res.status(400).render('error', { message: 'Invalid or expired verification token.' });
    }

    // Update the user's status to verified
    await db.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', [
      result[0].id,
    ]);

    res
      .status(200)
      .render('success', { message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).render('error', { message: 'Internal server error.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check for missing fields
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      data: null,
      error: { message: 'Both Email and password are required.' },
    });
  }

  try {
    // Query the user from the database
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    // Check if user exists and the password is correct
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        success: false,
        data: null,
        error: { message: 'Invalid username or password.' },
      });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    // Respond with user details and token
    return res.json({
      success: true,
      data: { token, id: user.id, email: user.email },
      error: null,
    });
  } catch (error) {
    // Handle unexpected server errors
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      data: null,
      error: { message: 'An internal server error occurred.' },
    });
  }
});

// Get User data from token
app.get('/user', async (req, res) => {
  const authHeader = req.headers.authorization;

  // Check for missing or improperly formatted authorization header
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      data: null,
      error: { message: 'Unauthorized. Bearer token is required.' },
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Query user data based on the decoded token
    const [rows] = await db.execute('SELECT id, email FROM users WHERE id = ?', [decoded.id]);
    const user = rows[0];

    if (!user) {
      return res.status(404).json({
        success: false,
        data: null,
        error: { message: 'User not found.' },
      });
    }

    // Return user data
    return res.status(200).json({
      success: true,
      data: { id: user.id, email: user.email },
      error: null,
    });
  } catch (err) {
    // Handle invalid or expired token errors
    return res.status(401).json({
      success: false,
      data: null,
      error: { message: 'Invalid or expired token.' },
    });
  }
});

// Health Check
app.get('/health', (req, res) => {
  res.status(200).send('Healthy');
});

// #endregion

// Start the server
async function startServer() {
  await testDbConnection();

  // sendTestEmail();

  app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
  });
}

startServer();
