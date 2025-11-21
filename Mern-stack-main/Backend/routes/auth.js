const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const User = require('../models/User');

dotenv.config();
const jwtSecret = process.env.JWT_SECRET || 'secret_dev_key';

// POST /api/auth/login
router.post('/login', async (req, res) => {
  console.log('Login request body:', req.body);
  const { username, password } = req.body;
  if (!username || !password) {
    console.log('Login validation failed:', { username, password });
    return res.status(400).json({ message: 'username and password required' });
  }

  // Accept login by username OR rollNo OR email
  const identifier = username;
  let user = await User.findOne({ $or: [ { username: identifier }, { rollNo: identifier }, { email: identifier } ] });

  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  // Passwords may be stored plain (for compatibility with existing frontend); support both
  const passwordMatches = (user.password === password) || bcrypt.compareSync(password, user.password);
  console.log('Found user. username:', user.username, 'passwordMatches:', passwordMatches);
  if (!passwordMatches) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id, username: user.username, role: user.role, name: user.name }, jwtSecret, { expiresIn: '12h' });

  res.json({ token, user: { username: user.username, role: user.role, name: user.name, rollNo: user.rollNo, courses: user.courses } });
});

// GET /api/auth/me - return current user based on token
router.get('/me', require('../middleware/auth').authMiddleware, async (req, res) => {
  try {
    const User = require('../models/User');
    const username = req.user.username;
    const user = await User.findOne({ username }).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Optional: signup
router.post('/signup', async (req, res) => {
  console.log('Signup request received:', req.body);
  let { username, password, role, name, rollNo, email } = req.body;
  if ((!username && !email) || !password || !role) {
    console.log('Validation failed:', { username, email, password, role });
    return res.status(400).json({ message: 'username/email, password and role required' });
  }

  // Remove all spaces from username, email, and rollNo
  if (username) username = username.replace(/\s+/g, '');
  if (email) email = email.replace(/\s+/g, '');
  if (rollNo) rollNo = rollNo.replace(/\s+/g, '');

  // If username not provided, derive from email
  if (!username && email) {
    username = email.split('@')[0];
  }

  // Auto-generate email if not provided based on role
  if (!email) {
    if (role === 'student' && rollNo) {
      email = `${rollNo}@uog.edu.pk`;
    } else if (role === 'teacher' || role === 'admin') {
      email = `${username}@uog.edu.pk`;
    }
  }

  // Check uniqueness by username, email, or rollNo
  try {
    const query = { $or: [ { username } ] };
    if (email) query.$or.push({ email });
    if (rollNo) query.$or.push({ rollNo });
    
    const exists = await User.findOne(query);
    if (exists) {
      console.log('User exists:', exists);
      if (exists.username === username) {
        return res.status(400).json({ message: 'Username already exists' });
      }
      if (exists.email === email) {
        return res.status(400).json({ message: 'Email already exists' });
      }
      if (exists.rollNo === rollNo) {
        return res.status(400).json({ message: 'Roll number already exists' });
      }
      return res.status(400).json({ message: 'User with same credentials exists' });
    }

    const hashed = bcrypt.hashSync(password, 8);
    const user = new User({ username, email, password: hashed, role, name, rollNo, courses: [] });
    console.log('Trying to save user:', user);
      await user.save();
    console.log('User saved successfully:', user._id);
    res.json({ ok: true, user });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({ message: `${field} already exists` });
    }
    res.status(500).json({ message: error.message || 'Failed to create user' });
  }
});

module.exports = router;
