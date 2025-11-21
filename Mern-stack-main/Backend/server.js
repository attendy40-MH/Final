const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

// Better error logging
mongoose.set('debug', true);

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:5173', 'http://localhost:3001', 'http://localhost:3002', 'http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/qr_attendance';

// Import routes
const authRoutes = require('./routes/auth');

// Connect to MongoDB with better error handling
const adminRoutes = require('./routes/admin');
const teacherRoutes = require('./routes/teacher');
const attendanceRoutes = require('./routes/attendance');
const coursesRoutes = require('./routes/courses');
const notificationRoutes = require('./routes/notifications');

// Make io accessible to routes
app.set('io', io);

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/teacher', teacherRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/courses', coursesRoutes);
app.use('/api/notifications', notificationRoutes);

app.get('/', (req, res) => res.json({ ok: true, message: 'QR Attendance Backend' }));

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  // Authenticate socket connection
  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      socket.userId = decoded.username;
      socket.userRole = decoded.role;
      socket.join(socket.userId); // Join room with username
      socket.join(socket.userRole); // Join room with role (student/teacher)
      console.log(`User ${socket.userId} (${socket.userRole}) authenticated`);
      socket.emit('authenticated', { success: true });
    } catch (err) {
      console.error('Socket authentication failed:', err.message);
      socket.emit('authenticated', { success: false, message: 'Invalid token' });
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });