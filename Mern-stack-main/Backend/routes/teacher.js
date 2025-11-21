const express = require('express');
const router = express.Router();
const { authMiddleware, permit } = require('../middleware/auth');
const ClassSession = require('../models/ClassSession');
const Course = require('../models/Course');
const User = require('../models/User');

router.use(authMiddleware, permit('teacher'));

// GET /api/teacher/courses - return course documents for courses assigned to the logged-in teacher
router.get('/courses', async (req, res) => {
  try {
    // Ensure we read the authoritative user record from DB (token payload may not include courses)
    const username = req.user && req.user.username;
    if (!username) return res.status(401).json({ message: 'Unauthorized' });
    const teacherUser = await User.findOne({ username }).lean();
    if (!teacherUser) return res.status(404).json({ message: 'Teacher not found' });
    const codes = Array.isArray(teacherUser.courses) ? teacherUser.courses : [];
    if (codes.length === 0) return res.json({ courses: [] });
    const coursesFound = await Course.find({ code: { $in: codes } }).lean();
    // Return course documents for assigned codes. If a Course doc is missing, return a placeholder with code as name.
    const mapped = codes.map(code => {
      const found = coursesFound.find(c => c.code === code);
      return found ? found : { code, name: code };
    });
    res.json({ courses: mapped });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/teacher/generate - { courseId, durationMinutes }
router.post('/generate', async (req, res) => {
  const { courseId, durationMinutes } = req.body;
  const teacher = req.user;
  if (!courseId) return res.status(400).json({ message: 'courseId required' });

  const course = await Course.findOne({ code: courseId });
  const teacherUser = await User.findOne({ username: teacher.username });

  const duration = Number(durationMinutes) || 15;
  const expiry = Date.now() + duration * 60 * 1000;
  const sessionTimestamp = Date.now();

  const courseName = course ? course.name : courseId;
  const session = new ClassSession({ 
    courseId, 
    courseName,
    teacherId: teacher.username, 
    teacherName: teacherUser ? teacherUser.name : teacher.username, 
    timestamp: new Date(sessionTimestamp), 
    expiry, 
    active: true 
  });
  await session.save();

  const qrData = { courseId, teacherId: teacher.username, teacherName: teacherUser ? teacherUser.name : teacher.username, timestamp: sessionTimestamp, expiry };

  // Emit real-time notification to all students enrolled in this course
  const io = req.app.get('io');
  const Notification = require('../models/Notification');
  
  // Find all students enrolled in this course
  const enrolledStudents = await User.find({ 
    role: 'student', 
    courses: courseId 
  }).select('username');

  // Create notifications and emit socket events for each enrolled student
  for (const student of enrolledStudents) {
    const notification = new Notification({
      userId: student.username,
      type: 'class_created',
      title: 'New Class Started',
      message: `${courseName} class has started by ${teacherUser ? teacherUser.name : teacher.username}`,
      data: {
        courseId,
        courseName,
        teacherId: teacher.username,
        teacherName: teacherUser ? teacherUser.name : teacher.username,
        sessionId: session._id,
        expiry
      }
    });
    await notification.save();

    // Emit to specific student
    io.to(student.username).emit('class_created', {
      courseId,
      courseName,
      teacherId: teacher.username,
      teacherName: teacherUser ? teacherUser.name : teacher.username,
      sessionId: session._id,
      expiry,
      timestamp: sessionTimestamp
    });
  }

  // Also emit to all students room
  io.to('student').emit('new_class_session', {
    courseId,
    courseName,
    teacherId: teacher.username,
    teacherName: teacherUser ? teacherUser.name : teacher.username,
    sessionId: session._id,
    expiry,
    timestamp: sessionTimestamp
  });

  res.json({ ok: true, qrString: JSON.stringify(qrData), session });
});

// GET /api/teacher/active-sessions - Get all currently active sessions (accessible by students too)
router.get('/active-sessions', async (req, res) => {
  try {
    const now = Date.now();
    // Find sessions that haven't expired yet
    const activeSessions = await ClassSession.find({
      expiry: { $gt: now },
      active: true
    }).sort({ timestamp: -1 });

    res.json({ sessions: activeSessions });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/teacher/check-global-session - Check if any session is active globally
router.get('/check-global-session', async (req, res) => {
  const now = Date.now();
  const oneHourThirtyMin = 90 * 60 * 1000; // 1 hour 30 minutes in milliseconds
  
  // Check for any session by any teacher within last 1.5 hours
  const recentSession = await ClassSession.findOne({ 
    createdAt: { $gte: new Date(now - oneHourThirtyMin) }
  }).sort({ createdAt: -1 });
  
  if (recentSession) {
    const sessionTime = new Date(recentSession.createdAt).getTime();
    const timeDiff = (now - sessionTime) / (1000 * 60); // minutes
    const remainingMinutes = Math.ceil(90 - timeDiff);
    
    return res.json({ 
      hasActiveSession: true,
      remainingMinutes: remainingMinutes,
      session: recentSession
    });
  }
  
  return res.json({ hasActiveSession: false });
});

// GET /api/teacher/current?courseId=...
router.get('/current', async (req, res) => {
  const { courseId } = req.query;
  const teacher = req.user;
  const now = Date.now();
  const oneHourThirtyMin = 90 * 60 * 1000; // 1 hour 30 minutes in milliseconds
  
  // Check for any active session by this teacher within last 1.5 hours
  const recentSession = await ClassSession.findOne({ 
    teacherId: teacher.username,
    createdAt: { $gte: new Date(now - oneHourThirtyMin) }
  }).sort({ createdAt: -1 });
  
  if (recentSession) {
    return res.json({ 
      qrString: null, 
      session: recentSession,
      hasRecentSession: true 
    });
  }
  
  const q = { active: true };
  if (courseId) q.courseId = courseId;

  const session = await ClassSession.findOne(q).sort({ createdAt: -1 });
  if (!session) return res.json({ qr: null });
  if (now > session.expiry) {
    session.active = false;
    await session.save();
    return res.json({ qr: null });
  }

  const qrData = { courseId: session.courseId, teacherId: session.teacherId, teacherName: session.teacherName, timestamp: session.timestamp, expiry: session.expiry };
  res.json({ qrString: JSON.stringify(qrData), session });
});

// POST /api/teacher/no-class { courseId }
router.post('/no-class', async (req, res) => {
  const { courseId } = req.body;
  const teacher = req.user;
  if (!courseId) return res.status(400).json({ message: 'courseId required' });

  // Mark by creating an inactive session with noClass flag by expiry = 0 and active=false
  const session = new ClassSession({ courseId, teacherId: teacher.username, teacherName: teacher.name, expiry: 0, active: false });
  await session.save();
  res.json({ ok: true });
});

// GET /api/teacher/students/:courseId - get all students enrolled in a course
router.get('/students/:courseId', async (req, res) => {
  try {
    const { courseId } = req.params;
    const students = await User.find({ role: 'student', courses: courseId }).select('-password').lean();
    res.json({ students });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/teacher/mark-attendance - manually mark attendance { studentId, courseId, date, status }
router.post('/mark-attendance', async (req, res) => {
  try {
    const { studentId, courseId, date, status } = req.body;
    const teacher = req.user;
    
    if (!studentId || !courseId || !date || !status) {
      return res.status(400).json({ message: 'studentId, courseId, date, and status required' });
    }

    const Attendance = require('../models/Attendance');
    const student = await User.findOne({ username: studentId });
    if (!student) return res.status(404).json({ message: 'Student not found' });

    const course = await Course.findOne({ code: courseId });
    
    // Check if attendance already exists for this date
    const existing = await Attendance.findOne({ studentId, courseId, date });
    
    if (existing) {
      // Update existing attendance
      existing.status = status;
      existing.timestamp = new Date();
      await existing.save();
      return res.json({ ok: true, record: existing, updated: true });
    } else {
      // Create new attendance record
      const record = new Attendance({
        studentId: student.username,
        studentName: student.name,
        rollNo: student.rollNo,
        courseId,
        courseName: course ? course.name : courseId,
        teacherId: teacher.username,
        teacherName: teacher.name,
        date,
        timestamp: new Date(),
        status
      });
      await record.save();
      return res.json({ ok: true, record, updated: false });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
