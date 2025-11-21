import React, { useState, useEffect, useRef } from 'react';
import jsQR from 'jsqr';
import { system } from '../system'; 
import './StudentDashboard.css';
import { io } from 'socket.io-client';

const StudentDashboard = () => {
  const [activeSection, setActiveSection] = useState('scan');
  const [classStatus, setClassStatus] = useState('');
  const [scanResult, setScanResult] = useState('');
  const [monthlyReport, setMonthlyReport] = useState([]);
  const [todayAttendance, setTodayAttendance] = useState([]);
  const [reportMonth, setReportMonth] = useState('');
  const [manualQR, setManualQR] = useState('');
  const [selectedReportCourse, setSelectedReportCourse] = useState('');
  const [courses, setCourses] = useState([]);
  const [isAuthChecking, setIsAuthChecking] = useState(true);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showNotifications, setShowNotifications] = useState(false);
  const [activeSessions, setActiveSessions] = useState([]);
  
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const qrCheckIntervalRef = useRef(null);
  const scannerRef = useRef(null);
  const socketRef = useRef(null);
  const sessionIntervalRef = useRef(null);

  // Current user state (refreshable from server)
  const [currentUser, setCurrentUser] = useState(system.getCurrentUser() || {});

  useEffect(() => {
    // Require real login for student portal. If no token present, redirect to /login.
    (async () => {
      // Check authentication
      if (!system.isAuthenticated()) {
        setIsAuthChecking(true);
        window.location.replace('/login');
        return;
      }

      const token = system.getToken();
      const user = system.getCurrentUser();
      
      // Verify user role
      if (!user || user.role !== 'student') {
        setIsAuthChecking(true);
        system.clearAuth();
        window.location.replace('/login');
        return;
      }

      setIsAuthChecking(false);

      // Prevent back button after logout
      window.history.pushState(null, '', window.location.href);
      window.onpopstate = function() {
        if (!system.isAuthenticated()) {
          window.location.replace('/login');
        }
      };

      // Set default month for report
      const now = new Date();
      setReportMonth(now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0'));

      // Load initial section
      showSection('scan');

      // Refresh current user from server so assignments updated by admin are reflected
      try {
        const user = await system.refreshCurrentUser();
        if (user) setCurrentUser(user);
      } catch (e) {
        console.error('Failed to refresh current user', e);
      }

      // Load courses from backend (public endpoint)
      try {
        const resp = await fetch('http://localhost:5000/api/courses');
        if (resp.ok) {
          const data = await resp.json();
          setCourses(data && data.courses ? data.courses : []);
        } else {
          console.warn('Failed to fetch courses', resp.status);
          alert('Failed to load courses from server. Please ensure backend is running.');
          setCourses([]);
        }
      } catch (e) {
        console.error('Failed to load courses', e);
        alert('Cannot connect to server. Please ensure backend server is running on http://localhost:5000');
        setCourses([]);
      }

      // Initialize Socket.io
      const socket = io('http://localhost:5000');
      socketRef.current = socket;

      socket.on('connect', () => {
        console.log('Socket connected');
        // Authenticate socket connection
        socket.emit('authenticate', token);
      });

      socket.on('authenticated', (data) => {
        if (data.success) {
          console.log('Socket authenticated');
        } else {
          console.error('Socket authentication failed');
        }
      });

      // Listen for new class creation notifications
      socket.on('class_created', (data) => {
        console.log('New class created:', data);
        // Show notification
        showClassNotification(data);
        // Add to active sessions
        setActiveSessions(prev => {
          const exists = prev.find(s => s.sessionId === data.sessionId);
          if (!exists) {
            return [data, ...prev];
          }
          return prev;
        });
        // Refresh notifications and sessions
        fetchUnreadCount();
        fetchActiveSessions();
      });

      socket.on('new_class_session', (data) => {
        console.log('New class session:', data);
        const user = system.getCurrentUser();
        // Update active sessions if student is enrolled
        if (user.courses && user.courses.includes(data.courseId)) {
          setActiveSessions(prev => {
            // Avoid duplicates
            const exists = prev.find(s => s.sessionId === data.sessionId);
            if (!exists) {
              return [data, ...prev];
            }
            return prev;
          });
        }
      });

      socket.on('disconnect', () => {
        console.log('Socket disconnected');
      });

      // Fetch active sessions on load
      fetchActiveSessions();
      
      // Fetch notifications
      fetchNotifications();
      fetchUnreadCount();

      // Refresh active sessions every 10 seconds
      sessionIntervalRef.current = setInterval(() => {
        fetchActiveSessions();
      }, 10000);

      // Request notification permission
      if (Notification.permission === 'default') {
        Notification.requestPermission();
      }

      // Cleanup will be handled below by returning a function from outer effect
    })();

    return () => {
      // Cleanup intervals and camera
      clearInterval(qrCheckIntervalRef.current);
      if (sessionIntervalRef.current) clearInterval(sessionIntervalRef.current);
      stopCamera();
      // Disconnect socket
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  const showSection = (section) => {
    setActiveSection(section);
    
    if (section === 'scan') {
      checkClassStatus();
      startQRCheckInterval();
      initializeCamera();
    } else if (section === 'today') {
      loadTodayAttendance();
    } else {
      clearInterval(qrCheckIntervalRef.current);
      stopCamera();
    }
  };

  const startQRCheckInterval = () => {
    clearInterval(qrCheckIntervalRef.current);
    qrCheckIntervalRef.current = setInterval(() => {
      checkClassStatus();
    }, 3000);
  };

  const initializeCamera = () => {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showCameraError('Camera not supported in this browser. Please use manual entry.');
      return;
    }
    startCamera();
  };

  const startCamera = async () => {
    const video = videoRef.current;
    if (!video) return;

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ 
        video: { 
          facingMode: 'environment',
          width: { ideal: 1280 },
          height: { ideal: 720 }
        } 
      });
      
      video.srcObject = stream;
      await video.play();
      startQRScanning(video);
    } catch (error) {
      console.error('Camera error:', error);
      showCameraError('Unable to access camera. Please use manual entry below.');
    }
  };

  const stopCamera = () => {
    const video = videoRef.current;
    if (video && video.srcObject) {
      const tracks = video.srcObject.getTracks();
      tracks.forEach(track => track.stop());
      video.srcObject = null;
    }
    
    if (scannerRef.current) {
      scannerRef.current = null;
    }
  };

  const startQRScanning = (video) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const context = canvas.getContext('2d');
    
    const scanFrame = () => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert",
        });
        
        if (code) {
          handleScannedQR(code.data);
          return;
        }
      }
      
      if (scannerRef.current !== null) {
        requestAnimationFrame(scanFrame);
      }
    };
    
    scannerRef.current = { stop: () => { scannerRef.current = null; } };
    scanFrame();
  };

  const handleScannedQR = (qrData) => {
    stopCamera();
    setScanResult('<div class="alert alert-info"><span class="loading"></span> Processing QR code...</div>');

    setTimeout(async () => {
      try {
        const resp = await system.markAttendance(qrData);
        if (resp && resp.ok) {
          setScanResult(`<div class="alert alert-success">✅ Attendance marked</div>`);
        } else {
          const msg = (resp && resp.message) ? resp.message : 'Failed to mark attendance';
          setScanResult(`<div class="alert alert-error">❌ ${msg}</div>`);
        }

        setTimeout(() => {
          loadTodayAttendance();
          checkClassStatus();
          setTimeout(() => {
            startCamera();
          }, 3000);
        }, 1000);
      } catch (err) {
        setScanResult(`<div class="alert alert-error">❌ ${err.message || 'Failed to mark attendance'}</div>`);
        setTimeout(() => {
          startCamera();
        }, 3000);
      }
    }, 1000);
  };

  const showCameraError = (message) => {
    setClassStatus(prev => prev + `
      <div class="camera-error">
        <div class="error-icon">📷</div>
        <h3>Camera Unavailable</h3>
        <p>${message}</p>
      </div>
    `);
  };

  const fetchActiveSessions = async () => {
    try {
      const token = system.getToken();
      if (!token) return;

      const resp = await fetch('http://localhost:5000/api/teacher/active-sessions', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await resp.json();
      if (resp.ok && data.sessions) {
        const user = system.getCurrentUser();
        // Filter sessions for enrolled courses
        const enrolledSessions = data.sessions.filter(session => 
          user.courses && user.courses.includes(session.courseId)
        );
        console.log('Active sessions:', enrolledSessions);
        setActiveSessions(enrolledSessions);
      }
    } catch (err) {
      console.error('Error fetching active sessions', err);
    }
  };

  const fetchNotifications = async () => {
    try {
      const token = system.getToken();
      if (!token) return;

      const resp = await fetch('http://localhost:5000/api/notifications', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await resp.json();
      if (resp.ok && data.notifications) {
        setNotifications(data.notifications);
      }
    } catch (err) {
      console.error('Error fetching notifications', err);
    }
  };

  const fetchUnreadCount = async () => {
    try {
      const token = system.getToken();
      if (!token) return;

      const resp = await fetch('http://localhost:5000/api/notifications/unread', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await resp.json();
      if (resp.ok) {
        setUnreadCount(data.count || 0);
      }
    } catch (err) {
      console.error('Error fetching unread count', err);
    }
  };

  const showClassNotification = (data) => {
    // Show browser notification
    if (Notification.permission === 'granted') {
      new Notification('New Class Started', {
        body: `${data.courseName} class has started by ${data.teacherName}. Click to mark attendance.`,
        icon: '/class-icon.png'
      });
    }

    // Show in-app alert
    alert(`📚 ${data.courseName} class has started by ${data.teacherName}! Scan QR code to mark attendance.`);
  };

  const markNotificationRead = async (id) => {
    try {
      const token = system.getToken();
      if (!token) return;

      await fetch(`http://localhost:5000/api/notifications/${id}/read`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      fetchNotifications();
      fetchUnreadCount();
    } catch (err) {
      console.error('Error marking notification as read', err);
    }
  };

  const checkClassStatus = async () => {
    const coursesList = courses || [];
    const today = new Date().toISOString().split('T')[0];
    
    let statusHTML = '';
    const enrolledCourses = coursesList.filter(course => 
      currentUser.courses && currentUser.courses.includes(course.code)
    );
    
    if (enrolledCourses.length === 0) {
      statusHTML = `<div class="alert alert-warning">You are not enrolled in any courses. Please contact admin.</div>`;
      setClassStatus(statusHTML);
      return;
    }

    // Only show status if there are active sessions
    if (activeSessions.length > 0) {
      // Active sessions will be shown in the separate active-sessions component
      statusHTML = '';
    } else {
      statusHTML = `<div class="alert alert-warning">📚 No active classes at the moment.</div>`;
    }
    
    setClassStatus(statusHTML);
  };

  const submitQRCode = async () => {
    if (!manualQR.trim()) {
      alert('Please enter QR code data');
      return;
    }

    try {
      JSON.parse(manualQR);
    } catch (error) {
      setScanResult('<div class="alert alert-error">❌ Invalid QR code format. Please check and try again.</div>');
      return;
    }

    try {
      const resp = await system.markAttendance(manualQR);
      if (resp && resp.ok) {
        setScanResult(`<div class="alert alert-success">✅ Attendance marked</div>`);
      } else {
        const msg = (resp && resp.message) ? resp.message : 'Failed to mark attendance';
        setScanResult(`<div class="alert alert-error">❌ ${msg}</div>`);
      }
      setManualQR('');
      
      setTimeout(() => {
        loadTodayAttendance();
        checkClassStatus();
      }, 1000);
    } catch (err) {
      setScanResult(`<div class="alert alert-error">❌ ${err.message || 'Failed to submit QR'}</div>`);
    }
  };

  const loadMonthlyReport = async () => {
    if (!selectedReportCourse) {
      alert('Please select a course');
      return;
    }

    try {
      const token = system.getToken();
      if (!token) {
        alert('Please login first');
        return;
      }

      // Get all attendance records for this course
      const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${selectedReportCourse}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const attendanceData = await attendanceResp.json();
      
      let userAttendance = attendanceData.records.filter(record => record.studentId === currentUser.username);
      
      if (userAttendance.length === 0) {
        const courseName = courses.find(c => c.code === selectedReportCourse)?.name || selectedReportCourse;
        setMonthlyReport([{
          isPlaceholder: true,
          message: `📊 No attendance records found for ${courseName}`
        }]);
        return;
      }

      const reportData = userAttendance
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .map(record => {
          const course = courses.find(c => c.code === record.courseId);
          const time = new Date(record.timestamp).toLocaleTimeString();
          return {
            date: record.date,
            course: course ? course.name : record.courseId,
            courseCode: record.courseId,
            status: record.status,
            time: time
          };
        });

      setMonthlyReport(reportData);
    } catch (error) {
      console.error('Error loading attendance:', error);
      alert('Failed to load attendance report');
    }
  };

  const downloadMonthlyPDF = () => {
    if (monthlyReport.length === 0 || monthlyReport[0]?.isPlaceholder) {
      alert('No data to download');
      return;
    }

    // Calculate statistics
    const totalDays = monthlyReport.length;
    const presentDays = monthlyReport.filter(r => r.status === 'present').length;
    const absentDays = monthlyReport.filter(r => r.status === 'absent').length;
    const attendancePercentage = totalDays > 0 ? ((presentDays / totalDays) * 100).toFixed(1) : '0.0';

    // Get selected course name
    const selectedCourseName = selectedReportCourse ? 
      (courses.find(c => c.code === selectedReportCourse)?.name || selectedReportCourse) : 
      'All Courses';

    // Group by course
    const courseWiseData = {};
    monthlyReport.forEach(record => {
      if (!courseWiseData[record.courseCode]) {
        courseWiseData[record.courseCode] = {
          courseName: record.course,
          present: 0,
          absent: 0,
          total: 0
        };
      }
      courseWiseData[record.courseCode].total++;
      if (record.status === 'present') {
        courseWiseData[record.courseCode].present++;
      } else {
        courseWiseData[record.courseCode].absent++;
      }
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Monthly Attendance Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          h1 { color: #2563eb; text-align: center; }
          h2 { color: #4F6EBE; margin-top: 30px; }
          .header { text-align: center; margin-bottom: 30px; }
          .student-info { background: #f0f9ff; padding: 15px; border-radius: 8px; margin: 20px 0; }
          .summary { display: flex; justify-content: space-around; margin: 20px 0; }
          .stat-box { text-align: center; padding: 15px; background: #e0f2fe; border-radius: 8px; }
          table { width: 100%; border-collapse: collapse; margin: 20px 0; }
          th { background: #2563eb; color: white; padding: 10px; text-align: left; }
          td { border: 1px solid #ddd; padding: 8px; }
          tr:nth-child(even) { background: #f9fafb; }
          .present { color: #059669; font-weight: bold; }
          .absent { color: #dc2626; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>📊 Complete Attendance Report</h1>
          <h2>${selectedCourseName}</h2>
          <p>Generated on: ${new Date().toLocaleString()}</p>
        </div>

        <div class="student-info">
          <h3>Student Information</h3>
          <p><strong>Name:</strong> ${currentUser.name}</p>
          <p><strong>Roll No:</strong> ${currentUser.rollNo || currentUser.username}</p>
          <p><strong>Course:</strong> ${selectedCourseName} (${selectedReportCourse})</p>
        </div>

        <div class="summary">
          <div class="stat-box">
            <strong style="font-size: 24px;">${totalDays}</strong><br>Total Sessions
          </div>
          <div class="stat-box">
            <strong style="font-size: 24px; color: #059669;">${presentDays}</strong><br>Present
          </div>
          <div class="stat-box">
            <strong style="font-size: 24px; color: #dc2626;">${absentDays}</strong><br>Absent
          </div>
          <div class="stat-box">
            <strong style="font-size: 24px; color: #2563eb;">${attendancePercentage}%</strong><br>Attendance
          </div>
        </div>

        <h2>Detailed Attendance Records</h2>
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Course</th>
              <th>Status</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            ${monthlyReport.map(record => `
            <tr>
              <td>${record.date}</td>
              <td>${record.course}</td>
              <td class="${record.status}">${record.status.toUpperCase()}</td>
              <td>${record.time}</td>
            </tr>
            `).join('')}
          </tbody>
        </table>
      </body>
      </html>
    `;

    const printWindow = window.open('', '_blank');
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 500);
  };

  const loadTodayAttendance = async () => {
    const today = new Date().toISOString().split('T')[0];
    const attendanceResp = await system.getAttendanceToday();
    const attendance = attendanceResp && attendanceResp.records ? attendanceResp.records : [];
    
    const enrolledCourses = courses.filter(course => 
      currentUser.courses && currentUser.courses.includes(course.code)
    );
    
    const todayAttendance = attendance.filter(record => 
      record.studentId === currentUser.username && record.date === today
    );

    // Get all today's attendance records to check which courses had sessions
    const allTodayRecords = attendance.filter(record => record.date === today);

    if (enrolledCourses.length === 0) {
      setTodayAttendance([{
        isPlaceholder: true,
        message: 'You are not enrolled in any courses'
      }]);
      return;
    }

    const attendanceData = enrolledCourses.map(course => {
      const attended = todayAttendance.find(record => record.courseId === course.code);
      const sessionCreated = allTodayRecords.some(record => record.courseId === course.code);
      
      return {
        course: course.name,
        status: attended ? 'Present' : (sessionCreated ? 'Absent' : 'No Session'),
        time: attended ? new Date(attended.timestamp).toLocaleTimeString() : '-'
      };
    });

    setTodayAttendance(attendanceData);
  };

  const handleLogout = () => {
    system.logout();
  };

  if (isAuthChecking) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <div style={{ textAlign: 'center', color: 'white' }}>
          <div style={{
            border: '4px solid rgba(255, 255, 255, 0.3)',
            borderTop: '4px solid white',
            borderRadius: '50%',
            width: '50px',
            height: '50px',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 20px'
          }}></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="student-dashboard">
      <div className="dashboard-container">
        {/* Header */}
        <div className="header">
          <div className="header-left">
            <h1>Student Dashboard</h1>
            <div className="welcome-message">
              Welcome, {currentUser.name} ({currentUser.rollNo})
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button 
              className="notification-btn" 
              onClick={() => setShowNotifications(!showNotifications)}
              style={{ position: 'relative', padding: '10px 15px', cursor: 'pointer' }}
            >
              🔔 Notifications
              {unreadCount > 0 && (
                <span style={{
                  position: 'absolute',
                  top: '0',
                  right: '0',
                  background: 'red',
                  color: 'white',
                  borderRadius: '50%',
                  padding: '2px 6px',
                  fontSize: '12px'
                }}>
                  {unreadCount}
                </span>
              )}
            </button>
            <button className="logout-btn" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>

        {showNotifications && (
          <div className="notifications-panel" style={{
            background: 'white',
            border: '1px solid #ddd',
            borderRadius: '8px',
            padding: '15px',
            marginBottom: '20px',
            maxHeight: '400px',
            overflowY: 'auto'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '15px' }}>
              <h3>Notifications</h3>
            </div>
            {notifications.length === 0 ? (
              <p>No notifications</p>
            ) : (
              <div>
                {notifications.map(notif => (
                  <div 
                    key={notif._id}
                    style={{
                      padding: '10px',
                      marginBottom: '10px',
                      background: notif.read ? '#f5f5f5' : '#e3f2fd',
                      borderRadius: '5px',
                      cursor: 'pointer'
                    }}
                    onClick={() => !notif.read && markNotificationRead(notif._id)}
                  >
                    <div style={{ fontWeight: 'bold' }}>{notif.title}</div>
                    <div style={{ fontSize: '14px', marginTop: '5px' }}>{notif.message}</div>
                    <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
                      {new Date(notif.createdAt).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Navigation Menu */}
        <div className="nav-menu">
          <button 
            className={`nav-btn ${activeSection === 'scan' ? 'active' : ''}`}
            onClick={() => showSection('scan')}
          >
            Scan QR Code
          </button>
          <button 
            className={`nav-btn ${activeSection === 'report' ? 'active' : ''}`}
            onClick={() => showSection('report')}
          >
            View Monthly Report
          </button>
          <button 
            className={`nav-btn ${activeSection === 'today' ? 'active' : ''}`}
            onClick={() => showSection('today')}
          >
            Today's Attendance
          </button>
        </div>

        {/* Content Area */}
        <div className="content">
          {/* Scan QR Section */}
          {activeSection === 'scan' && (
            <div className="section">
              <h2>Scan QR Code for Attendance</h2>
              
              {/* Active Sessions Display */}
              {(activeSessions.length > 0 || notifications.filter(n => n.type === 'class_created' && n.data?.expiry > Date.now()).length > 0) ? (
                <div style={{
                  background: '#e8f5e9',
                  border: '2px solid #4caf50',
                  borderRadius: '8px',
                  padding: '15px',
                  marginBottom: '20px'
                }}>
                  <h3 style={{ margin: '0 0 15px 0', color: '#2e7d32' }}>🟢 Active Classes - Scan QR Code Now!</h3>
                  {activeSessions.length > 0 ? activeSessions.map((session, idx) => {
                    const timeLeft = Math.max(0, Math.floor((session.expiry - Date.now()) / 60000));
                    return (
                      <div 
                        key={idx}
                        style={{
                          padding: '15px',
                          background: 'white',
                          marginTop: idx > 0 ? '10px' : '0',
                          borderRadius: '5px',
                          border: '2px solid #4caf50',
                          transition: 'all 0.3s ease',
                          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <div style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '5px' }}>
                              📚 {session.courseName}
                            </div>
                            <div style={{ fontSize: '14px', color: '#666' }}>
                              👨‍🏫 {session.teacherName}
                            </div>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ 
                              fontSize: '16px', 
                              fontWeight: 'bold',
                              color: timeLeft < 5 ? 'red' : '#4caf50',
                              marginBottom: '5px'
                            }}>
                              ⏰ {timeLeft} min left
                            </div>
                            <div style={{ 
                              fontSize: '14px',
                              color: '#4caf50',
                              fontWeight: 'bold'
                            }}>
                              👇 Scan Below
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  }) : notifications.filter(n => n.type === 'class_created' && n.data?.expiry > Date.now()).map((notif, idx) => {
                    const timeLeft = Math.max(0, Math.floor((notif.data.expiry - Date.now()) / 60000));
                    return (
                      <div 
                        key={idx}
                        style={{
                          padding: '15px',
                          background: 'white',
                          marginTop: idx > 0 ? '10px' : '0',
                          borderRadius: '5px',
                          border: '2px solid #4caf50',
                          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <div style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '5px' }}>
                              📚 {notif.data.courseName}
                            </div>
                            <div style={{ fontSize: '14px', color: '#666' }}>
                              👨‍🏫 {notif.data.teacherName}
                            </div>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ 
                              fontSize: '16px', 
                              fontWeight: 'bold',
                              color: timeLeft < 5 ? 'red' : '#4caf50',
                              marginBottom: '5px'
                            }}>
                              ⏰ {timeLeft} min left
                            </div>
                            <div style={{ 
                              fontSize: '14px',
                              color: '#4caf50',
                              fontWeight: 'bold'
                            }}>
                              👇 Scan Below
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div>
                  {/* Show recent class notifications if any */}
                  {notifications.filter(n => n.type === 'class_created').slice(0, 3).length > 0 ? (
                    <div style={{
                      background: '#e3f2fd',
                      border: '2px solid #2196f3',
                      borderRadius: '8px',
                      padding: '15px',
                      marginBottom: '20px'
                    }}>
                      <h3 style={{ margin: '0 0 15px 0', color: '#1565c0' }}>📢 Recent Class Notifications</h3>
                      {notifications.filter(n => n.type === 'class_created').slice(0, 3).map(notif => (
                        <div 
                          key={notif._id}
                          style={{
                            padding: '12px',
                            background: 'white',
                            marginTop: '10px',
                            borderRadius: '5px',
                            border: '1px solid #2196f3'
                          }}
                        >
                          <div style={{ fontWeight: 'bold', color: '#1565c0' }}>{notif.title}</div>
                          <div style={{ fontSize: '14px', marginTop: '5px', color: '#555' }}>{notif.message}</div>
                          <div style={{ fontSize: '12px', color: '#999', marginTop: '5px' }}>
                            {new Date(notif.createdAt).toLocaleString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{
                      background: '#fff3cd',
                      border: '1px solid #ffc107',
                      borderRadius: '8px',
                      padding: '15px',
                      marginBottom: '20px',
                      textAlign: 'center'
                    }}>
                      <div style={{ fontSize: '18px', color: '#856404' }}>
                        📚 No active classes at the moment.
                      </div>
                      <div style={{ fontSize: '14px', color: '#856404', marginTop: '5px' }}>
                        Wait for your teacher to start a class session
                      </div>
                    </div>
                  )}
                </div>
              )}
              
              {/* Camera Scanner - Only show when there are active sessions */}
              {(activeSessions.length > 0 || notifications.filter(n => n.type === 'class_created' && n.data?.expiry > Date.now()).length > 0) && (
                <>
                  <div className="scanner-container">
                    <div className="scanner-header">
                      <h3>📷 Camera Scanner</h3>
                      <p>Point your camera at the QR code shown by your teacher</p>
                    </div>
                    
                    <div className="camera-placeholder">
                      <div className="camera-frame">
                        <video 
                          ref={videoRef} 
                          id="cameraPreview" 
                          playsInline
                        />
                        <div className="scan-overlay">
                          <div className="scan-frame"></div>
                          <div className="scan-line"></div>
                        </div>
                      </div>
                      <div className="camera-instructions">
                        <p>🔍 Position QR code within the frame to scan automatically</p>
                        <p>💡 Ensure good lighting for better detection</p>
                      </div>
                    </div>
                    <canvas ref={canvasRef} style={{ display: 'none' }} />
                  </div>

                  {/* Manual Entry */}
                  <div className="manual-entry">
                    <h4>Or enter QR code manually:</h4>
                    <div className="form-group">
                      <input 
                        type="text" 
                        value={manualQR}
                        onChange={(e) => setManualQR(e.target.value)}
                        placeholder="Paste QR code data here" 
                      />
                      <button className="btn success" onClick={submitQRCode}>
                        Submit Attendance
                      </button>
                    </div>
                  </div>
                </>
              )}
              
              {/* Scan Result */}
              <div dangerouslySetInnerHTML={{ __html: scanResult }} />
            </div>
          )}

          {/* Monthly Report Section */}
          {activeSection === 'report' && (
            <div className="section">
              <h2>Complete Attendance Report</h2>
              <p style={{color: '#666', marginBottom: '20px'}}>
                💡 Select a course to view your complete attendance history
              </p>
              
              <div className="form-group" style={{maxWidth: '400px'}}>
                <label>Select Course:</label>
                <select 
                  value={selectedReportCourse}
                  onChange={(e) => setSelectedReportCourse(e.target.value)}
                >
                  <option value="">-- Select Course --</option>
                  {currentUser.courses && currentUser.courses.map(courseCode => {
                    const course = courses.find(c => c.code === courseCode);
                    return course ? (
                      <option key={course.code} value={course.code}>
                        {course.name} ({course.code})
                      </option>
                    ) : null;
                  })}
                </select>
              </div>

              <div style={{display: 'flex', gap: '10px', marginTop: '15px', marginBottom: '20px', flexWrap: 'wrap'}}>
                <button className="btn primary" onClick={loadMonthlyReport}>
                  Load Report
                </button>
                {monthlyReport.length > 0 && !monthlyReport[0]?.isPlaceholder && (
                  <button className="btn info" onClick={downloadMonthlyPDF}>
                    📄 Download PDF
                  </button>
                )}
              </div>
              
              <div className="table-container">
                <table id="monthlyReportTable">
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Course</th>
                      <th>Status</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {monthlyReport.length === 0 ? (
                      <tr>
                        <td colSpan="4" className="no-data">
                          Select a month to view your attendance report
                        </td>
                      </tr>
                    ) : monthlyReport[0]?.isPlaceholder ? (
                      <tr>
                        <td colSpan="4" className="no-data">
                          {monthlyReport[0].message}
                        </td>
                      </tr>
                    ) : (
                      monthlyReport.map((record, index) => (
                        <tr key={index}>
                          <td>{record.date}</td>
                          <td>{record.course}</td>
                          <td className={`status-${record.status}`}>
                            {record.status.toUpperCase()}
                          </td>
                          <td>{record.time}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Today's Attendance Section */}
          {activeSection === 'today' && (
            <div className="section">
              <h2>Today's Attendance</h2>
              
              <div className="table-container">
                <table id="todayAttendanceTable">
                  <thead>
                    <tr>
                      <th>Course</th>
                      <th>Status</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {todayAttendance.length === 0 ? (
                      <tr>
                        <td colSpan="3" className="no-data">
                          Loading today's attendance...
                        </td>
                      </tr>
                    ) : todayAttendance[0]?.isPlaceholder ? (
                      <tr>
                        <td colSpan="3" className="no-data">
                          {todayAttendance[0].message}
                        </td>
                      </tr>
                    ) : (
                      todayAttendance.map((item, index) => (
                        <tr key={index}>
                          <td>{item.course}</td>
                          <td>
                            <span style={{ 
                              color: item.status === 'Present' ? '#22C55E' : (item.status === 'Absent' ? '#EF4444' : '#F59E0B'), 
                              fontWeight: 'bold' 
                            }}>
                              {item.status === 'Present' ? '✅ Present' : (item.status === 'Absent' ? '❌ Absent' : '⚠️ No Session Created')}
                            </span>
                          </td>
                          <td>{item.time}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default StudentDashboard;