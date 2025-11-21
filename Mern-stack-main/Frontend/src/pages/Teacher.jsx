import React, { useState, useEffect, useRef } from 'react';
import './Teacher.css';
import { system } from '../system';
import { io } from 'socket.io-client';

const Teacher = () => {
    const [activeSection, setActiveSection] = useState('qr');
    const [courses, setCourses] = useState([]);
    const [loadingCourses, setLoadingCourses] = useState(false);
    const [coursesMessage, setCoursesMessage] = useState('');
    const [attendance, setAttendance] = useState([]);
    const [currentQR, setCurrentQR] = useState(null);
    const [qrTimer, setQrTimer] = useState('');
    const [selectedCourse, setSelectedCourse] = useState('');
    const [reportCourse, setReportCourse] = useState('');
    const [attendanceMonth, setAttendanceMonth] = useState('');
    const [attendanceData, setAttendanceData] = useState([]);
    const [noClassFlags, setNoClassFlags] = useState([]);
    const [currentUser, setCurrentUser] = useState(null);
    const [manualAttendanceCourse, setManualAttendanceCourse] = useState('');
    const [students, setStudents] = useState([]);
    const [attendanceDate, setAttendanceDate] = useState('');
    const [attendanceStatuses, setAttendanceStatuses] = useState({});
    const [sessionExists, setSessionExists] = useState(false);
    const [sessionCheckMessage, setSessionCheckMessage] = useState('');
    const [globalSessionActive, setGlobalSessionActive] = useState(false);
    const [isAuthChecking, setIsAuthChecking] = useState(true);
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const [showNotifications, setShowNotifications] = useState(false);
    const [realtimeAttendance, setRealtimeAttendance] = useState([]);
    
    const socketRef = useRef(null);

    // Initialize system data — require real teacher login; do not auto-login with dummy credentials
    useEffect(() => {
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
            if (!user || user.role !== 'teacher') {
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

            // Refresh current user from server and set state
            try {
                const user = await system.refreshCurrentUser();
                setCurrentUser(user || system.getCurrentUser());
            } catch (e) {
                console.error('Failed to refresh current user', e);
            }

            // Load courses/attendance and check for existing QR after auth is available
            try {
                await loadInitialData();
            } catch (e) {
                console.error('loadInitialData failed', e);
            }

            try {
                await checkExistingQR();
            } catch (e) {
                console.error('checkExistingQR failed', e);
            }

            try {
                await checkGlobalSession();
            } catch (e) {
                console.error('checkGlobalSession failed', e);
            }

            // Set current month as default
            const now = new Date();
            setAttendanceMonth(now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0'));

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

            // Listen for attendance notifications
            socket.on('attendance_marked', (data) => {
                console.log('Attendance marked:', data);
                // Show notification
                showAttendanceNotification(data);
                // Add to realtime attendance list
                setRealtimeAttendance(prev => [data, ...prev]);
                // Refresh unread count
                fetchUnreadCount();
            });

            socket.on('disconnect', () => {
                console.log('Socket disconnected');
            });

            // Fetch notifications on load
            fetchNotifications();
            fetchUnreadCount();
        })();

        // Cleanup on unmount
        return () => {
            if (socketRef.current) {
                socketRef.current.disconnect();
            }
        };
    }, []);

    const initializeSystem = () => {
        // seeding moved to backend; no localStorage usage in frontend
    };

    const loadInitialData = async () => {
        try {
            const token = system.getToken();
            if (token) {
                // Fetch courses assigned to this teacher
                try {
                    setLoadingCourses(true);
                    setCoursesMessage('Loading courses...');
                    const coursesResp = await fetch('http://localhost:5000/api/teacher/courses', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const coursesData = await coursesResp.json();
                    if (coursesResp.ok && coursesData && coursesData.courses) {
                        setCourses(coursesData.courses);
                        if (!coursesData.courses.length) setCoursesMessage('No courses assigned to this teacher');
                        else setCoursesMessage('');
                    } else {
                        console.warn('Failed to load teacher courses', coursesResp.status, coursesData);
                        setCoursesMessage('Failed to load courses from server');
                    }
                } catch (e) {
                    console.error('Error fetching teacher courses', e);
                    setCoursesMessage('Failed to load courses');
                } finally {
                    setLoadingCourses(false);
                }

                // Try fetch attendance (teacher can access attendance endpoints)
                try {
                    const attendanceResp = await fetch('http://localhost:5000/api/attendance', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const attendanceData = await attendanceResp.json();
                    if (attendanceData && attendanceData.records) setAttendance(attendanceData.records);
                } catch (e) { }
            }

            // No local fallback course data: if backend didn't return courses, keep the empty list
            // Admin should create courses via the Admin UI.
        } catch (err) {
            console.error('Error loading initial data', err);
        }
    };

    const checkExistingQR = async () => {
        try {
            const token = system.getToken();
            if (!token) return;

            // First check if there's a global active session
            const sessionsResp = await fetch(`http://localhost:5000/api/teacher/check-global-session`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const sessionData = await sessionsResp.json();
            
            // If there's an active session by current teacher, load it
            if (sessionData && sessionData.hasActiveSession) {
                const currentUser = system.getCurrentUser();
                if (sessionData.session && sessionData.session.teacherId === currentUser.username) {
                    // This is current teacher's session - reconstruct QR
                    const session = sessionData.session;
                    const qrData = {
                        courseId: session.courseId,
                        teacherId: session.teacherId,
                        teacherName: session.teacherName,
                        timestamp: session.timestamp,
                        expiry: session.expiry
                    };
                    const qrString = JSON.stringify(qrData);
                    setCurrentQR(qrString);
                    setSelectedCourse(session.courseId);
                    if (session.expiry) startQRTimer(session.expiry);
                    setGlobalSessionActive(false);
                    return;
                } else {
                    // Another teacher's session - disable buttons
                    setGlobalSessionActive(true);
                }
            }

            // Fallback to old method
            const resp = await system.getCurrentQR();
            if (resp && resp.qrString) {
                setCurrentQR(resp.qrString);
                try {
                    const qrData = JSON.parse(resp.qrString);
                    setSelectedCourse(qrData.courseId);
                    if (qrData.expiry) startQRTimer(qrData.expiry);
                } catch (e) { }
            } else {
                setCurrentQR(null);
            }
        } catch (err) {
            console.error('Error checking current QR', err);
        }
    };

    const checkGlobalSession = async () => {
        try {
            const token = system.getToken();
            if (!token) return;

            const sessionsResp = await fetch(`http://localhost:5000/api/teacher/check-global-session`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const sessionData = await sessionsResp.json();
            
            if (sessionData && sessionData.hasActiveSession) {
                // Check if current teacher created this session
                const currentUser = system.getCurrentUser();
                if (sessionData.session && sessionData.session.teacherId === currentUser.username) {
                    // Current teacher's session - allow buttons
                    setGlobalSessionActive(false);
                } else {
                    // Another teacher's session - disable buttons
                    setGlobalSessionActive(true);
                }
            } else {
                setGlobalSessionActive(false);
            }
        } catch (err) {
            console.error('Error checking global session', err);
            setGlobalSessionActive(false);
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

    const showAttendanceNotification = (data) => {
        // Show browser notification
        if (Notification.permission === 'granted') {
            new Notification('Student Attendance', {
                body: `${data.studentName} (${data.rollNo}) marked attendance for ${data.courseName}`,
                icon: '/attendance-icon.png'
            });
        }

        // Show in-app alert
        alert(`✅ ${data.studentName} (${data.rollNo}) marked attendance for ${data.courseName}`);
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

    const markAllNotificationsRead = async () => {
        try {
            const token = system.getToken();
            if (!token) return;

            await fetch('http://localhost:5000/api/notifications/read-all', {
                method: 'PUT',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            fetchNotifications();
            fetchUnreadCount();
        } catch (err) {
            console.error('Error marking all notifications as read', err);
        }
    };

    const generateQRCode = async () => {
        if (!selectedCourse) {
            alert('Please select a course');
            return;
        }

        if (!attendanceDate) {
            alert('Please select lecture date');
            return;
        }

        // Check if date is today
        const today = new Date().toISOString().split('T')[0];
        if (attendanceDate !== today) {
            alert('❌ You can only create sessions for today\'s date. Cannot create sessions for past or future dates.');
            return;
        }

        if (!currentUser) {
            alert('User not logged in');
            return;
        }

        // Verify assignment using the courses fetched for this teacher
        const assigned = courses.some(c => c.code === selectedCourse);
        if (!assigned) {
            alert(`You are not assigned to teach ${getCourseName(selectedCourse)}. Please contact admin.`);
            return;
        }

        if (hasNoClassToday(selectedCourse)) {
            alert(`❌ Cannot generate QR code. ${getCourseName(selectedCourse)} is marked as "No Class" today.`);
            return;
        }

        // Check if any session exists globally (within last 1.5 hours)
        try {
            const token = system.getToken();
            
            // Check for any active sessions by any teacher
            const sessionsResp = await fetch(`http://localhost:5000/api/teacher/check-global-session`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const sessionData = await sessionsResp.json();
            
            if (sessionData && sessionData.hasActiveSession) {
                const remainingTime = sessionData.remainingMinutes;
                alert(`❌ Another session is currently active. Please wait ${remainingTime} minutes before creating a new session.`);
                return;
            }
            
            // Check if a session already exists for today for this specific course
            const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${selectedCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const attendanceData = await attendanceResp.json();
            
            const todayRecords = attendanceData.records.filter(r => r.date === today);
            if (todayRecords.length > 0) {
                alert(`❌ A session has already been created for ${getCourseName(selectedCourse)} today. Only one session per day is allowed.`);
                return;
            }
        } catch (err) {
            console.error('Error checking existing session:', err);
        }

        // Use API-backed system to create session
        const result = await system.generateQRCode(selectedCourse, 15);
        if (result && result.ok) {
            setCurrentQR(result.qrString);
            if (result.session && result.session.expiry) startQRTimer(result.session.expiry);
            setGlobalSessionActive(true); // Mark global session as active
            alert('✅ QR Code generated successfully! Students can now scan it.');
        } else {
            alert(result.message || 'Failed to generate QR');
        }
    };

    const startQRTimer = (expiryTime) => {
        const updateTimer = () => {
            const now = Date.now();
            const remaining = expiryTime - now;
            
            if (remaining <= 0) {
                setQrTimer('QR Code Expired');
                setCurrentQR(null);
                return;
            }

            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            setQrTimer(`Expires in: ${minutes}:${seconds.toString().padStart(2, '0')}`);
        };

        updateTimer();
        const timerInterval = setInterval(updateTimer, 1000);
        
        // Cleanup interval on component unmount or QR expiry
        return () => clearInterval(timerInterval);
    };

    const displayQRCode = () => {
        if (!currentQR) {
            alert('Please generate QR code first');
            return;
        }

        const qrData = JSON.parse(currentQR);
        const course = courses.find(c => c.code === qrData.courseId);
        
        const displayWindow = window.open('', 'QR Display', 'width=500,height=600');
        displayWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>QR Code Display</title>
                <style>
                    body { 
                        text-align: center; 
                        padding: 40px; 
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        height: 100vh;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                    }
                    .container { 
                        background: white; 
                        padding: 30px; 
                        border-radius: 15px;
                        color: #333;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                    }
                    h2 { color: #333; margin-bottom: 20px; }
                    #displayQR { margin: 20px 0; }
                    button { 
                        padding: 10px 20px; 
                        margin: 10px; 
                        cursor: pointer; 
                        background: #667eea;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        font-size: 16px;
                    }
                    button:hover { background: #5a6fd8; }
                    .info { margin: 15px 0; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>📱 Scan QR Code for Attendance</h2>
                    <div class="info">
                        <strong>Course:</strong> ${course ? course.name : qrData.courseId}<br>
                        <strong>Teacher:</strong> ${qrData.teacherName}<br>
                        <strong>Time:</strong> ${new Date().toLocaleTimeString()}
                    </div>
                    <div id="displayQR"></div>
                    <p>Students should scan this QR code with their phones</p>
                    <div>
                        <button onclick="window.print()">🖨️ Print</button>
                        <button onclick="window.close()">❌ Close</button>
                    </div>
                </div>
                <script src="https://cdn.rawgit.com/davidshimjs/qrcodejs/gh-pages/qrcode.min.js"></script>
                <script>
                    // Clear any existing QR code
                    document.getElementById('displayQR').innerHTML = '';
                    new QRCode(document.getElementById('displayQR'), {
                        text: '${currentQR}',
                        width: 250,
                        height: 250,
                        colorDark: "#000000",
                        colorLight: "#ffffff"
                    });
                </script>
            </body>
            </html>
        `);
        displayWindow.document.close();
    };

    const printQRCode = () => {
        if (!currentQR) {
            alert('Please generate QR code first');
            return;
        }

        const qrData = JSON.parse(currentQR);
        const course = courses.find(c => c.code === qrData.courseId);
        
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Print QR Code</title>
                <style>
                    body { text-align: center; font-family: Arial; padding: 40px; }
                    .qr-container { margin: 30px 0; }
                    h2 { color: #333; }
                    .course-info { margin: 20px 0; font-size: 18px; }
                    .timestamp { color: #666; margin: 10px 0; }
                </style>
            </head>
            <body>
                <h2>🎓 Attendance QR Code</h2>
                <div class="course-info">
                    <strong>Course:</strong> ${course ? course.name : qrData.courseId}<br>
                    <strong>Teacher:</strong> ${qrData.teacherName}<br>
                    <strong>Date:</strong> ${new Date().toLocaleDateString()}
                </div>
                <div class="qr-container">
                    <div id="printQR"></div>
                </div>
                <div class="timestamp">
                    Generated: ${new Date().toLocaleTimeString()}<br>
                    Valid for 15 minutes
                </div>
                <script src="https://cdn.rawgit.com/davidshimjs/qrcodejs/gh-pages/qrcode.min.js"></script>
                <script>
                    new QRCode(document.getElementById('printQR'), {
                        text: '${currentQR}',
                        width: 200,
                        height: 200
                    });
                    window.onload = function() {
                        window.print();
                        setTimeout(() => window.close(), 1000);
                    }
                </script>
            </body>
            </html>
        `);
    };

    const markNoClass = async () => {
        if (!selectedCourse) {
            alert('Please select a course first');
            return;
        }

        // Ensure selected course is in the fetched teacher courses list
        const assigned = courses.some(c => c.code === selectedCourse);
        if (!assigned) {
            alert(`You are not assigned to teach ${getCourseName(selectedCourse)}`);
            return;
        }

        // Check if QR already generated for this course today
        const today = new Date().toISOString().split('T')[0];
        try {
            const token = system.getToken();
            const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${selectedCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const attendanceData = await attendanceResp.json();
            const todayRecords = attendanceData.records.filter(r => r.date === today);
            
            if (todayRecords.length > 0) {
                alert(`❌ Cannot mark "No Class" for ${getCourseName(selectedCourse)}. A session has already been created today.`);
                return;
            }
        } catch (err) {
            console.error('Error checking existing session:', err);
        }

        if (confirm(`Mark "No Class" for ${getCourseName(selectedCourse)} today? This will show "No Class Today" to students.`)) {
            const today = new Date().toISOString().split('T')[0];
            const flag = {
                courseId: selectedCourse,
                date: today,
                timestamp: new Date().toISOString(),
                teacherId: currentUser.username
            };

            const updatedFlags = [...noClassFlags, flag];
            setNoClassFlags(updatedFlags);
            // Persist no-class flag to backend if possible
            (async () => {
                try {
                    const token = system.getToken();
                    if (token) {
                        await fetch('http://localhost:5000/api/teacher/no-class', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                            body: JSON.stringify({ courseId: selectedCourse })
                        });
                    }
                } catch (e) { console.error('Failed to persist no-class flag', e); }
            })();
            
            // Clear QR code for this course
            if (currentQR) {
                const qrData = JSON.parse(currentQR);
                if (qrData.courseId === selectedCourse) {
                    setCurrentQR(null);
                    setQrTimer('');
                }
            }
            
            alert(`✅ ${getCourseName(selectedCourse)} marked as "No Class" for today. Students will see "No Class Today" message.`);
        }
    };

    const removeNoClassFlag = (courseId) => {
        if (confirm('Remove "No Class" status for this course?')) {
            const today = new Date().toISOString().split('T')[0];
            const updatedFlags = noClassFlags.filter(flag => 
                !(flag.courseId === courseId && flag.date === today)
            );
            setNoClassFlags(updatedFlags);
            alert('"No Class" status removed successfully!');
        }
    };

    const loadAttendanceReport = async () => {
        if (!reportCourse || !attendanceDate) {
            const emptyData = [{
                date: '',
                studentName: 'Please select a course and session date',
                rollNo: '',
                status: '',
                time: ''
            }];
            setAttendanceData(emptyData);
            setSessionExists(false);
            setSessionCheckMessage('');
            return;
        }

        try {
            const token = system.getToken();
            
            // Check if date is in the future
            const today = new Date().toISOString().split('T')[0];
            if (attendanceDate > today) {
                const emptyData = [{
                    date: '',
                    studentName: 'Cannot create session for future dates',
                    rollNo: '',
                    status: '',
                    time: ''
                }];
                setAttendanceData(emptyData);
                setSessionExists(false);
                setSessionCheckMessage('⚠️ Cannot create or view sessions for future dates');
                return;
            }
            
            // Get attendance records for the specific date
            const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const attendanceData = await attendanceResp.json();
            
            // Filter records for the selected date
            const dateRecords = attendanceData.records.filter(r => r.date === attendanceDate);
            
            // Check if session exists (at least one attendance record for this date)
            if (dateRecords.length === 0) {
                const emptyData = [{
                    date: '',
                    studentName: 'No session created for this date',
                    rollNo: '',
                    status: '',
                    time: ''
                }];
                setAttendanceData(emptyData);
                setSessionExists(false);
                setSessionCheckMessage('❌ No session was created for this date. Please create a session first.');
                return;
            }
            
            // Session exists - load all students
            setSessionExists(true);
            setSessionCheckMessage('');
            
            // Get all students enrolled in the course
            const studentsResp = await fetch(`http://localhost:5000/api/teacher/students/${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const studentsData = await studentsResp.json();
            
            if (!studentsResp.ok || !studentsData.students) {
                alert('Failed to load students');
                return;
            }
            
            // Create attendance list with all students
            const allStudentsAttendance = studentsData.students.map(student => {
                const record = dateRecords.find(r => r.studentId === student.username);
                
                if (record) {
                    return {
                        id: record._id,
                        date: record.date,
                        studentName: student.name || student.username,
                        rollNo: student.rollNo || 'N/A',
                        status: record.status,
                        timestamp: record.timestamp
                    };
                } else {
                    // Student not marked - default to absent
                    return {
                        id: `absent-${student.username}`,
                        date: attendanceDate,
                        studentName: student.name || student.username,
                        rollNo: student.rollNo || 'N/A',
                        status: 'absent',
                        timestamp: new Date().toISOString()
                    };
                }
            });
            
            // Sort by roll number
            allStudentsAttendance.sort((a, b) => {
                if (a.rollNo === 'N/A') return 1;
                if (b.rollNo === 'N/A') return -1;
                return a.rollNo.localeCompare(b.rollNo);
            });
            
            setAttendanceData(allStudentsAttendance);
            
        } catch (err) {
            console.error('Error loading attendance:', err);
            alert('Failed to load attendance records');
        }
    };

    const downloadSessionsPDF = async () => {
        if (!reportCourse) {
            alert('Please select a course');
            return;
        }

        try {
            const token = system.getToken();
            
            // Get all students in the course
            const studentsResp = await fetch(`http://localhost:5000/api/teacher/students/${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const studentsData = await studentsResp.json();
            
            if (!studentsResp.ok || !studentsData.students) {
                alert('Failed to load students');
                return;
            }

            // Get all attendance records for the course
            const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const attendanceData = await attendanceResp.json();
            
            // Get all unique dates (sessions)
            const sessions = [...new Set(attendanceData.records.map(r => r.date))].sort();
            
            if (sessions.length === 0) {
                alert('No sessions found for this course');
                return;
            }

            const course = courses.find(c => c.code === reportCourse);
            const courseName = course ? course.name : reportCourse;
            
            // Build PDF HTML
            let pdfHTML = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Attendance Report - ${courseName}</title>
                    <style>
                        @page {
                            size: A4 landscape;
                            margin: 15mm;
                        }
                        body {
                            font-family: Arial, sans-serif;
                            font-size: 10pt;
                            margin: 0;
                            padding: 20px;
                        }
                        .header {
                            text-align: center;
                            margin-bottom: 20px;
                            border-bottom: 3px solid #2B7DE9;
                            padding-bottom: 10px;
                        }
                        h1 {
                            color: #2B7DE9;
                            margin: 0;
                            font-size: 24pt;
                        }
                        .course-info {
                            margin: 10px 0;
                            font-size: 11pt;
                        }
                        table {
                            width: 100%;
                            border-collapse: collapse;
                            margin-top: 15px;
                            page-break-inside: auto;
                        }
                        thead {
                            background-color: #2B7DE9;
                            color: white;
                        }
                        th, td {
                            border: 1px solid #ddd;
                            padding: 8px;
                            text-align: center;
                            font-size: 9pt;
                        }
                        th {
                            font-weight: bold;
                            position: sticky;
                            top: 0;
                        }
                        tr:nth-child(even) {
                            background-color: #f9f9f9;
                        }
                        .present {
                            background-color: #d4edda;
                            color: #155724;
                            font-weight: bold;
                        }
                        .absent {
                            background-color: #f8d7da;
                            color: #721c24;
                            font-weight: bold;
                        }
                        .student-name {
                            text-align: left;
                            padding-left: 10px;
                        }
                        .summary {
                            margin-top: 20px;
                            padding: 15px;
                            background: #f5f5f5;
                            border-radius: 5px;
                            page-break-before: avoid;
                        }
                        .footer {
                            margin-top: 20px;
                            text-align: center;
                            font-size: 9pt;
                            color: #666;
                        }
                        @media print {
                            button { display: none; }
                            body { padding: 0; }
                        }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>📊 Attendance Report</h1>
                        <div class="course-info">
                            <strong>Course:</strong> ${courseName} (${reportCourse})<br>
                            <strong>Total Students:</strong> ${studentsData.students.length}<br>
                            <strong>Total Sessions:</strong> ${sessions.length}<br>
                            <strong>Generated:</strong> ${new Date().toLocaleString()}<br>
                            <strong>Teacher:</strong> ${currentUser?.name || 'N/A'}
                        </div>
                    </div>
                    
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 40px;">Sr#</th>
                                <th style="width: 120px;">Roll No</th>
                                <th style="width: 150px;">Student Name</th>
                                ${sessions.map(date => `<th style="width: 80px;">${date}</th>`).join('')}
                                <th style="width: 60px;">Present</th>
                                <th style="width: 60px;">Absent</th>
                                <th style="width: 60px;">%</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            // Add each student row
            studentsData.students.forEach((student, index) => {
                let presentCount = 0;
                let absentCount = 0;
                
                const sessionCells = sessions.map(date => {
                    const record = attendanceData.records.find(
                        r => r.studentId === student.username && r.date === date
                    );
                    
                    if (record && record.status === 'present') {
                        presentCount++;
                        return '<td class="present">P</td>';
                    } else {
                        absentCount++;
                        return '<td class="absent">A</td>';
                    }
                }).join('');
                
                const percentage = sessions.length > 0 ? ((presentCount / sessions.length) * 100).toFixed(1) : 0;
                
                pdfHTML += `
                    <tr>
                        <td>${index + 1}</td>
                        <td>${student.rollNo || 'N/A'}</td>
                        <td class="student-name">${student.name || student.username}</td>
                        ${sessionCells}
                        <td><strong>${presentCount}</strong></td>
                        <td><strong>${absentCount}</strong></td>
                        <td><strong>${percentage}%</strong></td>
                    </tr>
                `;
            });
            
            pdfHTML += `
                        </tbody>
                    </table>
                    
                    <div class="summary">
                        <strong>Legend:</strong> P = Present, A = Absent<br>
                        <strong>Note:</strong> Students without attendance record for a session are marked as Absent by default.
                    </div>
                    
                    <div class="footer">
                        <p>This is a computer-generated report. Generated on ${new Date().toLocaleString()}</p>
                    </div>
                    
                    <script>
                        window.onload = function() {
                            window.print();
                        }
                    </script>
                </body>
                </html>
            `;
            
            const printWindow = window.open('', '_blank');
            printWindow.document.write(pdfHTML);
            printWindow.document.close();
            
        } catch (err) {
            console.error('Error generating PDF:', err);
            alert('Failed to generate PDF report');
        }
    };

    const viewDetailedReport = async () => {
        if (!reportCourse || !attendanceDate) {
            alert('Please select a course and session date');
            return;
        }

        try {
            const token = system.getToken();
            
            // Get all students in the course
            const studentsResp = await fetch(`http://localhost:5000/api/teacher/students/${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const studentsData = await studentsResp.json();
            
            if (!studentsResp.ok || !studentsData.students) {
                alert('Failed to load students');
                return;
            }

            // Get all attendance records for the course
            const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${reportCourse}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const attendanceData = await attendanceResp.json();
            
            // Filter records for the selected date
            const dateRecords = attendanceData.records.filter(r => r.date === attendanceDate);
            
            // Build report table
            const course = courses.find(c => c.code === reportCourse);
            const courseName = course ? course.name : reportCourse;
            
            let presentCount = 0;
            let absentCount = 0;
            
            let tableHTML = `
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h2 { color: #2B7DE9; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
                    th { background-color: #2B7DE9; color: white; }
                    .present { background-color: #d4edda; color: #155724; font-weight: bold; }
                    .absent { background-color: #f8d7da; color: #721c24; font-weight: bold; }
                    .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
                    @media print {
                        button { display: none; }
                    }
                </style>
                <h2>📊 Attendance Report - ${attendanceDate}</h2>
                <div class="summary">
                    <p><strong>Course:</strong> ${courseName} (${reportCourse})</p>
                    <p><strong>Date:</strong> ${attendanceDate}</p>
                    <p><strong>Total Students:</strong> ${studentsData.students.length}</p>
                    <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Sr#</th>
                            <th>Roll No</th>
                            <th>Student Name</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            studentsData.students.forEach((student, index) => {
                const record = dateRecords.find(r => r.studentId === student.username);
                
                let status = 'ABSENT';
                let statusClass = 'absent';
                let time = '-';
                
                if (record) {
                    status = record.status.toUpperCase();
                    statusClass = record.status;
                    time = new Date(record.timestamp).toLocaleTimeString();
                }
                
                if (status === 'PRESENT') {
                    presentCount++;
                } else {
                    absentCount++;
                }
                
                tableHTML += `
                    <tr>
                        <td>${index + 1}</td>
                        <td>${student.rollNo || 'N/A'}</td>
                        <td style="text-align: left;">${student.name || student.username}</td>
                        <td class="${statusClass}">${status}</td>
                        <td>${time}</td>
                    </tr>
                `;
            });
            
            const percentage = studentsData.students.length > 0 ? ((presentCount / studentsData.students.length) * 100).toFixed(1) : 0;
            
            tableHTML += `
                    </tbody>
                </table>
                <div class="summary" style="margin-top: 20px;">
                    <p><strong>Present:</strong> ${presentCount}</p>
                    <p><strong>Absent:</strong> ${absentCount}</p>
                    <p><strong>Attendance Percentage:</strong> ${percentage}%</p>
                </div>
                <button onclick="window.print()" style="margin-top: 20px; padding: 10px 20px; background: #2B7DE9; color: white; border: none; border-radius: 5px; cursor: pointer;">Print Report</button>
            `;
            
            const reportWindow = window.open('', '_blank');
            reportWindow.document.write(tableHTML);
            reportWindow.document.close();
            
        } catch (err) {
            console.error('Error generating report:', err);
            alert('Failed to generate detailed report');
        }
    };

    const downloadPDF = () => {
        if (attendanceData.length === 0 || attendanceData[0].studentName.includes('No attendance')) {
            alert('No data available to download');
            return;
        }

        const course = courses.find(c => c.code === reportCourse);
        const courseName = course ? course.name : reportCourse;
        
        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Attendance Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h2 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
                    .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                    th { background-color: #f2f2f2; font-weight: bold; }
                    .present { color: #4caf50; font-weight: bold; }
                    .absent { color: #f44336; font-weight: bold; }
                </style>
            </head>
            <body>
                <h2>📊 Attendance Report</h2>
                <div class="summary">
                    <p><strong>Course:</strong> ${courseName}</p>
                    <p><strong>Month:</strong> ${attendanceMonth}</p>
                    <p><strong>Total Records:</strong> ${attendanceData.length}</p>
                    <p><strong>Generated on:</strong> ${new Date().toLocaleString()}</p>
                    <p><strong>Generated by:</strong> ${currentUser?.name}</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Student Name</th>
                            <th>Roll No</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${attendanceData.map(record => `
                            <tr>
                                <td>${record.date}</td>
                                <td>${record.studentName}</td>
                                <td>${record.rollNo}</td>
                                <td class="${record.status === 'present' ? 'present' : 'absent'}">${record.status.toUpperCase()}</td>
                                <td>${new Date(record.timestamp).toLocaleTimeString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </body>
            </html>
        `;
        
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attendance-${courseName}-${attendanceMonth}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const logout = () => {
        system.logout();
    };

    // Get course name helper
    const getCourseName = (courseCode) => {
        const course = courses.find(c => c.code === courseCode);
        return course ? course.name : courseCode;
    };

    // Get QR data for display
    const getQRData = () => {
        if (!currentQR) return null;
        try {
            return JSON.parse(currentQR);
        } catch {
            return null;
        }
    };

    // Get teacher's assigned courses
    const getTeacherCourses = () => {
        // The backend endpoint /api/teacher/courses returns the course documents
        // (or placeholders) for the logged-in teacher. Use that list directly
        // to populate the dropdown so UI matches DB assignments.
        return courses || [];
    };

    // Check if course has "No Class" today
    const hasNoClassToday = (courseCode) => {
        const today = new Date().toISOString().split('T')[0];
        return noClassFlags.some(flag => flag.courseId === courseCode && flag.date === today);
    };

    // Load students for a course and check existing attendance
    const loadStudentsForCourse = async (courseCode, selectedDate = attendanceDate) => {
        if (!courseCode) {
            setStudents([]);
            return;
        }
        
        try {
            const token = system.getToken();
            const resp = await fetch(`http://localhost:5000/api/teacher/students/${courseCode}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await resp.json();
            
            if (resp.ok && data.students) {
                setStudents(data.students);
                
                // Check if date is selected, load existing attendance
                if (selectedDate) {
                    const attendanceResp = await fetch(`http://localhost:5000/api/attendance?courseId=${courseCode}`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const attendanceData = await attendanceResp.json();
                    const dateRecords = attendanceData.records.filter(r => r.date === selectedDate);
                    
                    // Initialize attendance statuses based on existing records
                    const statuses = {};
                    data.students.forEach(student => {
                        const record = dateRecords.find(r => r.studentId === student.username);
                        statuses[student.username] = record ? record.status : 'absent';
                    });
                    setAttendanceStatuses(statuses);
                } else {
                    // Initialize all as absent
                    const statuses = {};
                    data.students.forEach(student => {
                        statuses[student.username] = 'absent';
                    });
                    setAttendanceStatuses(statuses);
                }
            } else {
                alert(data.message || 'Failed to load students');
                setStudents([]);
            }
        } catch (err) {
            console.error('Error loading students:', err);
            alert('Failed to load students');
            setStudents([]);
        }
    };

    // Mark manual attendance
    const markManualAttendance = async (studentId, status) => {
        if (!attendanceDate) {
            alert('Please select a date');
            return;
        }
        
        try {
            const token = system.getToken();
            const resp = await fetch('http://localhost:5000/api/teacher/mark-attendance', {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    studentId,
                    courseId: manualAttendanceCourse,
                    date: attendanceDate,
                    status
                })
            });
            
            const data = await resp.json();
            
            if (resp.ok) {
                // Update local state
                setAttendanceStatuses(prev => ({
                    ...prev,
                    [studentId]: status
                }));
            } else {
                alert(data.message || 'Failed to mark attendance');
            }
        } catch (err) {
            console.error('Error marking attendance:', err);
            alert('Failed to mark attendance');
        }
    };

    // Mark all students as present
    const markAllPresent = () => {
        const statuses = {};
        students.forEach(student => {
            statuses[student.username] = 'present';
        });
        setAttendanceStatuses(statuses);
    };

    // Mark all students as absent
    const markAllAbsent = () => {
        const statuses = {};
        students.forEach(student => {
            statuses[student.username] = 'absent';
        });
        setAttendanceStatuses(statuses);
    };

    // Save all attendance
    const saveAllAttendance = async () => {
        if (!manualAttendanceCourse || !attendanceDate) {
            alert('Please select course and date');
            return;
        }
        
        try {
            const token = system.getToken();
            let successCount = 0;
            
            for (const student of students) {
                const status = attendanceStatuses[student.username] || 'absent';
                const resp = await fetch('http://localhost:5000/api/teacher/mark-attendance', {
                    method: 'POST',
                    headers: { 
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        studentId: student.username,
                        courseId: manualAttendanceCourse,
                        date: attendanceDate,
                        status
                    })
                });
                
                if (resp.ok) successCount++;
            }
            
            alert(`✅ Attendance saved for ${successCount} students`);
        } catch (err) {
            console.error('Error saving attendance:', err);
            alert('Failed to save attendance');
        }
    };

    const qrData = getQRData();
    const teacherCourses = getTeacherCourses();

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
        <div className="teacher-dashboard">
            <div className="dashboard-container">
                <div className="header">
                    <div>
                        <h1>Teacher Dashboard</h1>
                        {currentUser && (
                            <p className="welcome-message">Welcome, {currentUser.name}!</p>
                        )}
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
                        <button className="logout-btn" onClick={logout}>Logout</button>
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
                            {notifications.length > 0 && (
                                <button onClick={markAllNotificationsRead} style={{ fontSize: '12px' }}>
                                    Mark all as read
                                </button>
                            )}
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

                {realtimeAttendance.length > 0 && (
                    <div className="realtime-attendance" style={{
                        background: '#e8f5e9',
                        border: '1px solid #4caf50',
                        borderRadius: '8px',
                        padding: '15px',
                        marginBottom: '20px'
                    }}>
                        <h3>📊 Real-time Attendance</h3>
                        {realtimeAttendance.slice(0, 5).map((att, idx) => (
                            <div key={idx} style={{
                                padding: '8px',
                                background: 'white',
                                marginTop: '8px',
                                borderRadius: '5px'
                            }}>
                                ✅ <strong>{att.studentName}</strong> ({att.rollNo}) - {att.courseName}
                                <span style={{ float: 'right', fontSize: '12px', color: '#666' }}>
                                    {new Date(att.timestamp).toLocaleTimeString()}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
                
                <div className="nav-menu">
                    <button 
                        onClick={() => setActiveSection('qr')} 
                        className={activeSection === 'qr' ? 'nav-btn active' : 'nav-btn'}
                    >
                        Generate QR Code
                    </button>
                    <button 
                        onClick={() => setActiveSection('manual-attendance')} 
                        className={activeSection === 'manual-attendance' ? 'nav-btn active' : 'nav-btn'}
                    >
                        Mark Attendance
                    </button>
                    <button 
                        onClick={() => setActiveSection('attendance')} 
                        className={activeSection === 'attendance' ? 'nav-btn active' : 'nav-btn'}
                    >
                        View Attendance
                    </button>
                    <button 
                        onClick={() => setActiveSection('no-class')} 
                        className={activeSection === 'no-class' ? 'nav-btn active' : 'nav-btn'}
                    >
                        No Class Management
                    </button>
                </div>

                <div className="content">
                    {/* QR Code Section */}
                    {activeSection === 'qr' && (
                        <div className="section">
                            <h2>Generate QR Code for Class</h2>
                            
                            {currentUser ? (
                                <>
                                    <div className="form-row">
                                        <div className="form-group">
                                            <label>Select Course:</label>
                                            <select 
                                                value={selectedCourse}
                                                onChange={(e) => setSelectedCourse(e.target.value)}
                                            >
                                                <option value="">-- Select Course --</option>
                                                    {teacherCourses.map(course => (
                                                        <option key={course.code} value={course.code}>
                                                            {course.name} ({course.code})
                                                        </option>
                                                    ))}
                                            </select>
                                        </div>

                                        <div className="form-group">
                                            <label>Lecture Date:</label>
                                            <input 
                                                type="date" 
                                                value={attendanceDate}
                                                onChange={(e) => setAttendanceDate(e.target.value)}
                                                max={new Date().toISOString().split('T')[0]}
                                            />
                                        </div>
                                    </div>

                                    <div className="form-row">
                                        <div style={{ marginTop: 8 }}>
                                            <button className="btn small" onClick={async () => { await loadInitialData(); }} type="button">Refresh Courses</button>
                                            <span style={{ marginLeft: 12, color: '#666' }}>{loadingCourses ? 'Loading...' : coursesMessage}</span>
                                        </div>
                                        
                                        <div className="form-group" style={{alignSelf: 'flex-end'}}>
                                            <button 
                                                className="btn success" 
                                                onClick={generateQRCode}
                                                disabled={!selectedCourse || hasNoClassToday(selectedCourse) || globalSessionActive}
                                            >
                                                Generate QR Code
                                            </button>
                                        </div>
                                    </div>

                                    <div className="action-buttons">
                                        <button className="btn" onClick={displayQRCode} disabled={!currentQR}>
                                            Display on Screen
                                        </button>
                                        <button className="btn" onClick={printQRCode} disabled={!currentQR}>
                                            Print QR Code
                                        </button>
                                        <button className="btn warning" onClick={markNoClass} disabled={!selectedCourse || globalSessionActive}>
                                            No Class Today
                                        </button>
                                    </div>
                                    
                                   

                                    {!currentQR && (
                                        <div className="info-message">
                                            💡 Select a course from your assigned courses and generate QR code to start attendance session.
                                            The QR code will be valid for 15 minutes.
                                        </div>
                                    )}
                                </>
                            ) : (
                                <p className="loading">Loading user data...</p>
                            )}
                        </div>
                    )}

                    {/* Manual Attendance Section */}
                    {activeSection === 'manual-attendance' && (
                        <div className="section">
                            <h2>Mark Attendance Manually</h2>
                            
                            <div className="info-message">
                                💡 Select a course and date to view enrolled students. Mark attendance as Present or Absent for each student.
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Select Course:</label>
                                    <select 
                                        value={manualAttendanceCourse}
                                        onChange={(e) => {
                                            setManualAttendanceCourse(e.target.value);
                                            loadStudentsForCourse(e.target.value);
                                        }}
                                    >
                                        <option value="">-- Select Course --</option>
                                        {teacherCourses.map(course => (
                                            <option key={course.code} value={course.code}>
                                                {course.name} ({course.code})
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                
                                <div className="form-group">
                                    <label>Lecture Date:</label>
                                    <input 
                                        type="date" 
                                        value={attendanceDate}
                                        onChange={(e) => {
                                            setAttendanceDate(e.target.value);
                                            if (manualAttendanceCourse && e.target.value) {
                                                loadStudentsForCourse(manualAttendanceCourse, e.target.value);
                                            }
                                        }}
                                        max={new Date().toISOString().split('T')[0]}
                                    />
                                </div>
                            </div>

                            {students.length > 0 && attendanceDate && (
                                <>
                                    <div style={{ marginTop: '20px', marginBottom: '15px', display: 'flex', gap: '10px' }}>
                                        <button className="btn success" onClick={markAllPresent}>
                                            ✅ Mark All Present
                                        </button>
                                        <button className="btn danger" onClick={markAllAbsent}>
                                            ❌ Mark All Absent
                                        </button>
                                    </div>

                                    <div className="table-container">
                                        <table>
                                            <thead>
                                                <tr>
                                                    <th>Sr#</th>
                                                    <th>Roll No</th>
                                                    <th>Name</th>
                                                    <th style={{ textAlign: 'center' }}>Present</th>
                                                    <th style={{ textAlign: 'center' }}>Absent</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {students.map((student, index) => (
                                                    <tr key={student.username}>
                                                        <td>{index + 1}</td>
                                                        <td>{student.rollNo || 'N/A'}</td>
                                                        <td>{student.name || student.username}</td>
                                                        <td style={{ textAlign: 'center' }}>
                                                            <input 
                                                                type="radio" 
                                                                name={`attendance-${student.username}`}
                                                                checked={attendanceStatuses[student.username] === 'present'}
                                                                onChange={() => markManualAttendance(student.username, 'present')}
                                                            />
                                                        </td>
                                                        <td style={{ textAlign: 'center' }}>
                                                            <input 
                                                                type="radio" 
                                                                name={`attendance-${student.username}`}
                                                                checked={attendanceStatuses[student.username] === 'absent'}
                                                                onChange={() => markManualAttendance(student.username, 'absent')}
                                                            />
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>

                                    <div className="action-buttons" style={{ marginTop: '20px' }}>
                                        <button className="btn success" onClick={saveAllAttendance}>
                                            Save Attendance
                                        </button>
                                    </div>
                                </>
                            )}

                            {students.length === 0 && manualAttendanceCourse && (
                                <div className="no-data" style={{ marginTop: '20px' }}>
                                    No students enrolled in this course
                                </div>
                            )}
                        </div>
                    )}

                    {/* Attendance Report Section */}
                    {activeSection === 'attendance' && (
                        <div className="section">
                            <h2>Attendance Records</h2>
                            
                            <div className="form-row">
                                <div className="form-group">
                                    <label>Select Course:</label>
                                    <select 
                                        value={reportCourse}
                                        onChange={(e) => setReportCourse(e.target.value)}
                                    >
                                        <option value="">-- Select Course --</option>
                                        {teacherCourses.map(course => (
                                            <option key={course.code} value={course.code}>
                                                {course.name} ({course.code})
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                
                                <div className="form-group">
                                    <label>Session Date:</label>
                                    <input 
                                        type="date" 
                                        value={attendanceDate}
                                        onChange={(e) => setAttendanceDate(e.target.value)}
                                        max={new Date().toISOString().split('T')[0]}
                                    />
                                </div>
                                
                                <div className="form-group" style={{alignSelf: 'flex-end'}}>
                                    <button className="btn success" onClick={loadAttendanceReport}>
                                        Load Report
                                    </button>
                                </div>
                            </div>

                            {sessionCheckMessage && (
                                <div className={sessionExists ? "info-message" : "error-message"} style={{ marginTop: '20px' }}>
                                    {sessionCheckMessage}
                                </div>
                            )}

                            <div className="action-buttons">
                                <button className="btn" onClick={downloadSessionsPDF} disabled={!reportCourse}>
                                    📄 Download Sessions Report PDF
                                </button>
                                <button className="btn" onClick={viewDetailedReport} disabled={!reportCourse || !attendanceDate || !sessionExists}>
                                    📊 View Detailed Report
                                </button>
                            </div>

                            <div className="table-container">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Student Name</th>
                                            <th>Roll No</th>
                                            <th>Status</th>
                                            <th>Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {attendanceData.length === 0 ? (
                                            <tr>
                                                <td colSpan="5" className="no-data">
                                                    Select a course and month to view attendance records
                                                </td>
                                            </tr>
                                        ) : (
                                            attendanceData.map(record => (
                                                <tr key={record.id}>
                                                    <td>{record.date}</td>
                                                    <td>{record.studentName}</td>
                                                    <td>{record.rollNo}</td>
                                                    <td className={`status-${record.status}`}>
                                                        {record.status.toUpperCase()}
                                                    </td>
                                                    <td>{new Date(record.timestamp).toLocaleTimeString()}</td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* No Class Management Section */}
                    {activeSection === 'no-class' && (
                        <div className="section">
                            <h2>No Class Management</h2>
                            
                            <div className="info-message">
                                💡 Manage "No Class" status for your courses. When marked as "No Class", 
                                students will see a "No Class Today" message instead of the QR code.
                            </div>

                            <div className="no-class-management">
                                <h3>Mark No Class for Today</h3>
                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Select Course:</label>
                                        <select 
                                            value={selectedCourse}
                                            onChange={(e) => setSelectedCourse(e.target.value)}
                                        >
                                            <option value="">-- Select Course --</option>
                                            {teacherCourses.map(course => (
                                                <option key={course.code} value={course.code}>
                                                    {course.name} ({course.code})
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    
                                    <div className="form-group" style={{alignSelf: 'flex-end'}}>
                                        <button className="btn warning" onClick={markNoClass} disabled={!selectedCourse || globalSessionActive}>
                                            Mark No Class
                                        </button>
                                    </div>
                                </div>

                                <h3>Today's No Class Status</h3>
                                <div className="no-class-list">
                                    {teacherCourses.length === 0 ? (
                                        <p className="no-data">No courses assigned</p>
                                    ) : (
                                        teacherCourses.map(course => {
                                            const isNoClass = hasNoClassToday(course.code);
                                            return (
                                                <div key={course.code} className="no-class-item">
                                                    <div className="course-info">
                                                        <strong>{course.name}</strong> ({course.code})
                                                    </div>
                                                    <div className="status-info">
                                                        {isNoClass ? (
                                                            <>
                                                                <span className="no-class-status">🚫 No Class Today</span>
                                                                <button 
                                                                    className="btn danger"
                                                                    onClick={() => removeNoClassFlag(course.code)}
                                                                >
                                                                    Remove
                                                                </button>
                                                            </>
                                                        ) : (
                                                            <span className="class-status">✅ Class Scheduled</span>
                                                        )}
                                                    </div>
                                                </div>
                                            );
                                        })
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Load QRCode library */}
            <script src="https://cdn.rawgit.com/davidshimjs/qrcodejs/gh-pages/qrcode.min.js"></script>
        </div>
    );
};

export default Teacher;