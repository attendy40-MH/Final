# QR Code Based Attendance System

A comprehensive **MERN Stack** (MongoDB, Express.js, React, Node.js) attendance management system with real-time notifications using Socket.io. Teachers can generate QR codes for classes, and students can scan them using their mobile devices to mark attendance.

---

## 🌟 Features

### **Admin Portal**
- ✅ Complete CRUD operations for users (students and teachers)
- ✅ Complete CRUD operations for courses
- ✅ Assign courses to students and teachers
- ✅ View all attendance records
- ✅ Manage system users

### **Teacher Portal**
- ✅ Generate QR codes for classes with expiry time
- ✅ Display QR code on screen for students to scan
- ✅ Print QR codes
- ✅ Mark attendance manually with radio buttons
- ✅ View attendance records and reports
- ✅ Export attendance as PDF
- ✅ **Real-time notifications** when students scan QR codes
- ✅ See student name, roll number instantly
- ✅ View monthly attendance statistics

### **Student Portal**
- ✅ Scan QR codes using mobile camera
- ✅ Manual QR code entry option
- ✅ **Real-time notifications** when teacher starts a class
- ✅ View active class sessions with countdown timer
- ✅ Only shows scanner when class is active
- ✅ View today's attendance
- ✅ View monthly attendance reports

### **Real-Time Features**
- ✅ Socket.io integration for instant updates
- ✅ Students get notified when teacher creates class
- ✅ Teachers get notified when student marks attendance
- ✅ Notification badge with unread count
- ✅ Browser notifications support

---

## 📋 Prerequisites

Before running this project, ensure you have the following installed:

1. **Node.js** (v16 or higher)
   - Download from: https://nodejs.org/
   - Check version: `node --version`

2. **MongoDB** (Community Edition)
   - Download from: https://www.mongodb.com/try/download/community
   - Or use MongoDB Atlas (cloud): https://www.mongodb.com/cloud/atlas
   - Check if running: `mongosh` or MongoDB Compass

3. **Git** (optional, for cloning)
   - Download from: https://git-scm.com/

4. **Modern Web Browser** (Chrome, Firefox, Edge, Safari)

---

## 🚀 Installation & Setup

### **Step 1: Clone or Download the Project**

```bash
# If using Git
git clone <repository-url>

# Or download and extract the ZIP file
```

### **Step 2: Install Backend Dependencies**

```bash
# Navigate to Backend folder
cd Backend

# Install dependencies
npm install

# If you face timeout issues, use:
npm install --fetch-timeout=120000
```

**Backend Dependencies:**
- `express` - Web framework
- `mongoose` - MongoDB ODM
- `cors` - Cross-origin resource sharing
- `dotenv` - Environment variables
- `bcryptjs` - Password hashing
- `jsonwebtoken` - JWT authentication
- `socket.io` - Real-time communication
- `qrcode` - QR code generation
- `pdfkit` - PDF generation

### **Step 3: Configure Backend Environment**

Create a `.env` file in the `Backend` folder:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/qr_attendance
JWT_SECRET=your-secret-key-here-change-this-in-production
```

**For MongoDB Atlas (Cloud):**
```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/qr_attendance
```

### **Step 4: Install Frontend Dependencies**

```bash
# Navigate to Frontend folder
cd ../Frontend

# Install dependencies
npm install

# If you face timeout issues, use:
npm install --fetch-timeout=120000
```

**Frontend Dependencies:**
- `react` - UI library
- `react-dom` - React DOM rendering
- `react-router-dom` - Client-side routing
- `socket.io-client` - Real-time client
- `jsqr` - QR code scanning
- `vite` - Build tool & dev server

### **Step 5: Start MongoDB**

**Windows:**
```bash
# If MongoDB is installed as a service, it starts automatically
# Or start manually:
mongod
```

**Mac/Linux:**
```bash
sudo systemctl start mongod
# Or
brew services start mongodb-community
```

**Verify MongoDB is running:**
```bash
mongosh
# Should connect successfully
```

### **Step 6: Start Backend Server**

```bash
# In Backend folder
cd Backend
npm start
```

**Expected Output:**
```
Connected to MongoDB
Server listening on port 5000
```

**The backend will run on:** `http://localhost:5000`

### **Step 7: Start Frontend Development Server**

```bash
# In Frontend folder (open new terminal)
cd Frontend
npm run dev
```

**Expected Output:**
```
VITE ready in X ms
Local:   http://localhost:3001/
Network: http://192.168.x.x:3001/
```

**The frontend will run on:** `http://localhost:3001` (or 3000, 3002 depending on availability)

---

## 🔑 Default Login Credentials

The system will automatically create default users on first run:

### **Admin Account**
- **Username:** `admin`
- **Password:** `admin123`
- **Role:** Administrator

### **Teacher Account**
- **Username:** `teacher1`
- **Password:** `teacher123`
- **Name:** Anbreen Kausar
- **Role:** Teacher

### **Student Account**
- **Username:** `student1`
- **Password:** `student123`
- **Name:** Mahnoor Akhtar
- **Roll No:** 23021519-080
- **Role:** Student

---

## 📖 How to Use

### **For Admin:**

1. **Login** with admin credentials
2. **Add Courses:**
   - Go to "Manage Courses"
   - Click "Add New Course"
   - Enter course code (e.g., CS-103) and name (e.g., Operating System)
   
3. **Add Users:**
   - Go to "Manage Users"
   - Click "Add New User"
   - Fill in details (username, password, name, role, etc.)
   
4. **Assign Courses:**
   - Select a user
   - Choose courses to assign
   - Click "Assign Courses"

### **For Teachers:**

1. **Login** with teacher credentials
2. **Generate QR Code:**
   - Go to "Generate QR Code"
   - Select a course
   - Select today's date
   - Click "Generate QR Code"
   
3. **Display QR Code:**
   - Click "Display QR on Screen"
   - QR code opens in new window
   - Students can scan this with their phones
   
4. **Mark Attendance Manually:**
   - Go to "Mark Attendance"
   - Select course and date
   - Use radio buttons to mark Present/Absent
   - Click "Save Attendance"
   
5. **View Notifications:**
   - Click bell icon 🔔 (top right)
   - See real-time updates when students scan QR

### **For Students:**

1. **Login** with student credentials
2. **Scan QR Code:**
   - Active classes appear automatically with countdown timer
   - Camera scanner appears when class is active
   - Point camera at teacher's QR code
   - Attendance marked automatically
   
3. **Manual Entry:**
   - If camera doesn't work
   - Copy QR data from teacher
   - Paste in "Manual Entry" field
   
4. **View Attendance:**
   - "Today's Attendance" - See today's marked classes
   - "Monthly Report" - See full month statistics

---

## 🔧 Troubleshooting

### **MongoDB Connection Error**
```
Error: connect ECONNREFUSED localhost:27017
```
**Solution:** 
- Make sure MongoDB is running
- Check MongoDB URI in `.env` file
- Try: `mongosh` to verify connection

### **Port Already in Use**
```
Error: listen EADDRINUSE :::5000
```
**Solution:**
```bash
# Windows
Get-NetTCPConnection -LocalPort 5000 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Mac/Linux
lsof -ti:5000 | xargs kill -9
```

### **CORS Error**
```
Access-Control-Allow-Origin error
```
**Solution:** Backend `server.js` already configured for multiple ports (3000, 3001, 3002, 5173)

### **Camera Not Working**
**Solution:**
- Use HTTPS or localhost
- Allow camera permissions in browser
- Use manual QR entry as alternative

### **QR Code Not Scanning**
**Solution:**
- Ensure good lighting
- Hold camera steady
- Try manual entry option
- Check if class session hasn't expired

---

## 📁 Project Structure

```
Mern-stack-main/
│
├── Backend/
│   ├── models/           # Database schemas
│   │   ├── User.js
│   │   ├── Course.js
│   │   ├── Attendance.js
│   │   ├── ClassSession.js
│   │   └── Notification.js
│   │
│   ├── routes/           # API endpoints
│   │   ├── admin.js      # Admin CRUD operations
│   │   ├── teacher.js    # Teacher operations
│   │   ├── attendance.js # Attendance operations
│   │   ├── auth.js       # Authentication
│   │   ├── courses.js    # Course operations
│   │   └── notifications.js # Notification operations
│   │
│   ├── middleware/       # Auth middleware
│   │   └── auth.js
│   │
│   ├── server.js         # Express server + Socket.io
│   ├── package.json      # Backend dependencies
│   └── .env              # Environment variables
│
├── Frontend/
│   ├── src/
│   │   ├── pages/        # Main application pages
│   │   │   ├── Admin.jsx           # Admin dashboard
│   │   │   ├── Teacher.jsx         # Teacher dashboard
│   │   │   ├── StudentDashboard.jsx # Student dashboard
│   │   │   ├── LoginSignUp.jsx     # Login page
│   │   │   └── HomePage.jsx        # Landing page
│   │   │
│   │   ├── components/   # Reusable components
│   │   ├── system.jsx    # System utilities & API calls
│   │   ├── App.jsx       # Main app component
│   │   └── main.jsx      # Entry point
│   │
│   ├── package.json      # Frontend dependencies
│   └── vite.config.js    # Vite configuration
│
└── README.md             # This file
```

---

## 🔐 Security Features

- ✅ Password hashing with bcrypt
- ✅ JWT token authentication
- ✅ Protected API routes with middleware
- ✅ Role-based access control (Admin, Teacher, Student)
- ✅ QR code expiry validation
- ✅ Session management
- ✅ CORS configuration

---

## 🌐 API Endpoints

### **Authentication**
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get current user

### **Admin**
- `GET /api/admin/users` - Get all users
- `POST /api/admin/users` - Create user
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user
- `GET /api/admin/courses` - Get all courses
- `POST /api/admin/courses` - Create course
- `PUT /api/admin/courses/:id` - Update course
- `DELETE /api/admin/courses/:id` - Delete course

### **Teacher**
- `GET /api/teacher/courses` - Get teacher's courses
- `POST /api/teacher/generate` - Generate QR code
- `GET /api/teacher/active-sessions` - Get active sessions
- `POST /api/teacher/mark-attendance` - Mark manual attendance

### **Attendance**
- `POST /api/attendance/scan` - Scan QR code
- `GET /api/attendance` - Get attendance records
- `GET /api/attendance/report` - Get attendance report

### **Notifications**
- `GET /api/notifications` - Get all notifications
- `GET /api/notifications/unread` - Get unread count
- `PUT /api/notifications/:id/read` - Mark as read
- `DELETE /api/notifications/:id` - Delete notification

---

## 🎯 Key Technologies

**Backend:**
- Node.js + Express.js
- MongoDB + Mongoose
- Socket.io (Real-time)
- JWT Authentication
- QRCode & PDFKit

**Frontend:**
- React 18
- Vite
- React Router v6
- Socket.io Client
- jsQR (QR scanning)

---

## 📱 Mobile Responsive

✅ Fully responsive design
✅ Works on mobile, tablet, and desktop
✅ Mobile camera scanning support
✅ Touch-friendly interface

---

## 🐛 Known Issues & Solutions

1. **Radio buttons not visible:** Already fixed with black color and larger size
2. **Duplicate QR codes:** Already fixed by clearing innerHTML before generation
3. **Scanner not showing:** Already fixed - shows only when class is active
4. **Socket connection:** Configured for multiple ports (3000-3002, 5173)

---

## 📝 Database Schema

### **Users Collection**
```javascript
{
  username: String,
  password: String (hashed),
  name: String,
  email: String,
  role: String, // 'admin', 'teacher', 'student'
  rollNo: String, // for students
  courses: [String] // course codes
}
```

### **Courses Collection**
```javascript
{
  code: String,
  name: String
}
```

### **Attendance Collection**
```javascript
{
  studentId: String,
  studentName: String,
  rollNo: String,
  courseId: String,
  courseName: String,
  teacherId: String,
  teacherName: String,
  date: String,
  timestamp: Date,
  status: String // 'present', 'absent'
}
```

### **ClassSession Collection**
```javascript
{
  courseId: String,
  courseName: String,
  teacherId: String,
  teacherName: String,
  timestamp: Date,
  expiry: Number, // epoch ms
  active: Boolean
}
```

### **Notifications Collection**
```javascript
{
  userId: String,
  type: String, // 'class_created', 'attendance_marked'
  title: String,
  message: String,
  data: Object,
  read: Boolean,
  createdAt: Date
}
```

---

## 💡 Tips for Deployment

### **For Production:**

1. **Change JWT Secret:**
   - Generate strong secret: `openssl rand -base64 32`
   - Update in `.env` file

2. **Use MongoDB Atlas:**
   - Free cloud MongoDB hosting
   - Better reliability than local

3. **Environment Variables:**
   - Never commit `.env` to Git
   - Use different values for production

4. **Backend Deployment (Heroku, Railway, Render):**
   - Set environment variables
   - Update CORS origins
   - Use process.env.PORT

5. **Frontend Deployment (Vercel, Netlify):**
   - Update API URLs to production backend
   - Build: `npm run build`
   - Deploy `dist` folder

---

## 👥 User Roles & Permissions

| Feature | Admin | Teacher | Student |
|---------|-------|---------|---------|
| Manage Users | ✅ | ❌ | ❌ |
| Manage Courses | ✅ | ❌ | ❌ |
| Generate QR | ❌ | ✅ | ❌ |
| Mark Attendance | ❌ | ✅ | ❌ |
| Scan QR Code | ❌ | ❌ | ✅ |
| View Own Attendance | ❌ | ❌ | ✅ |
| View All Attendance | ✅ | ✅ | ❌ |
| Real-time Notifications | ❌ | ✅ | ✅ |

---

## 🆘 Support & Contact

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

## 📄 License

This project is open-source and available for educational purposes.

---

## 🙏 Acknowledgments

- QRCode.js for QR generation
- jsQR for QR scanning
- Socket.io for real-time features
- MongoDB for database
- React & Vite for frontend

---

## ✨ Future Enhancements

- 📧 Email notifications
- 📊 Advanced analytics dashboard
- 📅 Attendance scheduling
- 🔄 Bulk operations
- 📱 Mobile app (React Native)
- 🌍 Multi-language support
- 🎨 Theme customization
- 📥 Excel import/export

---

**Made with ❤️ using MERN Stack + Socket.io**
