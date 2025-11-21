// This system module now proxies requests to the backend API.
const API_BASE = (typeof process !== 'undefined' && process.env && process.env.REACT_APP_API_BASE) ? process.env.REACT_APP_API_BASE : 'http://localhost:5000/api';

class AttendanceSystem {
    constructor() {
        // Try to restore session from sessionStorage on initialization
        const storedToken = sessionStorage.getItem('authToken');
        const storedUser = sessionStorage.getItem('authUser');
        
        this.token = storedToken || null;
        this.currentUser = storedUser ? JSON.parse(storedUser) : null;
    }

    // Auth helpers
    setAuth(token, user) {
        this.token = token;
        this.currentUser = user || null;
        
        // Store in sessionStorage (cleared when browser/tab closes)
        if (token && user) {
            sessionStorage.setItem('authToken', token);
            sessionStorage.setItem('authUser', JSON.stringify(user));
        }
    }

    getToken() {
        // Always check sessionStorage first in case of refresh
        if (!this.token) {
            this.token = sessionStorage.getItem('authToken');
        }
        return this.token;
    }

    getCurrentUser() {
        // Always check sessionStorage first in case of refresh
        if (!this.currentUser) {
            const storedUser = sessionStorage.getItem('authUser');
            this.currentUser = storedUser ? JSON.parse(storedUser) : null;
        }
        return this.currentUser;
    }

    clearAuth() {
        this.token = null;
        this.currentUser = null;
        
        // Clear sessionStorage
        sessionStorage.removeItem('authToken');
        sessionStorage.removeItem('authUser');
        
        // Clear any browser history state
        if (window.history && window.history.pushState) {
            window.history.pushState(null, '', window.location.href);
            window.onpopstate = function() {
                window.history.pushState(null, '', window.location.href);
            };
        }
    }

    async login(username, password) {
        const resp = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();
        if (!resp.ok) return { success: false, message: data.message || 'Login failed' };
        // store token and user in sessionStorage
        this.setAuth(data.token, data.user);
        return { success: true, user: data.user };
    }

    logout() {
        this.clearAuth();
        // Force redirect to login and prevent back button
        window.location.replace('/');
    }

    // Check if user is authenticated
    isAuthenticated() {
        const token = this.getToken();
        if (!token) return false;
        
        try {
            // Basic JWT validation (check if it's expired)
            const payload = JSON.parse(atob(token.split('.')[1]));
            const isExpired = payload.exp && (Date.now() >= payload.exp * 1000);
            
            if (isExpired) {
                this.clearAuth();
                return false;
            }
            
            return true;
        } catch (err) {
            this.clearAuth();
            return false;
        }
    }

    // Fetch latest current user from server (useful after admin updates)
    async refreshCurrentUser() {
        const token = this.getToken();
        if (!token) return null;
        try {
            const resp = await fetch(`${API_BASE}/auth/me`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await resp.json();
            if (resp.ok && data.user) {
                this.currentUser = data.user;
                return data.user;
            }
            return null;
        } catch (err) {
            console.error('refreshCurrentUser error', err);
            return null;
        }
    }

    async generateQRCode(courseId, durationMinutes = 15) {
        const token = this.getToken();
        const resp = await fetch(`${API_BASE}/teacher/generate`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ courseId, durationMinutes })
        });
        return await resp.json();
    }

    async getCurrentQR(courseId) {
        const token = this.getToken();
        const url = new URL(`${API_BASE}/teacher/current`);
        if (courseId) url.searchParams.append('courseId', courseId);
        const resp = await fetch(url.toString(), { headers: { 'Authorization': `Bearer ${token}` } });
        return await resp.json();
    }

    async markAttendance(qrString) {
        const token = this.getToken();
        const resp = await fetch(`${API_BASE}/attendance/scan`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ qrString })
        });
        return await resp.json();
    }

    async getAttendanceToday() {
        const token = this.getToken();
        const resp = await fetch(`${API_BASE}/attendance/today`, { headers: { 'Authorization': `Bearer ${token}` } });
        return await resp.json();
    }

    async getAttendanceMonth(month, year) {
        const token = this.getToken();
        const url = new URL(`${API_BASE}/attendance/month`);
        url.searchParams.append('month', month);
        url.searchParams.append('year', year);
        const resp = await fetch(url.toString(), { headers: { 'Authorization': `Bearer ${token}` } });
        return await resp.json();
    }

    async addStudent(name, rollNo) {
        const token = this.getToken();
        const resp = await fetch(`${API_BASE}/admin/students`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ name, rollNo })
        });
        return await resp.json();
    }

    async addCourse(code, name) {
        const token = this.getToken();
        const resp = await fetch(`${API_BASE}/admin/courses`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ code, name })
        });
        return await resp.json();
    }

    async signup(email, password, fullName, role, rollNo) {
        const resp = await fetch(`${API_BASE}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                name: fullName,
                role,
                rollNo,
                username: email.split('@')[0] // derive username from email
            })
        });
        const data = await resp.json();
        if (!resp.ok) return { success: false, message: data.message || 'Signup failed' };
        return { success: true, user: data.user };
    }
}

export const system = new AttendanceSystem();