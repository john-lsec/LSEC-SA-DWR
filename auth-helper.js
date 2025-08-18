// auth-helper.js - Consistent authentication helper for all pages
// Include this script in all HTML pages that need authentication

const AUTH_CONFIG = {
    API_BASE: '/.netlify/functions/',
    LOGIN_PAGE: '/login.html',
    DASHBOARD_PAGE: '/dashboard.html',
    TOKEN_KEY: 'jwtToken',
    USER_KEY: 'userName',
    ROLE_KEY: 'userRole',
    USER_ID_KEY: 'userId',
    EMAIL_KEY: 'userEmail'
};

// Authentication Helper Object
const AuthHelper = {
    // Check if user is authenticated
    checkAuth: async function() {
        const token = localStorage.getItem(AUTH_CONFIG.TOKEN_KEY);
        
        if (!token) {
            this.redirectToLogin();
            return false;
        }
        
        // Verify token with backend
        try {
            const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/verify', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                this.clearAuth();
                this.redirectToLogin();
                return false;
            }
            
            const data = await response.json();
            if (data.valid) {
                // Update stored user info
                this.updateUserInfo(data);
                return true;
            } else {
                this.clearAuth();
                this.redirectToLogin();
                return false;
            }
        } catch (error) {
            console.error('Auth verification failed:', error);
            // Allow user to continue for now
            return true;
        }
    },
    
    // Update user information in localStorage
    updateUserInfo: function(data) {
        if (data.name) localStorage.setItem(AUTH_CONFIG.USER_KEY, data.name);
        if (data.role) localStorage.setItem(AUTH_CONFIG.ROLE_KEY, data.role);
        if (data.userId) localStorage.setItem(AUTH_CONFIG.USER_ID_KEY, data.userId);
        if (data.email) localStorage.setItem(AUTH_CONFIG.EMAIL_KEY, data.email);
    },
    
    // Get authentication token
    getToken: function() {
        return localStorage.getItem(AUTH_CONFIG.TOKEN_KEY);
    },
    
    // Get user information
    getUserInfo: function() {
        return {
            name: localStorage.getItem(AUTH_CONFIG.USER_KEY) || 'User',
            role: localStorage.getItem(AUTH_CONFIG.ROLE_KEY) || 'Employee',
            userId: localStorage.getItem(AUTH_CONFIG.USER_ID_KEY),
            email: localStorage.getItem(AUTH_CONFIG.EMAIL_KEY)
        };
    },
    
    // Clear authentication data
    clearAuth: function() {
        localStorage.removeItem(AUTH_CONFIG.TOKEN_KEY);
        localStorage.removeItem(AUTH_CONFIG.USER_KEY);
        localStorage.removeItem(AUTH_CONFIG.ROLE_KEY);
        localStorage.removeItem(AUTH_CONFIG.USER_ID_KEY);
        localStorage.removeItem(AUTH_CONFIG.EMAIL_KEY);
        // Also clear old session token if it exists
        localStorage.removeItem('sessionToken');
    },
    
    // Redirect to login page
    redirectToLogin: function() {
        window.location.href = AUTH_CONFIG.LOGIN_PAGE;
    },
    
    // Redirect to dashboard
    redirectToDashboard: function() {
        window.location.href = AUTH_CONFIG.DASHBOARD_PAGE;
    },
    
    // Logout function
    logout: async function() {
        const token = this.getToken();
        
        if (token) {
            try {
                await fetch(AUTH_CONFIG.API_BASE + 'auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
        
        this.clearAuth();
        this.redirectToLogin();
    },
    
    // API call helper with authentication
    apiCall: async function(endpoint, options = {}) {
        const token = this.getToken();
        
        if (!token && !options.skipAuth) {
            this.redirectToLogin();
            throw new Error('No authentication token');
        }
        
        try {
            const headers = {
                'Content-Type': 'application/json',
                ...options.headers
            };
            
            if (token && !options.skipAuth) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            const response = await fetch(AUTH_CONFIG.API_BASE + 'api/' + endpoint, {
                ...options,
                headers: headers
            });
            
            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuth();
                this.redirectToLogin();
                throw new Error('Authentication expired');
            }
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            
            // Handle empty responses (204 No Content)
            if (response.status === 204) {
                return null;
            }
            
            return await response.json();
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            throw error;
        }
    },
    
    // Login function
    login: async function(username, password) {
        try {
            const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store authentication data
                localStorage.setItem(AUTH_CONFIG.TOKEN_KEY, data.token);
                localStorage.setItem(AUTH_CONFIG.USER_KEY, data.name || username);
                localStorage.setItem(AUTH_CONFIG.ROLE_KEY, data.role || 'Employee');
                localStorage.setItem(AUTH_CONFIG.USER_ID_KEY, data.userId);
                localStorage.setItem(AUTH_CONFIG.EMAIL_KEY, data.email || '');
                
                // Clean up old session token if it exists
                localStorage.removeItem('sessionToken');
                
                return { success: true, data };
            } else {
                return { 
                    success: false, 
                    error: data.error || 'Login failed',
                    attemptsLeft: data.attemptsLeft
                };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { 
                success: false, 
                error: 'Connection error. Please check your internet and try again.'
            };
        }
    },
    
    // Initialize authentication on page load
    init: async function(options = {}) {
        // Skip auth check on login page
        if (window.location.pathname.includes('login')) {
            // Check if already logged in
            const token = this.getToken();
            if (token) {
                try {
                    const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/verify', {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    
                    if (response.ok) {
                        // Already logged in, redirect to dashboard
                        this.redirectToDashboard();
                    }
                } catch (error) {
                    console.error('Session check failed:', error);
                }
            }
            return;
        }
        
        // Check authentication for protected pages
        const isAuthenticated = await this.checkAuth();
        
        if (isAuthenticated && options.onAuthenticated) {
            options.onAuthenticated(this.getUserInfo());
        }
        
        return isAuthenticated;
    }
};

// Auto-initialize on DOM load for non-login pages
if (!window.location.pathname.includes('login')) {
    document.addEventListener('DOMContentLoaded', function() {
        AuthHelper.init({
            onAuthenticated: function(userInfo) {
                // Update any user display elements
                const userNameElements = document.querySelectorAll('#userName, .user-name');
                const userRoleElements = document.querySelectorAll('#userRole, .user-role');
                
                userNameElements.forEach(el => {
                    if (el) el.textContent = userInfo.name;
                });
                
                userRoleElements.forEach(el => {
                    if (el) el.textContent = userInfo.role;
                });
            }
        });
    });
}
