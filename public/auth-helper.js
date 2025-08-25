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
    EMAIL_KEY: 'userEmail',
    REDIRECT_KEY: 'intendedPage'  // Store where user was trying to go
};

// Authentication Helper Object
const AuthHelper = {
    // Check if user is authenticated
    checkAuth: async function() {
        const token = localStorage.getItem(AUTH_CONFIG.TOKEN_KEY);
        
        if (!token) {
            // Store current page before redirecting to login
            this.storeIntendedPage();
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
                this.storeIntendedPage();
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
                this.storeIntendedPage();
                this.redirectToLogin();
                return false;
            }
        } catch (error) {
            console.error('Auth verification failed:', error);
            // Allow user to continue for now
            return true;
        }
    },
    
    // Store the page user was trying to access
    storeIntendedPage: function() {
        const currentPath = window.location.pathname + window.location.search;
        // Don't store login page as intended destination
        if (!currentPath.includes('login')) {
            localStorage.setItem(AUTH_CONFIG.REDIRECT_KEY, currentPath);
        }
    },
    
    // Get and clear intended page
    getIntendedPage: function() {
        const intendedPage = localStorage.getItem(AUTH_CONFIG.REDIRECT_KEY);
        if (intendedPage) {
            localStorage.removeItem(AUTH_CONFIG.REDIRECT_KEY);
            return intendedPage;
        }
        return null;
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
            email: localStorage.getItem(AUTH_CONFIG.EMAIL_KEY),
            // Add additional properties for compatibility
            first_name: localStorage.getItem(AUTH_CONFIG.USER_KEY) ? localStorage.getItem(AUTH_CONFIG.USER_KEY).split(' ')[0] : '',
            last_name: localStorage.getItem(AUTH_CONFIG.USER_KEY) ? localStorage.getItem(AUTH_CONFIG.USER_KEY).split(' ').slice(1).join(' ') : '',
            username: localStorage.getItem(AUTH_CONFIG.USER_KEY) || 'User'
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
    
    // Redirect to intended page or dashboard
    redirectToIntendedOrDashboard: function() {
        const intendedPage = this.getIntendedPage();
        if (intendedPage) {
            window.location.href = intendedPage;
        } else {
            this.redirectToDashboard();
        }
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
                console.error('Logout API call failed:', error);
            }
        }
        
        this.clearAuth();
        this.redirectToLogin();
    },
    
    // Make API calls with authentication
    apiCall: async function(endpoint, options = {}) {
        const token = this.getToken();
        
        if (!token) {
            throw new Error('No authentication token available');
        }
        
        const url = endpoint.startsWith('http') ? endpoint : AUTH_CONFIG.API_BASE + endpoint;
        
        const defaultHeaders = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
        
        const finalOptions = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers
            }
        };
        
        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
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
    
    // ✅ NEW: Format user name for display (FIXES YOUR ERROR)
    formatUserName: function(user, format = 'full') {
        if (!user) {
            return 'Unknown User';
        }

        // Handle string input (username)
        if (typeof user === 'string') {
            return user;
        }

        const firstName = user.first_name || user.firstName || '';
        const lastName = user.last_name || user.lastName || '';
        const username = user.username || user.name || user.email || '';

        switch (format.toLowerCase()) {
            case 'full':
                if (firstName && lastName) {
                    return `${firstName} ${lastName}`;
                } else if (firstName) {
                    return firstName;
                } else if (lastName) {
                    return lastName;
                } else {
                    return username;
                }
                
            case 'first':
                return firstName || username;
                
            case 'last':
                return lastName || username;
                
            case 'initials':
                if (firstName && lastName) {
                    return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
                } else if (firstName) {
                    return firstName.charAt(0).toUpperCase();
                } else if (username) {
                    return username.charAt(0).toUpperCase();
                }
                return 'U';
                
            case 'username':
                return username;
                
            case 'formal':
                if (firstName && lastName) {
                    return `${lastName}, ${firstName}`;
                } else {
                    return this.formatUserName(user, 'full');
                }
                
            default:
                return this.formatUserName(user, 'full');
        }
    },
    
    // ✅ NEW: Initialize authentication on page load (FIXES COMPATIBILITY)
    init: async function(options = {}) {
        // Check if we're on the login page
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
                        // Already logged in, redirect to intended page or dashboard
                        this.redirectToIntendedOrDashboard();
                        return true;
                    }
                } catch (error) {
                    console.error('Session check failed:', error);
                }
            }
            return false;
        }
        
        // Check authentication for protected pages
        const isAuthenticated = await this.checkAuth();
        
        if (isAuthenticated && options.onAuthenticated) {
            const userInfo = this.getUserInfo();
            options.onAuthenticated(userInfo);
        }
        
        return isAuthenticated;
    },
    
    // ✅ NEW: Get current user (for compatibility)
    getCurrentUser: function() {
        return this.getUserInfo();
    },
    
    // ✅ NEW: Role checking functions (for compatibility)
    hasRole: function(role) {
        const userInfo = this.getUserInfo();
        return userInfo.role === role;
    },
    
    hasAnyRole: function(roles) {
        const userInfo = this.getUserInfo();
        return roles.includes(userInfo.role);
    },
    
    // ✅ NEW: Show message function (for compatibility)
    showMessage: function(message, type = 'info', duration = 5000) {
        // Create or get message container
        let messageContainer = document.getElementById('message-container');
        if (!messageContainer) {
            messageContainer = document.createElement('div');
            messageContainer.id = 'message-container';
            messageContainer.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 400px;
            `;
            document.body.appendChild(messageContainer);
        }

        // Create message element
        const messageElement = document.createElement('div');
        messageElement.style.cssText = `
            background: ${type === 'error' ? '#f8d7da' : type === 'success' ? '#d4edda' : '#d1ecf1'};
            color: ${type === 'error' ? '#721c24' : type === 'success' ? '#155724' : '#0c5460'};
            border: 1px solid ${type === 'error' ? '#f5c6cb' : type === 'success' ? '#c3e6cb' : '#bee5eb'};
            border-radius: 4px;
            padding: 12px 16px;
            margin-bottom: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            position: relative;
        `;
        messageElement.textContent = message;

        // Add close button
        const closeButton = document.createElement('button');
        closeButton.innerHTML = '×';
        closeButton.style.cssText = `
            position: absolute;
            top: 8px;
            right: 12px;
            background: none;
            border: none;
            font-size: 18px;
            cursor: pointer;
            color: inherit;
        `;
        closeButton.onclick = () => messageElement.remove();
        messageElement.appendChild(closeButton);

        // Add to container
        messageContainer.appendChild(messageElement);

        // Auto-hide after duration
        if (duration > 0) {
            setTimeout(() => {
                if (messageElement.parentNode) {
                    messageElement.remove();
                }
            }, duration);
        }
    }
};

// Auto-initialize on DOM load for non-login pages (MAINTAINS YOUR EXISTING BEHAVIOR)
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
