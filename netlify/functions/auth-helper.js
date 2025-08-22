// auth-helper.js - COMPLETE FIXED VERSION
// Consistent authentication helper for all pages

const AUTH_CONFIG = {
    API_BASE: '/.netlify/functions/',
    LOGIN_PAGE: '/login.html',
    DASHBOARD_PAGE: '/dashboard.html',
    TOKEN_KEY: 'jwtToken',
    USER_KEY: 'userName',
    ROLE_KEY: 'userRole',
    USER_ID_KEY: 'userId',
    EMAIL_KEY: 'userEmail',
    REDIRECT_KEY: 'intendedPage',
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000
};

// FIXED: Enhanced Authentication Helper Object
const AuthHelper = {
    // Get stored token
    getToken: function() {
        try {
            return localStorage.getItem(AUTH_CONFIG.TOKEN_KEY);
        } catch (error) {
            console.error('Error getting token:', error);
            return null;
        }
    },

    // Store token
    setToken: function(token) {
        try {
            localStorage.setItem(AUTH_CONFIG.TOKEN_KEY, token);
        } catch (error) {
            console.error('Error storing token:', error);
        }
    },

    // Get user info from storage
    getUserInfo: function() {
        try {
            return {
                id: localStorage.getItem(AUTH_CONFIG.USER_ID_KEY),
                name: localStorage.getItem(AUTH_CONFIG.USER_KEY),
                role: localStorage.getItem(AUTH_CONFIG.ROLE_KEY),
                email: localStorage.getItem(AUTH_CONFIG.EMAIL_KEY)
            };
        } catch (error) {
            console.error('Error getting user info:', error);
            return null;
        }
    },

    // Store user info
    setUserInfo: function(userInfo) {
        try {
            localStorage.setItem(AUTH_CONFIG.USER_ID_KEY, userInfo.id || '');
            localStorage.setItem(AUTH_CONFIG.USER_KEY, userInfo.name || '');
            localStorage.setItem(AUTH_CONFIG.ROLE_KEY, userInfo.role || '');
            localStorage.setItem(AUTH_CONFIG.EMAIL_KEY, userInfo.email || '');
        } catch (error) {
            console.error('Error storing user info:', error);
        }
    },

    // Update user info from API response
    updateUserInfo: function(data) {
        if (data && data.user) {
            this.setUserInfo(data.user);
        }
    },

    // Clear all authentication data
    clearAuth: function() {
        try {
            localStorage.removeItem(AUTH_CONFIG.TOKEN_KEY);
            localStorage.removeItem(AUTH_CONFIG.USER_KEY);
            localStorage.removeItem(AUTH_CONFIG.ROLE_KEY);
            localStorage.removeItem(AUTH_CONFIG.USER_ID_KEY);
            localStorage.removeItem(AUTH_CONFIG.EMAIL_KEY);
        } catch (error) {
            console.error('Error clearing auth:', error);
        }
    },

    // Store intended page for post-login redirect
    storeIntendedPage: function() {
        try {
            const currentPage = window.location.pathname + window.location.search;
            if (!currentPage.includes('login') && currentPage !== '/') {
                localStorage.setItem(AUTH_CONFIG.REDIRECT_KEY, currentPage);
            }
        } catch (error) {
            console.error('Error storing intended page:', error);
        }
    },

    // Get intended page and clear it
    getIntendedPage: function() {
        try {
            const intendedPage = localStorage.getItem(AUTH_CONFIG.REDIRECT_KEY);
            localStorage.removeItem(AUTH_CONFIG.REDIRECT_KEY);
            return intendedPage;
        } catch (error) {
            console.error('Error getting intended page:', error);
            return null;
        }
    },

    // Redirect to login page
    redirectToLogin: function() {
        try {
            window.location.href = AUTH_CONFIG.LOGIN_PAGE;
        } catch (error) {
            console.error('Error redirecting to login:', error);
            // Fallback
            window.location.reload();
        }
    },

    // Redirect to intended page or dashboard
    redirectToIntendedOrDashboard: function() {
        try {
            const intendedPage = this.getIntendedPage();
            window.location.href = intendedPage || AUTH_CONFIG.DASHBOARD_PAGE;
        } catch (error) {
            console.error('Error redirecting after login:', error);
            window.location.href = AUTH_CONFIG.DASHBOARD_PAGE;
        }
    },

    // FIXED: Enhanced authentication check with retry logic
    checkAuth: async function(retryCount = 0) {
        const token = this.getToken();
        
        if (!token) {
            this.storeIntendedPage();
            this.redirectToLogin();
            return false;
        }
        
        try {
            const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/verify', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                if (response.status === 401) {
                    // Token is invalid or expired
                    this.clearAuth();
                    this.storeIntendedPage();
                    this.redirectToLogin();
                    return false;
                }
                
                // For other errors, retry if we haven't exceeded retry attempts
                if (retryCount < AUTH_CONFIG.RETRY_ATTEMPTS) {
                    console.warn(`Auth check failed (${response.status}), retrying... (${retryCount + 1}/${AUTH_CONFIG.RETRY_ATTEMPTS})`);
                    await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY));
                    return this.checkAuth(retryCount + 1);
                }
                
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            if (data.valid) {
                this.updateUserInfo(data);
                return true;
            } else {
                this.clearAuth();
                this.storeIntendedPage();
                this.redirectToLogin();
                return false;
            }
        } catch (error) {
            console.error('Auth check error:', error);
            
            // If we've exhausted retries, clear auth and redirect
            if (retryCount >= AUTH_CONFIG.RETRY_ATTEMPTS) {
                this.clearAuth();
                this.storeIntendedPage();
                this.redirectToLogin();
                return false;
            }
            
            // Retry for network errors
            console.warn(`Auth check failed, retrying... (${retryCount + 1}/${AUTH_CONFIG.RETRY_ATTEMPTS})`);
            await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY));
            return this.checkAuth(retryCount + 1);
        }
    },

    // FIXED: Enhanced login function
    login: async function(credentials) {
        try {
            const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                this.setToken(data.token);
                this.setUserInfo(data.user);
                return { success: true, user: data.user };
            } else {
                return { 
                    success: false, 
                    error: data.error || 'Login failed',
                    attempts_remaining: data.attempts_remaining
                };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { 
                success: false, 
                error: 'Network error. Please check your connection and try again.' 
            };
        }
    },

    // FIXED: Enhanced logout function
    logout: async function() {
        const token = this.getToken();
        
        if (token) {
            try {
                await fetch(AUTH_CONFIG.API_BASE + 'auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.error('Logout error:', error);
                // Continue with local logout even if server logout fails
            }
        }
        
        this.clearAuth();
        localStorage.removeItem(AUTH_CONFIG.REDIRECT_KEY);
        this.redirectToLogin();
    },

    // FIXED: Enhanced API call helper with authentication and retry logic
    apiCall: async function(endpoint, options = {}, retryCount = 0) {
        const token = this.getToken();
        
        if (!token && !options.skipAuth) {
            this.storeIntendedPage();
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
            
            const requestOptions = {
                ...options,
                headers: headers
            };

            const response = await fetch(AUTH_CONFIG.API_BASE + endpoint, requestOptions);
            
            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuth();
                this.storeIntendedPage();
                this.redirectToLogin();
                throw new Error('Authentication expired');
            }
            
            // Handle server errors with retry
            if (response.status >= 500 && retryCount < AUTH_CONFIG.RETRY_ATTEMPTS) {
                console.warn(`API call failed (${response.status}), retrying... (${retryCount + 1}/${AUTH_CONFIG.RETRY_ATTEMPTS})`);
                await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY));
                return this.apiCall(endpoint, options, retryCount + 1);
            }
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            
            return response;
            
        } catch (error) {
            // Network errors - retry if we haven't exceeded attempts
            if (error.name === 'TypeError' && error.message.includes('fetch') && retryCount < AUTH_CONFIG.RETRY_ATTEMPTS) {
                console.warn(`Network error, retrying... (${retryCount + 1}/${AUTH_CONFIG.RETRY_ATTEMPTS})`);
                await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY));
                return this.apiCall(endpoint, options, retryCount + 1);
            }
            
            throw error;
        }
    },

    // FIXED: Enhanced role checking
    hasRole: function(requiredRoles) {
        const userRole = localStorage.getItem(AUTH_CONFIG.ROLE_KEY);
        if (!userRole) return false;
        
        if (Array.isArray(requiredRoles)) {
            return requiredRoles.includes(userRole);
        }
        
        return userRole === requiredRoles;
    },

    // Check if user has admin role
    isAdmin: function() {
        return this.hasRole('admin');
    },

    // Check if user has manager role or higher
    canManage: function() {
        return this.hasRole(['admin', 'manager', 'project_manager']);
    },

    // FIXED: Enhanced initialization with comprehensive error handling
    init: async function(options = {}) {
        try {
            // Check if we're on the login page
            if (window.location.pathname.includes('login')) {
                // Check if already logged in
                const token = this.getToken();
                if (token) {
                    try {
                        const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/verify', {
                            method: 'GET',
                            headers: {
                                'Authorization': `Bearer ${token}`,
                                'Content-Type': 'application/json'
                            }
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            if (data.valid) {
                                // Already logged in, redirect to intended page or dashboard
                                this.redirectToIntendedOrDashboard();
                                return true;
                            }
                        }
                    } catch (error) {
                        console.error('Session check failed:', error);
                        // Clear invalid session data
                        this.clearAuth();
                    }
                }
                return false;
            }
            
            // Check authentication for protected pages
            const isAuthenticated = await this.checkAuth();
            
            if (isAuthenticated && options.onAuthenticated) {
                try {
                    options.onAuthenticated(this.getUserInfo());
                } catch (error) {
                    console.error('Error in onAuthenticated callback:', error);
                }
            }
            
            return isAuthenticated;
        } catch (error) {
            console.error('Auth initialization error:', error);
            
            // If initialization fails completely, clear auth and redirect
            this.clearAuth();
            if (!window.location.pathname.includes('login')) {
                this.storeIntendedPage();
                this.redirectToLogin();
            }
            
            return false;
        }
    },

    // FIXED: Enhanced registration function
    register: async function(userData) {
        try {
            const response = await fetch(AUTH_CONFIG.API_BASE + 'auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                return { success: true, user: data.user, message: data.message };
            } else {
                return { 
                    success: false, 
                    error: data.error || 'Registration failed'
                };
            }
        } catch (error) {
            console.error('Registration error:', error);
            return { 
                success: false, 
                error: 'Network error. Please check your connection and try again.' 
            };
        }
    },

    // Change password function
    changePassword: async function(passwordData) {
        try {
            const response = await this.apiCall('auth/change-password', {
                method: 'POST',
                body: JSON.stringify(passwordData)
            });

            const data = await response.json();
            return { success: true, message: data.message };
        } catch (error) {
            console.error('Change password error:', error);
            return { 
                success: false, 
                error: error.message || 'Failed to change password' 
            };
        }
    },

    // FIXED: Enhanced error handling
    handleError: function(error, context = 'Unknown') {
        console.error(`${context} error:`, error);
        
        // Handle specific error types
        if (error.message.includes('Authentication expired') || error.message.includes('token')) {
            this.clearAuth();
            this.storeIntendedPage();
            this.redirectToLogin();
            return;
        }
        
        if (error.message.includes('Network error') || error.name === 'TypeError') {
            this.showMessage('Network connection issue. Please check your internet connection.', 'error');
            return;
        }
        
        // Show generic error message
        this.showMessage(error.message || 'An unexpected error occurred.', 'error');
    },

    // Show user-friendly messages
    showMessage: function(message, type = 'info', duration = 5000) {
        // Try to use existing message system if available
        if (typeof showMessage === 'function') {
            showMessage(message, type, duration);
            return;
        }
        
        // Fallback to simple alert or console
        if (type === 'error') {
            console.error(message);
            alert('Error: ' + message);
        } else {
            console.log(message);
        }
    },

    // Utility function to format user display name
    formatUserName: function(userInfo) {
        if (!userInfo) return 'Unknown User';
        
        if (userInfo.firstName && userInfo.lastName) {
            return `${userInfo.firstName} ${userInfo.lastName}`;
        }
        
        if (userInfo.name && userInfo.name.trim()) {
            return userInfo.name;
        }
        
        return userInfo.username || userInfo.email || 'Unknown User';
    }
};

// FIXED: Auto-initialize on DOM load with enhanced error handling
if (!window.location.pathname.includes('login')) {
    document.addEventListener('DOMContentLoaded', function() {
        AuthHelper.init({
            onAuthenticated: function(userInfo) {
                try {
                    // Update any user display elements
                    const userNameElements = document.querySelectorAll('#userName, .user-name');
                    const userRoleElements = document.querySelectorAll('#userRole, .user-role');
                    const userEmailElements = document.querySelectorAll('#userEmail, .user-email');
                    
                    const displayName = AuthHelper.formatUserName(userInfo);
                    
                    userNameElements.forEach(el => {
                        if (el) el.textContent = displayName;
                    });
                    
                    userRoleElements.forEach(el => {
                        if (el) el.textContent = userInfo.role || 'viewer';
                    });
                    
                    userEmailElements.forEach(el => {
                        if (el) el.textContent = userInfo.email || '';
                    });
                    
                    // Hide/show elements based on role
                    const adminElements = document.querySelectorAll('.admin-only');
                    const managerElements = document.querySelectorAll('.manager-only');
                    
                    adminElements.forEach(el => {
                        el.style.display = AuthHelper.isAdmin() ? '' : 'none';
                    });
                    
                    managerElements.forEach(el => {
                        el.style.display = AuthHelper.canManage() ? '' : 'none';
                    });
                    
                } catch (error) {
                    console.error('Error updating UI with user info:', error);
                }
            }
        }).catch(error => {
            console.error('Failed to initialize authentication:', error);
        });
    });
}

// Export for use in other modules (if using module system)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthHelper;
}

// Make available globally
window.AuthHelper = AuthHelper;
