<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LSEC SA User Management</title>
    <style>
        /* Reset and base styles */
        * {
            box-sizing: border-box;
        }
        
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, Arial, sans-serif;
            line-height: 1.5;
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #121212;
            min-height: 100vh;
            box-shadow: 0 0 40px rgba(0,0,0,0.5);
        }
        
        /* User info bar */
        .user-info-bar {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #333;
        }
        
        .user-details {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .user-name {
            color: #4a9eff;
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .user-role {
            color: #888;
            font-size: 0.9rem;
            background: #2a2a2a;
            padding: 4px 12px;
            border-radius: 12px;
        }
        
        .logout-btn {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
            background: linear-gradient(135deg, #c82333 0%, #bd2130 100%);
            transform: translateY(-1px);
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #4a9eff;
        }
        
        .header h1 {
            color: #4a9eff;
            margin: 0;
            font-size: 2.5rem;
            font-weight: 700;
            text-shadow: 0 2px 4px rgba(74, 158, 255, 0.3);
        }
        
        .header p {
            color: #b0b0b0;
            margin: 10px 0 0 0;
            font-size: 1.1rem;
        }
        
        /* Navigation */
        .nav-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #333;
        }
        
        .nav-tab {
            background: #2a2a2a;
            color: #888;
            border: none;
            padding: 12px 20px;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }
        
        .nav-tab.active {
            background: #1e1e1e;
            color: #4a9eff;
            border-bottom-color: #4a9eff;
        }
        
        .nav-tab:hover:not(.active) {
            background: #333;
            color: #c0c0c0;
        }
        
        /* Tab content */
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Form sections */
        .section {
            background: #1e1e1e;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            border-left: 5px solid #4a9eff;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            border: 1px solid #333;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            font-size: 1.5rem;
            font-weight: 600;
            color: #e0e0e0;
        }
        
        .section-number {
            background: #4a9eff;
            color: #000;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            font-weight: bold;
            box-shadow: 0 2px 8px rgba(74, 158, 255, 0.4);
        }
        
        /* Form inputs */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #c0c0c0;
        }
        
        .required::after {
            content: " *";
            color: #dc3545;
        }
        
        input, select, textarea {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #404040;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
            background: #2a2a2a;
            color: #e0e0e0;
        }
        
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #4a9eff;
            box-shadow: 0 0 0 3px rgba(74, 158, 255, 0.2);
            background: #333;
        }
        
        input::placeholder, textarea::placeholder {
            color: #777;
        }
        
        select {
            cursor: pointer;
        }
        
        option {
            background: #2a2a2a;
            color: #e0e0e0;
        }
        
        /* Field validation states */
        input.valid {
            border-color: #28a745;
        }
        
        input.invalid {
            border-color: #dc3545;
        }
        
        /* Checkbox styling */
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
            cursor: pointer;
            accent-color: #4a9eff;
        }
        
        .checkbox-group label {
            margin: 0;
            cursor: pointer;
            font-weight: normal;
        }
        
        /* Password strength indicator */
        .password-strength {
            margin-top: 8px;
            height: 4px;
            background: #333;
            border-radius: 2px;
            overflow: hidden;
            display: none;
        }
        
        .password-strength.show {
            display: block;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: all 0.3s ease;
            border-radius: 2px;
        }
        
        .password-strength-bar.weak { background: #dc3545; width: 25%; }
        .password-strength-bar.fair { background: #fd7e14; width: 50%; }
        .password-strength-bar.good { background: #ffc107; width: 75%; }
        .password-strength-bar.strong { background: #28a745; width: 100%; }
        
        .password-requirements {
            margin-top: 8px;
            font-size: 0.9rem;
            color: #888;
        }
        
        .password-requirement {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 4px;
        }
        
        .password-requirement.met {
            color: #28a745;
        }
        
        .password-requirement.met::before {
            content: "âœ“";
            color: #28a745;
            font-weight: bold;
        }
        
        .password-requirement:not(.met)::before {
            content: "âœ—";
            color: #dc3545;
            font-weight: bold;
        }
        
        /* Buttons */
        .btn {
            background: linear-gradient(135deg, #4a9eff 0%, #357abd 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(74, 158, 255, 0.3);
        }
        
        .btn:hover:not(:disabled) {
            background: linear-gradient(135deg, #357abd 0%, #2968a3 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(74, 158, 255, 0.4);
        }
        
        .btn:disabled {
            background: #555;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .btn-success {
            background: linear-gradient(135deg, #28a745 0%, #20924c 100%);
            box-shadow: 0 2px 8px rgba(40, 167, 69, 0.3);
        }
        
        .btn-success:hover:not(:disabled) {
            background: linear-gradient(135deg, #218838 0%, #1e7e34 100%);
            box-shadow: 0 4px 12px rgba(40, 167, 69, 0.4);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            box-shadow: 0 2px 8px rgba(220, 53, 69, 0.3);
        }
        
        .btn-danger:hover:not(:disabled) {
            background: linear-gradient(135deg, #c82333 0%, #bd2130 100%);
            box-shadow: 0 4px 12px rgba(220, 53, 69, 0.4);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
            box-shadow: 0 2px 8px rgba(108, 117, 125, 0.3);
        }
        
        .btn-secondary:hover:not(:disabled) {
            background: linear-gradient(135deg, #5a6268 0%, #4e555b 100%);
            box-shadow: 0 4px 12px rgba(108, 117, 125, 0.4);
        }
        
        .btn-block {
            width: 100%;
            justify-content: center;
        }
        
        .btn-small {
            padding: 6px 12px;
            font-size: 14px;
        }
        
        /* Loading and messages */
        .loading {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #888;
            font-style: italic;
        }
        
        .loading::after {
            content: '';
            width: 16px;
            height: 16px;
            border: 2px solid #333;
            border-top: 2px solid #4a9eff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #1e3d29 0%, #2d5a41 100%);
            color: #4ade80;
            border: 1px solid #16a34a;
            box-shadow: 0 2px 8px rgba(74, 222, 128, 0.2);
        }
        
        .alert-error {
            background: linear-gradient(135deg, #3d1e1e 0%, #5a2d2d 100%);
            color: #f87171;
            border: 1px solid #dc2626;
            box-shadow: 0 2px 8px rgba(248, 113, 113, 0.2);
        }
        
        .alert-warning {
            background: linear-gradient(135deg, #3d3a1e 0%, #5a5330 100%);
            color: #fbbf24;
            border: 1px solid #d97706;
            box-shadow: 0 2px 8px rgba(251, 191, 36, 0.2);
        }
        
        /* Users table */
        .users-table {
            width: 100%;
            border-collapse: collapse;
            background: #1e1e1e;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #333;
        }
        
        .users-table th,
        .users-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        
        .users-table th {
            background: #2a2a2a;
            font-weight: 600;
            color: #4a9eff;
        }
        
        .users-table tr:hover {
            background: #242424;
        }
        
        .users-table td {
            color: #e0e0e0;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-badge.active {
            background: rgba(40, 167, 69, 0.2);
            color: #4ade80;
            border: 1px solid #16a34a;
        }
        
        .status-badge.inactive {
            background: rgba(220, 53, 69, 0.2);
            color: #f87171;
            border: 1px solid #dc2626;
        }
        
        .action-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        /* Search and filter controls */
        .search-filters {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #333;
        }
        
        .search-filters h3 {
            margin: 0 0 15px 0;
            color: #4a9eff;
            font-size: 1.2rem;
        }
        
        .filter-row {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
            gap: 15px;
            align-items: end;
        }
        
        /* Hidden utility */
        .hidden {
            display: none !important;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .section {
                padding: 20px;
            }
            
            .form-row {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .filter-row {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .user-info-bar {
                flex-direction: column;
                gap: 10px;
                text-align: center;
            }
            
            .user-details {
                flex-direction: column;
                gap: 10px;
            }
            
            .nav-tabs {
                flex-direction: column;
            }
            
            .users-table {
                font-size: 14px;
            }
            
            .users-table th,
            .users-table td {
                padding: 8px 12px;
            }
            
            .action-buttons {
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- User Info Bar -->
        <div class="user-info-bar">
            <div class="user-details">
                <span class="user-name" id="userName">Loading...</span>
                <span class="user-role" id="userRole">Loading...</span>
            </div>
            <button type="button" class="logout-btn" onclick="handleLogout()">Logout</button>
        </div>

        <div class="header">
            <h1>User Management</h1>
            <p>LSEC SA User Administration</p>
        </div>

        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="switchTab('add-user')">Add User</button>
            <button class="nav-tab" onclick="switchTab('view-users')">View Users</button>
        </div>

        <!-- Add User Tab -->
        <div id="add-user-tab" class="tab-content active">
            <form id="addUserForm">
                <!-- Basic Information Section -->
                <div class="section">
                    <div class="section-header">
                        <span class="section-number">1</span>
                        Basic Information
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="firstName" class="required">First Name</label>
                            <input type="text" id="firstName" required placeholder="Enter first name">
                        </div>
                        <div class="form-group">
                            <label for="lastName" class="required">Last Name</label>
                            <input type="text" id="lastName" required placeholder="Enter last name">
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="email" class="required">Email Address</label>
                        <input type="email" id="email" required placeholder="user@lsecsa.com">
                    </div>

                    <div class="form-group">
                        <label for="username" class="required">Username</label>
                        <input type="text" id="username" required placeholder="Enter username">
                    </div>
                </div>

                <!-- Account Settings Section -->
                <div class="section">
                    <div class="section-header">
                        <span class="section-number">2</span>
                        Account Settings
                    </div>

                    <div class="form-group">
                        <label for="role" class="required">User Role</label>
                        <select id="role" required>
                            <option value="">-- Select Role --</option>
                            <option value="admin">Administrator</option>
                            <option value="project_manager">Project Manager</option>
                            <option value="estimator">Estimator</option>
                            <option value="accountant">Accountant</option>
                            <option value="superintendent">Superintendent</option>
                            <option value="foreman">Foreman</option>
                            <option value="laborer">Laborer</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="password" class="required">Password</label>
                        <input type="password" id="password" required placeholder="Enter secure password">
                        <div id="passwordStrength" class="password-strength">
                            <div id="passwordStrengthBar" class="password-strength-bar"></div>
                        </div>
                        <div class="password-requirements">
                            <div id="req-length" class="password-requirement">At least 8 characters</div>
                            <div id="req-upper" class="password-requirement">At least one uppercase letter</div>
                            <div id="req-lower" class="password-requirement">At least one lowercase letter</div>
                            <div id="req-number" class="password-requirement">At least one number</div>
                            <div id="req-special" class="password-requirement">At least one special character</div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="confirmPassword" class="required">Confirm Password</label>
                        <input type="password" id="confirmPassword" required placeholder="Confirm password">
                    </div>

                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="isActive" checked>
                            <label for="isActive">Account is active</label>
                        </div>
                    </div>
                </div>

                <!-- Submit Section -->
                <div class="form-group">
                    <button type="submit" id="submitBtn" class="btn btn-success btn-block">
                        âž• Create User Account
                    </button>
                    <div id="submitLoader" class="loading hidden">Creating user account</div>
                </div>
            </form>

            <!-- Result Messages -->
            <div id="resultMessage"></div>
        </div>

        <!-- View Users Tab -->
        <div id="view-users-tab" class="tab-content">
            <!-- Search and Filter Controls -->
            <div class="search-filters">
                <h3>ðŸ” Search & Filter Users</h3>
                <div class="filter-row">
                    <div class="form-group">
                        <label for="userSearch">Search Users</label>
                        <input type="text" id="userSearch" placeholder="Search by name, username, or email...">
                    </div>
                    <div class="form-group">
                        <label for="roleFilter">Filter by Role</label>
                        <select id="roleFilter">
                            <option value="">All Roles</option>
                            <option value="admin">Administrator</option>
                            <option value="project_manager">Project Manager</option>
                            <option value="estimator">Estimator</option>
                            <option value="accountant">Accountant</option>
                            <option value="superintendent">Superintendent</option>
                            <option value="foreman">Foreman</option>
                            <option value="laborer">Laborer</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="statusFilter">Filter by Status</label>
                        <select id="statusFilter">
                            <option value="">All Status</option>
                            <option value="true">Active</option>
                            <option value="false">Inactive</option>
                        </select>
                    </div>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <span class="section-number">ðŸ“‹</span>
                    All Users
                </div>

                <div id="usersTableContainer">
                    <div id="usersLoader" class="loading">Loading users</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Include AuthHelper (assuming it exists like in the DWR form) -->
    <script src="auth-helper.js"></script>
    
    <script>
        // Global variables
        let currentUser = null;
        let allUsers = [];
        let usernameCheckTimeout;
        let emailCheckTimeout;

        // Initialize page on DOM load
        document.addEventListener('DOMContentLoaded', async function() {
            // Check if AuthHelper exists
            if (typeof AuthHelper === 'undefined') {
                console.warn('AuthHelper not available, using demo mode');
                initializeDemoMode();
                return;
            }
            
            try {
                // Initialize authentication using AuthHelper
                const isAuthenticated = await AuthHelper.init({
                    onAuthenticated: function(userInfo) {
                        currentUser = userInfo;
                        // Update user display
                        document.getElementById('userName').textContent = userInfo.name;
                        document.getElementById('userRole').textContent = userInfo.role;
                        
                        // Update UI based on user role
                        updateUIBasedOnRole(userInfo.role);
                        
                        // Initialize the page functionality
                        initializeApp();
                    }
                });
                
                if (!isAuthenticated) {
                    // User will be redirected to login by AuthHelper
                    return;
                }
            } catch (error) {
                console.warn('Authentication failed, using demo mode:', error);
                initializeDemoMode();
            }
        });
        
        // Initialize demo mode when AuthHelper is not available
        function initializeDemoMode() {
            // Set demo user info
            document.getElementById('userName').textContent = 'Demo User';
            document.getElementById('userRole').textContent = 'Administrator';
            
            // Initialize the page functionality
            initializeApp();
        }
        
        // Logout handler
        function handleLogout() {
            if (typeof AuthHelper !== 'undefined') {
                AuthHelper.logout();
            } else {
                alert('Logout functionality requires AuthHelper integration');
            }
        }
        
        // Initialize the application
        function initializeApp() {
            setupEventListeners();
            loadUsers(); // Load users for the view tab
        }

        // Setup event listeners
        function setupEventListeners() {
            document.getElementById('addUserForm').addEventListener('submit', handleSubmit);
            document.getElementById('password').addEventListener('input', checkPasswordStrength);
            document.getElementById('confirmPassword').addEventListener('input', checkPasswordMatch);
            
            // Enhanced with debounced availability checking
            document.getElementById('username').addEventListener('input', checkUsernameAvailability);
            document.getElementById('email').addEventListener('input', checkEmailAvailability);
            
            // Add real-time form validation
            document.getElementById('firstName').addEventListener('input', validateRequiredField);
            document.getElementById('lastName').addEventListener('input', validateRequiredField);
            document.getElementById('role').addEventListener('change', validateRequiredField);
            
            // Search and filter event listeners
            document.getElementById('userSearch').addEventListener('input', filterUsers);
            document.getElementById('roleFilter').addEventListener('change', filterUsers);
            document.getElementById('statusFilter').addEventListener('change', filterUsers);
        }

        // Tab switching
        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            if (event && event.target) {
                event.target.classList.add('active');
            }
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            const targetTab = document.getElementById(tabName + '-tab');
            if (targetTab) {
                targetTab.classList.add('active');
            }
            
            // Load users when switching to view tab
            if (tabName === 'view-users') {
                loadUsers();
            }
        }

        // Real-time validation for required fields
        function validateRequiredField(event) {
            const field = event.target;
            const value = field.value.trim();
            
            if (value.length === 0) {
                field.style.borderColor = '#dc3545';
                field.title = 'This field is required';
            } else {
                field.style.borderColor = '#28a745';
                field.title = '';
            }
        }

        // Enhanced username availability checker with debouncing
        async function checkUsernameAvailability() {
            const username = document.getElementById('username').value;
            const usernameInput = document.getElementById('username');
            
            // Clear previous timeout
            clearTimeout(usernameCheckTimeout);
            
            if (username.length < 3) {
                usernameInput.style.borderColor = '#404040';
                usernameInput.title = '';
                return;
            }
            
            // Basic validation
            if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
                usernameInput.style.borderColor = '#dc3545';
                usernameInput.title = 'Username can only contain letters, numbers, dots, dashes, and underscores';
                return;
            }
            
            // Debounce the API call
            usernameCheckTimeout = setTimeout(async () => {
                try {
                    if (typeof AuthHelper !== 'undefined') {
                        const result = await AuthHelper.apiCall('check-username', {
                            method: 'POST',
                            body: JSON.stringify({ username: username })
                        });
                        
                        if (result.available) {
                            usernameInput.style.borderColor = '#28a745';
                            usernameInput.title = 'Username is available';
                        } else {
                            usernameInput.style.borderColor = '#dc3545';
                            usernameInput.title = 'Username is already taken';
                        }
                    } else {
                        // Fallback for demo mode
                        usernameInput.style.borderColor = '#28a745';
                        usernameInput.title = 'Username appears available (demo mode)';
                    }
                } catch (error) {
                    console.warn('Username check failed:', error);
                    usernameInput.style.borderColor = '#404040';
                    usernameInput.title = '';
                }
            }, 500); // 500ms debounce
        }

        // Enhanced email availability checker with debouncing
        async function checkEmailAvailability() {
            const email = document.getElementById('email').value;
            const emailInput = document.getElementById('email');
            
            // Clear previous timeout
            clearTimeout(emailCheckTimeout);
            
            // Basic email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email) && email.length > 0) {
                emailInput.style.borderColor = '#dc3545';
                emailInput.title = 'Invalid email format';
                return;
            }
            
            if (email.length === 0) {
                emailInput.style.borderColor = '#404040';
                emailInput.title = '';
                return;
            }
            
            // Debounce the API call
            emailCheckTimeout = setTimeout(async () => {
                try {
                    if (typeof AuthHelper !== 'undefined') {
                        const result = await AuthHelper.apiCall('check-email', {
                            method: 'POST',
                            body: JSON.stringify({ email: email })
                        });
                        
                        if (result.available) {
                            emailInput.style.borderColor = '#28a745';
                            emailInput.title = 'Email is available';
                        } else {
                            emailInput.style.borderColor = '#dc3545';
                            emailInput.title = 'Email is already registered';
                        }
                    } else {
                        // Fallback for demo mode
                        emailInput.style.borderColor = '#28a745';
                        emailInput.title = 'Email appears available (demo mode)';
                    }
                } catch (error) {
                    console.warn('Email check failed:', error);
                    emailInput.style.borderColor = '#404040';
                    emailInput.title = '';
                }
            }, 500); // 500ms debounce
        }

        // Password strength checker
        function checkPasswordStrength() {
            const password = document.getElementById('password').value;
            const strengthIndicator = document.getElementById('passwordStrength');
            const strengthBar = document.getElementById('passwordStrengthBar');
            
            if (password.length === 0) {
                strengthIndicator.classList.remove('show');
                return;
            }
            
            strengthIndicator.classList.add('show');
            
            let score = 0;
            const requirements = {
                length: password.length >= 8,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
            };
            
            // Update requirement indicators
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(`req-${req}`);
                if (requirements[req]) {
                    element.classList.add('met');
                    score++;
                } else {
                    element.classList.remove('met');
                }
            });
            
            // Update strength bar
            strengthBar.className = 'password-strength-bar';
            if (score <= 1) {
                strengthBar.classList.add('weak');
            } else if (score <= 2) {
                strengthBar.classList.add('fair');
            } else if (score <= 3) {
                strengthBar.classList.add('good');
            } else {
                strengthBar.classList.add('strong');
            }
        }

        // Password confirmation checker
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const confirmInput = document.getElementById('confirmPassword');
            
            if (confirmPassword.length === 0) {
                confirmInput.style.borderColor = '#404040';
                return;
            }
            
            if (password === confirmPassword) {
                confirmInput.style.borderColor = '#28a745';
            } else {
                confirmInput.style.borderColor = '#dc3545';
            }
        }

        // Detailed password validation
        function validatePasswordStrength(password) {
            const requirements = {
                length: { test: password.length >= 8, description: 'at least 8 characters' },
                upper: { test: /[A-Z]/.test(password), description: 'at least one uppercase letter' },
                lower: { test: /[a-z]/.test(password), description: 'at least one lowercase letter' },
                number: { test: /\d/.test(password), description: 'at least one number' },
                special: { test: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password), description: 'at least one special character' }
            };
            
            const failedRequirements = Object.keys(requirements).filter(key => !requirements[key].test);
            const missingRequirements = failedRequirements.map(key => requirements[key].description);
            
            return {
                isValid: failedRequirements.length === 0,
                missingRequirements: missingRequirements,
                score: Object.keys(requirements).length - failedRequirements.length
            };
        }

        // Enhanced form validation with more detailed feedback
        function validateForm() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const email = document.getElementById('email').value;
            const username = document.getElementById('username').value;
            
            // Check required fields
            const requiredFields = [
                { id: 'firstName', name: 'First Name' },
                { id: 'lastName', name: 'Last Name' },
                { id: 'email', name: 'Email' },
                { id: 'username', name: 'Username' },
                { id: 'password', name: 'Password' },
                { id: 'confirmPassword', name: 'Confirm Password' },
                { id: 'role', name: 'Role' }
            ];
            
            for (const field of requiredFields) {
                const element = document.getElementById(field.id);
                if (!element.value.trim()) {
                    showMessage(`${field.name} is required.`, 'error');
                    element.focus();
                    element.style.borderColor = '#dc3545';
                    return false;
                }
            }
            
            // Username validation
            if (username.length < 3) {
                showMessage('Username must be at least 3 characters long.', 'error');
                document.getElementById('username').focus();
                return false;
            }
            
            if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
                showMessage('Username can only contain letters, numbers, dots, dashes, and underscores.', 'error');
                document.getElementById('username').focus();
                return false;
            }
            
            // Email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                showMessage('Please enter a valid email address.', 'error');
                document.getElementById('email').focus();
                return false;
            }
            
            // Password strength validation
            const passwordValidation = validatePasswordStrength(password);
            if (!passwordValidation.isValid) {
                showMessage(`Password requirements: ${passwordValidation.missingRequirements.join(', ')}.`, 'error');
                document.getElementById('password').focus();
                return false;
            }
            
            // Password confirmation
            if (password !== confirmPassword) {
                showMessage('Passwords do not match.', 'error');
                document.getElementById('confirmPassword').focus();
                return false;
            }
            
            return true;
        }

        // Load users for the view tab
        async function loadUsers() {
            const loader = document.getElementById('usersLoader');
            const container = document.getElementById('usersTableContainer');
            
            // Check if elements exist
            if (!loader || !container) {
                console.warn('Users table elements not found');
                return;
            }
            
            try {
                setLoadingState(true, null, 'usersLoader');
                
                // Try to use AuthHelper to fetch users, fallback to mock data
                try {
                    allUsers = await AuthHelper.apiCall('users');
                } catch (apiError) {
                    console.warn('API endpoint not available, using mock data:', apiError.message);
                    // Use mock data for demonstration
                    allUsers = getMockUsers();
                }
                
                displayUsersTable(allUsers);
                
            } catch (error) {
                console.error('Error loading users:', error);
                container.innerHTML = '<div class="alert alert-error">Error loading users: ' + error.message + '</div>';
            } finally {
                setLoadingState(false, null, 'usersLoader');
            }
        }

        // Mock data for demonstration when API is not available
        function getMockUsers() {
            return [
                {
                    id: '1',
                    first_name: 'John',
                    last_name: 'Smith',
                    username: 'jsmith',
                    email: 'john.smith@lsecsa.com',
                    role: 'admin',
                    is_active: true,
                    last_login: '2024-01-15T10:30:00Z'
                },
                {
                    id: '2',
                    first_name: 'Maria',
                    last_name: 'Garcia',
                    username: 'mgarcia',
                    email: 'maria.garcia@lsecsa.com',
                    role: 'project_manager',
                    is_active: true,
                    last_login: '2024-01-14T14:20:00Z'
                },
                {
                    id: '3',
                    first_name: 'Robert',
                    last_name: 'Johnson',
                    username: 'rjohnson',
                    email: 'robert.johnson@lsecsa.com',
                    role: 'foreman',
                    is_active: false,
                    last_login: '2024-01-10T09:15:00Z'
                },
                {
                    id: '4',
                    first_name: 'Sarah',
                    last_name: 'Williams',
                    username: 'swilliams',
                    email: 'sarah.williams@lsecsa.com',
                    role: 'estimator',
                    is_active: true,
                    last_login: null
                }
            ];
        }

        // Enhanced displayUsersTable with additional action buttons
        function displayUsersTable(users) {
            const container = document.getElementById('usersTableContainer');
            
            if (users.length === 0) {
                container.innerHTML = '<div class="alert alert-warning">No users found.</div>';
                return;
            }
            
            const tableHTML = `
                <table class="users-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${users.map(user => `
                            <tr>
                                <td>${user.first_name} ${user.last_name}</td>
                                <td>${user.username}</td>
                                <td>${user.email}</td>
                                <td>${user.role}</td>
                                <td>
                                    <span class="status-badge ${user.is_active ? 'active' : 'inactive'}">
                                        ${user.is_active ? 'Active' : 'Inactive'}
                                    </span>
                                </td>
                                <td>${user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}</td>
                                <td>
                                    <div class="action-buttons">
                                        <button class="btn btn-secondary btn-small" onclick="editUser('${user.id}')" title="Edit user details">
                                            âœï¸ Edit
                                        </button>
                                        <button class="btn ${user.is_active ? 'btn-danger' : 'btn-success'} btn-small" 
                                                onclick="toggleUserStatus('${user.id}', ${user.is_active})"
                                                title="${user.is_active ? 'Disable' : 'Enable'} user account">
                                            ${user.is_active ? 'ðŸš« Disable' : 'âœ… Enable'}
                                        </button>
                                        <button class="btn btn-secondary btn-small" 
                                                onclick="resetUserPassword('${user.id}', '${user.username}')"
                                                title="Reset user password">
                                            ðŸ”‘ Reset
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
            
            container.innerHTML = tableHTML;
        }

        // Enhanced toggle user status with proper API integration
        async function toggleUserStatus(userId, currentStatus) {
            try {
                const action = currentStatus ? 'disable' : 'enable';
                const confirmed = confirm(`Are you sure you want to ${action} this user?`);
                
                if (!confirmed) return;
                
                try {
                    const result = await AuthHelper.apiCall(`users/${userId}/toggle-status`, {
                        method: 'POST'
                    });
                    
                    if (result.success) {
                        showMessage(`User ${action}d successfully!`, 'success');
                        loadUsers(); // Reload the users table
                    } else {
                        throw new Error(result.error || 'Unknown error occurred');
                    }
                } catch (apiError) {
                    console.warn('API endpoint error:', apiError.message);
                    // For demo purposes when API is not available
                    showMessage(`User would be ${action}d successfully! (API endpoint working in demo mode)`, 'warning');
                    
                    // Update the UI optimistically in demo mode
                    const allTableRows = document.querySelectorAll('.users-table tbody tr');
                    allTableRows.forEach(row => {
                        const actionCell = row.cells[6]; // Assuming actions are in 7th column (index 6)
                        const toggleBtn = actionCell.querySelector('.btn-danger, .btn-success');
                        if (toggleBtn && toggleBtn.onclick && toggleBtn.onclick.toString().includes(userId)) {
                            const statusCell = row.cells[4]; // Assuming status is in 5th column (index 4)
                            const statusBadge = statusCell.querySelector('.status-badge');
                            
                            if (currentStatus) {
                                // Disabling user
                                statusBadge.className = 'status-badge inactive';
                                statusBadge.textContent = 'Inactive';
                                toggleBtn.className = 'btn btn-success btn-small';
                                toggleBtn.innerHTML = 'âœ… Enable';
                                toggleBtn.onclick = () => toggleUserStatus(userId, false);
                            } else {
                                // Enabling user
                                statusBadge.className = 'status-badge active';
                                statusBadge.textContent = 'Active';
                                toggleBtn.className = 'btn btn-danger btn-small';
                                toggleBtn.innerHTML = 'ðŸš« Disable';
                                toggleBtn.onclick = () => toggleUserStatus(userId, true);
                            }
                        }
                    });
                }
                
            } catch (error) {
                console.error('Error toggling user status:', error);
                showMessage('Error updating user status: ' + error.message, 'error');
            }
        }

        // Enhanced edit user function (placeholder for future implementation)
        function editUser(userId) {
            // For now, show a message. In the future, this could open a modal or redirect to an edit page
            showMessage('User editing functionality will be implemented in the next phase.', 'warning');
            
            // TODO: Implement user editing functionality
            // This could involve:
            // 1. Fetching user details via API
            // 2. Opening a modal with pre-filled form
            // 3. Allowing updates to user information
            // 4. Calling the PUT /users/{id} endpoint
        }

        // Enhanced password reset function
        async function resetUserPassword(userId, userName) {
            try {
                const newPassword = prompt(`Enter new password for user "${userName}":`);
                
                if (!newPassword) return;
                
                if (newPassword.length < 8) {
                    showMessage('Password must be at least 8 characters long.', 'error');
                    return;
                }
                
                try {
                    const result = await AuthHelper.apiCall(`users/${userId}/reset-password`, {
                        method: 'POST',
                        body: JSON.stringify({ new_password: newPassword })
                    });
                    
                    if (result.success) {
                        showMessage('Password reset successfully!', 'success');
                    } else {
                        throw new Error(result.error || 'Unknown error occurred');
                    }
                } catch (apiError) {
                    console.warn('API endpoint error:', apiError.message);
                    showMessage('Password would be reset successfully! (API endpoint working in demo mode)', 'warning');
                }
                
            } catch (error) {
                console.error('Error resetting password:', error);
                showMessage('Error resetting password: ' + error.message, 'error');
            }
        }

        // Search and filter functionality for users table
        function filterUsers() {
            const searchTerm = document.getElementById('userSearch')?.value.toLowerCase() || '';
            const roleFilter = document.getElementById('roleFilter')?.value || '';
            const statusFilter = document.getElementById('statusFilter')?.value || '';
            
            const filteredUsers = allUsers.filter(user => {
                const matchesSearch = !searchTerm || 
                    user.first_name.toLowerCase().includes(searchTerm) ||
                    user.last_name.toLowerCase().includes(searchTerm) ||
                    user.username.toLowerCase().includes(searchTerm) ||
                    user.email.toLowerCase().includes(searchTerm);
                    
                const matchesRole = !roleFilter || user.role === roleFilter;
                const matchesStatus = !statusFilter || user.is_active.toString() === statusFilter;
                
                return matchesSearch && matchesRole && matchesStatus;
            });
            
            displayUsersTable(filteredUsers);
        }

        // Role-based feature visibility
        function updateUIBasedOnRole(userRole) {
            // Hide certain features based on user role
            const adminOnlyElements = document.querySelectorAll('[data-admin-only]');
            const managerPlusElements = document.querySelectorAll('[data-manager-plus]');
            
            const isAdmin = userRole === 'admin';
            const isManagerPlus = ['admin', 'project_manager', 'superintendent'].includes(userRole);
            
            adminOnlyElements.forEach(element => {
                element.style.display = isAdmin ? 'block' : 'none';
            });
            
            managerPlusElements.forEach(element => {
                element.style.display = isManagerPlus ? 'block' : 'none';
            });
        }

        // Enhanced loading state management
        function setLoadingState(isLoading, buttonId = 'submitBtn', loaderId = 'submitLoader') {
            const button = buttonId ? document.getElementById(buttonId) : null;
            const loader = document.getElementById(loaderId);
            
            if (button) {
                button.disabled = isLoading;
                if (isLoading) {
                    button.style.opacity = '0.7';
                } else {
                    button.style.opacity = '1';
                }
            }
            
            if (loader) {
                if (isLoading) {
                    loader.classList.remove('hidden');
                } else {
                    loader.classList.add('hidden');
                }
            }
        }

        // Enhanced show message with auto-dismiss and better UX
        function showMessage(message, type, autoDismiss = true) {
            const resultDiv = document.getElementById('resultMessage');
            resultDiv.className = `alert alert-${type}`;
            resultDiv.textContent = message;
            
            // Scroll to message if it's not visible
            resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            
            // Auto-hide messages after delay
            if (autoDismiss) {
                const delay = type === 'error' ? 8000 : 5000; // Errors stay longer
                setTimeout(() => {
                    if (resultDiv.textContent === message) { // Only clear if message hasn't changed
                        resultDiv.innerHTML = '';
                        resultDiv.className = '';
                    }
                }, delay);
            }
        }

        // Form submission
        async function handleSubmit(event) {
            event.preventDefault();
            
            try {
                setLoadingState(true);
                
                // Validate form
                if (!validateForm()) {
                    return;
                }
                
                // Collect form data
                const formData = {
                    username: document.getElementById('username').value,
                    email: document.getElementById('email').value,
                    password: document.getElementById('password').value,
                    first_name: document.getElementById('firstName').value,
                    last_name: document.getElementById('lastName').value,
                    role: document.getElementById('role').value,
                    is_active: document.getElementById('isActive').checked
                };
                
                // Try to submit to API, fallback to mock success
                try {
                    const result = await AuthHelper.apiCall('users', {
                        method: 'POST',
                        body: JSON.stringify(formData)
                    });
                    
                    if (result.success) {
                        showMessage('User created successfully!', 'success');
                        resetForm();
                        // Reload users if on view tab
                        if (document.getElementById('view-users-tab').classList.contains('active')) {
                            loadUsers();
                        }
                    } else {
                        throw new Error(result.error || 'Unknown error occurred');
                    }
                } catch (apiError) {
                    console.warn('API endpoint not available:', apiError.message);
                    // Simulate success for demonstration
                    showMessage('User would be created successfully! (API endpoint not yet implemented)', 'warning');
                    resetForm();
                }
                
            } catch (error) {
                console.error('Error creating user:', error);
                showMessage('Error creating user: ' + error.message, 'error');
            } finally {
                setLoadingState(false);
            }
        }

        // Reset form
        function resetForm() {
            document.getElementById('addUserForm').reset();
            document.getElementById('passwordStrength').classList.remove('show');
            document.getElementById('confirmPassword').style.borderColor = '#404040';
            
            // Reset password requirements
            document.querySelectorAll('.password-requirement').forEach(req => {
                req.classList.remove('met');
            });
            
            // Reset input border colors
            document.querySelectorAll('input, select').forEach(input => {
                input.style.borderColor = '#404040';
                input.title = '';
            });
        }
    </script>
</body>
</html>
