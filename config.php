<?php
// Charity Galley Foundation - Database Configuration
// Author: BlackCodeCyberZone
// Last Updated: 2025

// Prevent direct access
if (!defined('CHARITY_GALLEY_INIT')) {
    define('CHARITY_GALLEY_INIT', true);
}

// Database Configuration
$config = [
    'host' => 'localhost',
    'user' => 'root',
    'pass' => '',
    'name' => 'charity_galley_db'
];

// Site Configuration
define('SITE_NAME', 'Charity Galley Foundation for Education');
define('SITE_URL', 'http://localhost/charity-galley'); // Update this for production
define('ADMIN_EMAIL', 'admin@charitygalleyfoundation.com');
define('THEME_COLOR', '#017d03');

// Security Settings
define('SESSION_TIMEOUT', 3600); // 1 hour in seconds
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes in seconds

// File Upload Settings
define('MAX_FILE_SIZE', 5242880); // 5MB in bytes
define('ALLOWED_IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('UPLOAD_PATH', __DIR__ . '/uploads/');

// Create database connection
try {
    $conn = new mysqli($config['host'], $config['user'], $config['pass'], $config['name']);
    
    // Check connection
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Set charset to UTF-8
    $conn->set_charset("utf8mb4");
    
} catch (Exception $e) {
    // Log error (in production, use proper logging)
    error_log($e->getMessage());
    
    // Show user-friendly error
    die("Sorry, we're experiencing technical difficulties. Please try again later.");
}

// Helper Functions
function sanitize_input($data) {
    global $conn;
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $conn->real_escape_string($data);
}

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function is_logged_in() {
    return isset($_SESSION['user_id']) && isset($_SESSION['role']);
}

function is_admin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function redirect($url) {
    header("Location: " . $url);
    exit();
}

function set_message($message, $type = 'success') {
    $_SESSION['message'] = $message;
    $_SESSION['message_type'] = $type;
}

function get_message() {
    if (isset($_SESSION['message'])) {
        $message = $_SESSION['message'];
        $type = $_SESSION['message_type'] ?? 'info';
        unset($_SESSION['message'], $_SESSION['message_type']);
        return ['message' => $message, 'type' => $type];
    }
    return null;
}

// Time zone
date_default_timezone_set('Africa/Accra');

// Error reporting (disable in production)
if ($_SERVER['SERVER_NAME'] === 'localhost') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}
?>