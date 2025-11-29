<?php
session_start();
require_once 'config.php';

// Check if already logged in
if (is_logged_in()) {
    redirect('admin/dashboard.php');
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
        set_message('Invalid security token. Please try again.', 'error');
    } else {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'];
        $remember = isset($_POST['remember']);
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            set_message('Please enter a valid email address.', 'error');
        } else {
            // Check login attempts (basic rate limiting)
            $attempt_key = 'login_attempts_' . md5($email);
            $attempts = $_SESSION[$attempt_key] ?? 0;
            $lockout_key = 'lockout_time_' . md5($email);
            
            // Check if locked out
            if (isset($_SESSION[$lockout_key]) && time() < $_SESSION[$lockout_key]) {
                $remaining = ceil(($_SESSION[$lockout_key] - time()) / 60);
                set_message("Too many failed attempts. Please try again in {$remaining} minute(s).", 'error');
            } else {
                // Query user
                $stmt = $conn->prepare("SELECT id, name, email, password, role FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($user = $result->fetch_assoc()) {
                    if (password_verify($password, $user['password'])) {
                        // Successful login
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['name'] = $user['name'];
                        $_SESSION['email'] = $user['email'];
                        $_SESSION['role'] = $user['role'];
                        
                        // Update last login
                        $update_stmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                        $update_stmt->bind_param("i", $user['id']);
                        $update_stmt->execute();
                        
                        // Set remember me cookie
                        if ($remember) {
                            $token = bin2hex(random_bytes(32));
                            setcookie('remember_token', $token, time() + (86400 * 30), '/'); // 30 days
                        }
                        
                        // Clear login attempts
                        unset($_SESSION[$attempt_key], $_SESSION[$lockout_key]);
                        
                        set_message('Login successful! Welcome back, ' . $user['name'] . '.', 'success');
                        redirect('admin/dashboard.php');
                    } else {
                        // Failed login
                        $attempts++;
                        $_SESSION[$attempt_key] = $attempts;
                        
                        if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                            $_SESSION[$lockout_key] = time() + LOCKOUT_TIME;
                            set_message('Too many failed attempts. Account locked for 15 minutes.', 'error');
                        } else {
                            $remaining = MAX_LOGIN_ATTEMPTS - $attempts;
                            set_message("Invalid email or password. {$remaining} attempt(s) remaining.", 'error');
                        }
                    }
                } else {
                    // User not found
                    set_message('Invalid email or password.', 'error');
                }
                
                $stmt->close();
            }
        }
    }
}

// Generate new CSRF token
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Admin Login - Charity Galley Foundation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#017d03">
    <meta name="robots" content="noindex, nofollow">
    
    <link rel="preconnect" href="https://fonts.googleapis.com/">
    <link rel="preconnect" href="https://fonts.gstatic.com/" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background: linear-gradient(135deg, #017d03 0%, #015a02 100%);
            font-family: 'Poppins', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        body::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255, 255, 255, 0.1) 0%, transparent 70%);
            animation: rotate 30s linear infinite;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .login-container {
            background: white;
            display: flex;
            flex-direction: row;
            max-width: 950px;
            width: 100%;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            position: relative;
            z-index: 1;
        }

        .login-image {
            flex: 1;
            background: linear-gradient(135deg, rgba(1, 125, 3, 0.9), rgba(1, 90, 2, 0.9)), 
                        url('assets/img/normal/jun.png') center/cover;
            min-height: 550px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: white;
            text-align: center;
            position: relative;
        }

        .login-image::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="30" fill="rgba(255,255,255,0.05)"/></svg>') repeat;
            opacity: 0.1;
        }

        .brand-logo {
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            position: relative;
            z-index: 2;
        }

        .brand-logo img {
            width: 80px;
            height: 80px;
            object-fit: contain;
        }

        .brand-text {
            position: relative;
            z-index: 2;
        }

        .brand-text h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }

        .brand-text p {
            font-size: 15px;
            opacity: 0.95;
            line-height: 1.6;
            max-width: 350px;
        }

        .login-form {
            flex: 1;
            padding: 50px 45px;
            background: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .form-header {
            margin-bottom: 35px;
        }

        .form-header h2 {
            font-size: 32px;
            color: #1f2937;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .form-header p {
            color: #6b7280;
            font-size: 14px;
        }

        .alert {
            border-radius: 12px;
            padding: 14px 18px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideDown 0.3s ease;
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .alert i {
            font-size: 18px;
        }

        .alert-success {
            background: #d1fae5;
            color: #065f46;
            border-left: 4px solid #10b981;
        }

        .alert-error {
            background: #fee2e2;
            color: #991b1b;
            border-left: 4px solid #ef4444;
        }

        .form-group {
            margin-bottom: 20px;
            position: relative;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            color: #374151;
            font-weight: 500;
            font-size: 14px;
        }

        .form-control {
            width: 100%;
            height: 50px;
            border-radius: 12px;
            border: 2px solid #e5e7eb;
            padding: 0 18px;
            font-size: 15px;
            background: #f9fafb;
            transition: all 0.3s ease;
            font-family: 'Poppins', sans-serif;
        }

        .form-control:focus {
            outline: none;
            border-color: #017d03;
            background: white;
            box-shadow: 0 0 0 4px rgba(1, 125, 3, 0.1);
        }

        .password-wrapper {
            position: relative;
        }

        .password-toggle {
            position: absolute;
            top: 50%;
            right: 18px;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6b7280;
            transition: color 0.3s ease;
        }

        .password-toggle:hover {
            color: #017d03;
        }

        .form-options {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }

        .checkbox-wrapper {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .checkbox-wrapper input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            accent-color: #017d03;
        }

        .checkbox-wrapper label {
            font-size: 14px;
            color: #6b7280;
            cursor: pointer;
            user-select: none;
        }

        .forgot-password {
            font-size: 14px;
            color: #017d03;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .forgot-password:hover {
            color: #015a02;
        }

        .btn-primary {
            width: 100%;
            height: 50px;
            border-radius: 12px;
            background: linear-gradient(135deg, #017d03 0%, #015a02 100%);
            border: none;
            color: white;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(1, 125, 3, 0.3);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(1, 125, 3, 0.4);
        }

        .btn-primary:active {
            transform: translateY(0);
        }

        .form-footer {
            margin-top: 25px;
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
        }

        .form-footer p {
            font-size: 13px;
            color: #6b7280;
        }

        .form-footer a {
            color: #017d03;
            text-decoration: none;
            font-weight: 600;
        }

        .form-footer a:hover {
            text-decoration: underline;
        }

        /* Responsive Design */
        @media (max-width: 968px) {
            .login-container {
                flex-direction: column;
                max-width: 500px;
            }

            .login-image {
                min-height: 300px;
                padding: 30px;
            }

            .brand-logo {
                width: 100px;
                height: 100px;
                margin-bottom: 20px;
            }

            .brand-logo img {
                width: 70px;
                height: 70px;
            }

            .brand-text h1 {
                font-size: 24px;
            }

            .brand-text p {
                font-size: 14px;
            }

            .login-form {
                padding: 40px 30px;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 10px;
            }

            .login-image {
                min-height: 250px;
                padding: 25px;
            }

            .brand-logo {
                width: 80px;
                height: 80px;
            }

            .brand-logo img {
                width: 60px;
                height: 60px;
            }

            .brand-text h1 {
                font-size: 20px;
            }

            .login-form {
                padding: 30px 20px;
            }

            .form-header h2 {
                font-size: 26px;
            }

            .form-control,
            .btn-primary {
                height: 45px;
            }

            .form-options {
                flex-direction: column;
                gap: 12px;
                align-items: flex-start;
            }
        }
    </style>
</head>

<body>
    <div class="login-container">
        <!-- Left Side - Branding -->
        <div class="login-image">
            <div class="brand-logo">
                <img src="assets/img/icon/logo.png" alt="Charity Galley Foundation Logo">
            </div>
            <div class="brand-text">
                <h1>Charity Galley Foundation</h1>
                <p>Empowering communities through education, technology, and sustainable development</p>
            </div>
        </div>

        <!-- Right Side - Login Form -->
        <div class="login-form">
            <div class="form-header">
                <h2>Admin Login</h2>
                <p>Enter your credentials to access the dashboard</p>
            </div>

            <!-- Alert Messages -->
            <?php
            $message = get_message();
            if ($message):
            ?>
                <div class="alert alert-<?php echo $message['type'] === 'error' ? 'error' : 'success'; ?>" id="message-box">
                    <i class="fas fa-<?php echo $message['type'] === 'error' ? 'exclamation-circle' : 'check-circle'; ?>"></i>
                    <span><?php echo htmlspecialchars($message['message']); ?></span>
                </div>
            <?php endif; ?>

            <!-- Login Form -->
            <form action="" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="form-group">
                    <label class="form-label" for="email">Email Address</label>
                    <input 
                        type="email" 
                        id="email" 
                        class="form-control" 
                        name="email" 
                        placeholder="admin@charitygalleyfoundation.com" 
                        required 
                        autofocus
                    >
                </div>

                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <div class="password-wrapper">
                        <input 
                            type="password" 
                            id="password" 
                            class="form-control" 
                            name="password" 
                            placeholder="Enter your password" 
                            required
                        >
                        <span class="password-toggle" onclick="togglePassword()">
                            <i class="fas fa-eye" id="toggleIcon"></i>
                        </span>
                    </div>
                </div>

                <div class="form-options">
                    <div class="checkbox-wrapper">
                        <input type="checkbox" id="remember" name="remember">
                        <label for="remember">Remember me</label>
                    </div>
                    <a href="#" class="forgot-password">Forgot Password?</a>
                </div>

                <button type="submit" class="btn-primary">
                    Sign In
                </button>
            </form>

            <div class="form-footer">
                <p>Powered by <a href="https://blackcodecyberzone.tech/" target="_blank">BlackCodeCyberZone</a></p>
            </div>
        </div>
    </div>

    <script>
        // Toggle password visibility
        function togglePassword() {
            const passwordField = document.getElementById("password");
            const toggleIcon = document.getElementById("toggleIcon");

            if (passwordField.type === "password") {
                passwordField.type = "text";
                toggleIcon.classList.remove("fa-eye");
                toggleIcon.classList.add("fa-eye-slash");
            } else {
                passwordField.type = "password";
                toggleIcon.classList.remove("fa-eye-slash");
                toggleIcon.classList.add("fa-eye");
            }
        }

        // Auto-hide messages after 5 seconds
        setTimeout(function() {
            const messageBox = document.getElementById('message-box');
            if (messageBox) {
                messageBox.style.transition = "opacity 0.5s ease";
                messageBox.style.opacity = "0";
                setTimeout(() => messageBox.remove(), 500);
            }
        }, 5000);

        // Prevent multiple form submissions
        document.querySelector('form').addEventListener('submit', function(e) {
            const submitBtn = this.querySelector('.btn-primary');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing in...';
        });
    </script>
</body>
</html>