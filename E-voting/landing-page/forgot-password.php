<?php
session_start();
require_once __DIR__ . '/password-reset-support.php';

if (!isset($_SESSION['csrf_token'])) {
	$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$email = '';
$error = '';
$success = false;
$statusEmail = '';
$flash = $_SESSION['password_reset_flash'] ?? null;
unset($_SESSION['password_reset_flash']);

if (is_array($flash)) {
	$success = ($flash['status'] ?? '') === 'success';
	$error = is_string($flash['error'] ?? null) ? $flash['error'] : '';
	$statusEmail = is_string($flash['email'] ?? null) ? $flash['email'] : '';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$postedEmail = $_POST['email'] ?? '';
	$csrfToken = $_POST['csrf_token'] ?? '';
	$email = is_string($postedEmail) ? trim($postedEmail) : '';

	if (!is_string($csrfToken) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
		$error = 'Your session expired. Reload the page and try again.';
	} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
		$error = 'Enter a valid email address.';
	} elseif (isset($_SESSION['password_reset_requested_at']) && time() - (int) $_SESSION['password_reset_requested_at'] < 60) {
		$error = 'Please wait a minute before requesting another reset email.';
	} else {
		$tokenPath = null;
		try {
			$storageDirectory = passwordResetDirectory();
			if (!allowPasswordResetRequest($storageDirectory, (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'))) {
				$error = 'Too many reset requests were made from this connection. Try again in 15 minutes.';
			} else {
				$_SESSION['password_reset_requested_at'] = time();
				require_once __DIR__ . '/../database/connect.php';
				$stmt = $conn->prepare("SELECT account_id FROM accounts WHERE email = ? AND role = 'voter' AND status = 'active' LIMIT 1");
				$stmt->bind_param('s', $email);
				$stmt->execute();
				$account = $stmt->get_result()->fetch_assoc();
				$stmt->close();

				if ($account) {
					$tokenData = createPasswordResetToken($storageDirectory, (int) $account['account_id']);
					$tokenPath = $tokenData['path'];
					$link = passwordResetLink($tokenData['token']);
					if (!sendPasswordResetEmail($email, $link)) {
						unlink($tokenPath);
						$tokenPath = null;
						throw new RuntimeException('Password reset email could not be handed to the mail server.');
					}
				}

				$conn->close();
				$_SESSION['password_reset_flash'] = ['status' => 'success', 'email' => $email];
				header('Location: forgot-password.php');
				exit;
			}
		} catch (Throwable $exception) {
			if (is_string($tokenPath) && is_file($tokenPath)) {
				unlink($tokenPath);
			}
			error_log('Password reset request error: ' . $exception->getMessage());
			if (isset($conn) && $conn instanceof mysqli) {
				$conn->close();
			}
			$error = 'We could not send a password reset email. Check the server mail configuration and try again.';
		}
	}
}

function escape(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="theme-color" content="#f4fbfa">
	<meta name="referrer" content="no-referrer">
	<title>Forgot password | CCS E-Voting System</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="../front_end/style.css?v=16">
</head>
<body class="auth-page">
	<header class="site-header auth-header">
		<a class="brand" href="index.php" aria-label="CCS E-Voting System home">
			<img class="brand-seal" src="../image/logo-css.jpg" alt="College of Computer Studies seal">
			<span class="brand-copy"><strong>CCS E-VOTING SYSTEM</strong><small>COLLEGE OF COMPUTER STUDIES</small></span>
		</a>
		<a class="auth-back" href="log-in.php"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m15 18-6-6 6-6"></path><path d="M9 12h12"></path></svg> Back to Login</a>
	</header>
	<main class="settings-layout">
		<section class="auth-panel settings-panel forgot-password-panel" aria-labelledby="forgot-password-title">
			<div class="forgot-password-icon" aria-hidden="true">
				<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m3 7 9 6 9-6"></path></svg>
			</div>
			<div class="auth-heading forgot-password-heading">
				<p class="eyebrow">ACCOUNT RECOVERY</p>
				<h1 id="forgot-password-title">Forgot Password?</h1>
				<p>Enter the email address registered to your voter account to receive password reset instructions.</p>
			</div>
			<?php if ($error !== ''): ?><p class="auth-notice auth-error forgot-password-error" role="alert"><?= escape($error) ?></p><?php endif; ?>
			<form class="auth-form forgot-password-form" id="forgot-password-form" method="post" action="forgot-password.php">
				<input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
				<div class="auth-field">
					<label for="reset-email">Email address</label>
					<input id="reset-email" name="email" type="email" autocomplete="email" placeholder="name@example.com" value="<?= escape($email) ?>" maxlength="100" required>
				</div>
				<button class="auth-submit" type="submit">Send Reset Link</button>
			</form>
			<p class="auth-switch forgot-password-back"><a href="log-in.php">Back to Login</a></p>
		</section>
	</main>
	<?php if ($success): ?>
		<dialog class="forgot-password-dialog" id="check-inbox-dialog" aria-labelledby="check-inbox-title" aria-describedby="check-inbox-description">
			<section class="forgot-password-dialog-card">
				<div class="forgot-password-icon forgot-password-success-icon" aria-hidden="true">
					<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m3 7 9 6 9-6"></path><path d="m16 11 2 2 4-4"></path></svg>
				</div>
				<h2 id="check-inbox-title">Password Reset Email Sent!</h2>
				<p id="check-inbox-description">If your email address is registered, you will receive instructions to reset your password. Please check your inbox.</p>
				<p class="forgot-password-submitted-email"><?= escape($statusEmail) ?></p>
				<a class="auth-submit forgot-password-login-link" href="log-in.php">Back to Login</a>
			</section>
		</dialog>
	<?php endif; ?>
	<script>
		const inboxDialog = document.querySelector('#check-inbox-dialog');
		if (inboxDialog) {
			inboxDialog.showModal();
		}

		const resetForm = document.querySelector('#forgot-password-form');
		if (resetForm) {
			resetForm.addEventListener('submit', (event) => {
				if (!resetForm.reportValidity()) {
					event.preventDefault();
					return;
				}

				const button = resetForm.querySelector('button[type="submit"]');
				button.disabled = true;
				button.setAttribute('aria-busy', 'true');
				button.classList.add('is-loading');
				button.textContent = 'Sending…';
			});
		}
	</script>
</body>
</html>
