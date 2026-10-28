<?php
session_start();
header('Referrer-Policy: no-referrer');
require_once __DIR__ . '/password-reset-support.php';

if (!isset($_SESSION['csrf_token'])) {
	$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$tokenValue = $_SERVER['REQUEST_METHOD'] === 'POST' ? ($_POST['token'] ?? '') : ($_GET['token'] ?? '');
$token = is_string($tokenValue) ? $tokenValue : '';
$error = '';
$validLink = false;

try {
	$record = loadPasswordResetRecord($token);
	if ($record !== null) {
		require __DIR__ . '/../database/connect.php';
		$accountQuery = $conn->prepare("SELECT account_id FROM accounts WHERE account_id = ? AND role = 'voter' AND status = 'active' LIMIT 1");
		$accountQuery->bind_param('i', $record['account_id']);
		$accountQuery->execute();
		$account = $accountQuery->get_result()->fetch_assoc();
		$accountQuery->close();
		$conn->close();
		$validLink = (bool) $account;
	}
} catch (Throwable $exception) {
	error_log('Password reset link validation error: ' . $exception->getMessage());
	if (isset($conn) && $conn instanceof mysqli) {
		$conn->close();
	}
	$error = 'Password reset is temporarily unavailable. Please try again later.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $error === '') {
	$csrfToken = $_POST['csrf_token'] ?? '';
	$passwordValue = $_POST['new_password'] ?? '';
	$confirmValue = $_POST['confirm_password'] ?? '';

	if (!is_string($csrfToken) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
		$error = 'Your session expired. Reload the page and try again.';
	} elseif (!is_string($passwordValue) || !is_string($confirmValue)) {
		$error = 'Enter valid password values.';
	} elseif (strlen($passwordValue) < 8 || strlen($passwordValue) > 72) {
		$error = 'Your password must be between 8 and 72 characters.';
	} elseif ($passwordValue !== $confirmValue) {
		$error = 'Your password and confirmation do not match.';
	} elseif (!$validLink || $record === null) {
		$error = 'This reset link is invalid or has expired. Request a new one.';
	} else {
		$tokenFile = @fopen($record['path'], 'r+');
		if ($tokenFile === false || !flock($tokenFile, LOCK_EX)) {
			if (is_resource($tokenFile)) {
				fclose($tokenFile);
			}
			$error = 'This reset link is invalid or has expired. Request a new one.';
		} else {
			try {
				rewind($tokenFile);
				$lockedRecord = json_decode(stream_get_contents($tokenFile), true);
				if (!is_array($lockedRecord)
					|| !isset($lockedRecord['account_id'], $lockedRecord['token_hash'], $lockedRecord['expires_at'])
					|| $lockedRecord['account_id'] !== $record['account_id']
					|| !is_string($lockedRecord['token_hash'])
					|| !hash_equals($lockedRecord['token_hash'], hash('sha256', $token))
					|| !is_int($lockedRecord['expires_at'])
					|| $lockedRecord['expires_at'] < time()) {
					$error = 'This reset link is invalid or has expired. Request a new one.';
				} else {
					require_once __DIR__ . '/../database/connect.php';
					$accountId = (int) $record['account_id'];
					$passwordHash = password_hash($passwordValue, PASSWORD_DEFAULT);
					if (!is_string($passwordHash)) {
						throw new RuntimeException('Password could not be hashed.');
					}

					$update = $conn->prepare("UPDATE accounts SET password = ? WHERE account_id = ? AND role = 'voter' AND status = 'active'");
					$conn->begin_transaction();
					$update->bind_param('si', $passwordHash, $accountId);
					$update->execute();
					$updated = $update->affected_rows;
					$update->close();

					if ($updated !== 1) {
						$conn->rollback();
						$conn->close();
						$error = 'Your password could not be reset. Request a new link and try again.';
					} else {
						if (!ftruncate($tokenFile, 0)) {
							throw new RuntimeException('Password reset token could not be invalidated.');
						}
						rewind($tokenFile);
						if (fwrite($tokenFile, '{"used":true}') === false || !fflush($tokenFile)) {
							throw new RuntimeException('Password reset token could not be invalidated.');
						}
						$conn->commit();
						$conn->close();
						$validLink = false;
						$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
						header('Location: log-in.php?password_reset=1');
						exit;
					}
				}
			} catch (Throwable $exception) {
				error_log('Password reset error: ' . $exception->getMessage());
				if (isset($conn) && $conn instanceof mysqli) {
					$conn->close();
				}
				$error = 'Password reset is temporarily unavailable. Please try again later.';
			} finally {
				flock($tokenFile, LOCK_UN);
				fclose($tokenFile);
			}
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
	<title>Reset password | CCS E-Voting System</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="../front_end/style.css?v=15">
	<script src="../front_end/script.js?v=8" defer></script>
</head>
<body class="auth-page">
	<header class="site-header auth-header">
		<a class="brand" href="index.php" aria-label="CCS E-Voting System home">
			<img class="brand-seal" src="../image/logo-css.jpg" alt="College of Computer Studies seal">
			<span class="brand-copy"><strong>CCS E-VOTING SYSTEM</strong><small>COLLEGE OF COMPUTER STUDIES</small></span>
		</a>
		<a class="auth-back" href="log-in.php">Back to Login</a>
	</header>
	<main class="settings-layout">
		<section class="auth-panel settings-panel forgot-password-panel" aria-labelledby="reset-password-title">
			<div class="forgot-password-icon" aria-hidden="true">
				<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10V7a5 5 0 0 1 10 0v3"></path><rect x="4" y="10" width="16" height="11" rx="2"></rect><path d="M12 14v3"></path></svg>
			</div>
			<div class="auth-heading forgot-password-heading">
				<p class="eyebrow">ACCOUNT RECOVERY</p>
				<h1 id="reset-password-title">Reset Your Password</h1>
				<p>Choose a new password for your voter account.</p>
			</div>
			<?php if ($error !== ''): ?><p class="auth-notice auth-error forgot-password-error" role="alert"><?= escape($error) ?></p><?php endif; ?>
			<?php if ($validLink): ?>
				<form class="auth-form forgot-password-form" method="post" action="reset-password.php" data-confirm-title="Save your new password?" data-confirm-message="Your password will be updated and this reset link can no longer be used." data-confirm-action="Save password">
					<input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
					<input type="hidden" name="token" value="<?= escape($token) ?>">
					<div class="auth-field">
						<label for="new-password">New password</label>
						<input id="new-password" name="new_password" type="password" minlength="8" maxlength="72" autocomplete="new-password" required>
					</div>
					<div class="auth-field">
						<label for="confirm-password">Confirm new password</label>
						<input id="confirm-password" name="confirm_password" type="password" minlength="8" maxlength="72" autocomplete="new-password" required>
					</div>
					<button class="auth-submit" type="submit">Save New Password</button>
				</form>
			<?php else: ?>
				<?php if ($error === ''): ?><p class="auth-notice auth-error forgot-password-error" role="alert">This reset link is invalid or has expired. Request a new one.</p><?php endif; ?>
				<p class="auth-switch forgot-password-back"><a href="forgot-password.php">Request another reset link</a></p>
			<?php endif; ?>
			<p class="auth-switch forgot-password-back"><a href="log-in.php">Back to Login</a></p>
		</section>
	</main>
</body>
</html>
