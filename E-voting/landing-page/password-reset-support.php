<?php

function passwordResetDirectory(): string
{
	$configuredPath = getenv('EVOTING_PASSWORD_RESET_DIR');
	$directory = is_string($configuredPath) && trim($configuredPath) !== ''
		? trim($configuredPath)
		: 'C:\\xampp\\private\\E-voting-reset-tokens';

	if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
		throw new RuntimeException('Password reset storage could not be created.');
	}

	$resolvedDirectory = realpath($directory);
	if ($resolvedDirectory === false) {
		throw new RuntimeException('Password reset storage could not be resolved.');
	}

	$documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath($_SERVER['DOCUMENT_ROOT']) : false;
	if ($documentRoot !== false) {
		$root = strtolower(rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $documentRoot), DIRECTORY_SEPARATOR));
		$storage = strtolower(rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $resolvedDirectory), DIRECTORY_SEPARATOR));
		if ($storage === $root || strpos($storage . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR) === 0) {
			throw new RuntimeException('Password reset storage must be outside the web root.');
		}
	}

	return $resolvedDirectory;
}

function createPasswordResetToken(string $directory, int $accountId): array
{
	$token = bin2hex(random_bytes(32));
	$tokenHash = hash('sha256', $token);
	$tokenPath = $directory . DIRECTORY_SEPARATOR . $tokenHash . '.json';
	$temporaryPath = tempnam($directory, '.reset-');
	if ($temporaryPath === false) {
		throw new RuntimeException('Password reset token could not be stored.');
	}

	$record = json_encode([
		'account_id' => $accountId,
		'token_hash' => $tokenHash,
		'expires_at' => time() + 1800,
	]);

	if ($record === false || file_put_contents($temporaryPath, $record, LOCK_EX) === false) {
		unlink($temporaryPath);
		throw new RuntimeException('Password reset token could not be stored.');
	}

	@chmod($temporaryPath, 0600);
	if (!rename($temporaryPath, $tokenPath)) {
		unlink($temporaryPath);
		throw new RuntimeException('Password reset token could not be stored.');
	}

	return ['token' => $token, 'path' => $tokenPath];
}

function allowPasswordResetRequest(string $directory, string $ipAddress): bool
{
	$ratePath = $directory . DIRECTORY_SEPARATOR . hash('sha256', $ipAddress) . '.rate';
	$rateFile = @fopen($ratePath, 'c+');
	if ($rateFile === false) {
		throw new RuntimeException('Password reset rate limit could not be checked.');
	}
	@chmod($ratePath, 0600);
	if (!flock($rateFile, LOCK_EX)) {
		fclose($rateFile);
		throw new RuntimeException('Password reset rate limit could not be locked.');
	}

	try {
		rewind($rateFile);
		$current = json_decode(stream_get_contents($rateFile), true);
		$now = time();
		$windowStart = is_array($current) && isset($current['window_start']) && is_int($current['window_start'])
			? $current['window_start']
			: 0;
		$count = is_array($current) && isset($current['count']) && is_int($current['count'])
			? $current['count']
			: 0;

		if ($now < $windowStart || $now - $windowStart >= 900) {
			$windowStart = $now;
			$count = 0;
		}
		if ($count >= 5) {
			return false;
		}

		$record = json_encode(['window_start' => $windowStart, 'count' => $count + 1]);
		if ($record === false || !ftruncate($rateFile, 0)) {
			throw new RuntimeException('Password reset rate limit could not be stored.');
		}
		rewind($rateFile);
		if (fwrite($rateFile, $record) === false || !fflush($rateFile)) {
			throw new RuntimeException('Password reset rate limit could not be stored.');
		}

		return true;
	} finally {
		flock($rateFile, LOCK_UN);
		fclose($rateFile);
	}
}

function passwordResetSender(): ?string
{
	$sender = getenv('EVOTING_RESET_FROM');
	if (!is_string($sender) || trim($sender) === '') {
		$sender = ini_get('sendmail_from');
	}

	$sender = is_string($sender) ? trim($sender) : '';
	return filter_var($sender, FILTER_VALIDATE_EMAIL) ? $sender : null;
}

function passwordResetLink(string $token): string
{
	$configuredBaseUrl = getenv('EVOTING_APP_BASE_URL');
	if (is_string($configuredBaseUrl) && trim($configuredBaseUrl) !== '') {
		$baseUrl = rtrim(trim($configuredBaseUrl), '/');
		$parts = parse_url($baseUrl);
		if (!filter_var($baseUrl, FILTER_VALIDATE_URL)
			|| !is_array($parts)
			|| !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
			|| empty($parts['host'])
			|| array_intersect(['user', 'pass', 'query', 'fragment'], array_keys($parts))) {
			throw new RuntimeException('The password reset base URL is invalid.');
		}
		if ($parts['scheme'] !== 'https' && !in_array(strtolower($parts['host']), ['localhost', '127.0.0.1'], true)) {
			throw new RuntimeException('Password reset links require HTTPS outside localhost.');
		}

		return $baseUrl . '/landing-page/reset-password.php?token=' . rawurlencode($token);
	}

	$host = $_SERVER['HTTP_HOST'] ?? '';
	if (!is_string($host) || !preg_match('/\A[a-zA-Z0-9.-]+(?::[0-9]{1,5})?\z/', $host)) {
		throw new RuntimeException('The password reset host is invalid.');
	}

	$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
	if ($scheme !== 'https' && !in_array(strtolower(explode(':', $host)[0]), ['localhost', '127.0.0.1'], true)) {
		throw new RuntimeException('Password reset links require HTTPS outside localhost.');
	}
	$directory = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/landing-page/forgot-password.php'));
	$directory = rtrim($directory, '/');

	return $scheme . '://' . $host . $directory . '/reset-password.php?token=' . rawurlencode($token);
}

function sendPasswordResetEmail(string $email, string $link): bool
{
	$sender = passwordResetSender();
	if ($sender === null) {
		return false;
	}

	$subject = 'Reset your CCS E-Voting System password';
	$message = "A password reset was requested for your CCS E-Voting System account.\r\n\r\n"
		. "Use the one-time link below within 30 minutes to choose a new password:\r\n"
		. $link . "\r\n\r\n"
		. "If you did not request a password reset, you can ignore this email.";
	$headers = [
		'From: CCS E-Voting System <' . $sender . '>',
		'Reply-To: ' . $sender,
		'Content-Type: text/plain; charset=UTF-8',
		'X-Mailer: PHP/' . PHP_VERSION,
	];

	return mail($email, $subject, $message, implode("\r\n", $headers));
}

function loadPasswordResetRecord(string $token): ?array
{
	if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) {
		return null;
	}

	$directory = passwordResetDirectory();
	$path = $directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
	if (!is_file($path)) {
		return null;
	}

	$content = file_get_contents($path);
	$record = is_string($content) ? json_decode($content, true) : null;
	if (!is_array($record)
		|| !isset($record['account_id'], $record['token_hash'], $record['expires_at'])
		|| !is_int($record['account_id'])
		|| !is_string($record['token_hash'])
		|| !is_int($record['expires_at'])
		|| $record['expires_at'] < time()
		|| !hash_equals($record['token_hash'], hash('sha256', $token))) {
		return null;
	}

	$record['path'] = $path;
	return $record;
}
