<?php
if (PHP_SAPI !== 'cli') {
	http_response_code(404);
	exit('Not found.');
}

$fullname = getenv('ADMIN_FULLNAME');
$username = getenv('ADMIN_USERNAME');
$email = getenv('ADMIN_EMAIL');
$password = getenv('ADMIN_PASSWORD');

if (!is_string($fullname) || !is_string($username) || !is_string($email) || !is_string($password)
	|| trim($fullname) === '' || strlen($fullname) > 100
	|| trim($username) === '' || strlen($username) > 50
	|| !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100
	|| strlen($password) < 12 || strlen($password) > 72) {
	fwrite(STDERR, "Set ADMIN_FULLNAME, ADMIN_USERNAME, ADMIN_EMAIL, and ADMIN_PASSWORD. The password must be 12-72 bytes.\n");
	exit(1);
}

require_once __DIR__ . '/../database/connect.php';

$existingAdmins = $conn->query("SELECT COUNT(*) AS total FROM accounts WHERE role = 'admin'")->fetch_assoc();
if ((int) $existingAdmins['total'] !== 0) {
	$conn->close();
	fwrite(STDERR, "An administrator account already exists; bootstrap is disabled.\n");
	exit(1);
}

$passwordHash = password_hash($password, PASSWORD_DEFAULT);
try {
	$stmt = $conn->prepare("INSERT INTO accounts (fullname, username, email, password, role, status) VALUES (?, ?, ?, ?, 'admin', 'active')");
	$stmt->bind_param('ssss', $fullname, $username, $email, $passwordHash);
	$stmt->execute();
	$stmt->close();
	$conn->close();
} catch (mysqli_sql_exception $exception) {
	error_log('Administrator bootstrap failed: ' . $exception->getMessage());
	$conn->close();
	if ((int) $exception->getCode() === 1062) {
		fwrite(STDERR, "The username or email address is already in use.\n");
	} else {
		fwrite(STDERR, "The administrator account could not be created. Check the database configuration and try again.\n");
	}
	exit(1);
}

fwrite(STDOUT, "Initial administrator account created.\n");