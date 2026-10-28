<?php
require_once __DIR__ . '/../admin-auth-guard.php';
require_once __DIR__ . '/../database/connect.php';
require_once __DIR__ . '/../database/sync-election-statuses.php';
syncElectionStatuses($conn);

if (!isset($_SESSION['csrf_token'])) {
	$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function escape(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

$error = '';
$resetPasswordRequested = false;
$resetVoterId = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$csrfToken = $_POST['csrf_token'] ?? '';
	$voterId = filter_input(INPUT_POST, 'voter_id', FILTER_VALIDATE_INT) ?: 0;
	$targetStatus = $_POST['status'] ?? '';
	$postAction = $_POST['action'] ?? 'update_status';

	if (!is_string($csrfToken) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
		$error = 'Your session expired. Reload the page and try again.';
	} elseif (!is_string($postAction) || !in_array($postAction, ['update_status', 'reset_password'], true)) {
		$error = 'Choose a valid voter account action.';
	} elseif ($postAction === 'reset_password') {
		$resetPasswordRequested = true;
		$resetVoterId = $voterId;
		$newPassword = $_POST['new_password'] ?? '';
		$confirmPassword = $_POST['confirm_password'] ?? '';

		if ($voterId < 1) {
			$error = 'Choose a valid voter account.';
		} elseif (!is_string($newPassword) || !is_string($confirmPassword)) {
			$error = 'Enter valid password values.';
		} elseif (strlen($newPassword) < 8 || strlen($newPassword) > 72) {
			$error = 'The temporary password must be between 8 and 72 characters.';
		} elseif ($newPassword !== $confirmPassword) {
			$error = 'The temporary password and confirmation do not match.';
		} else {
			try {
				$conn->begin_transaction();
				$voterQuery = $conn->prepare("SELECT account_id FROM accounts WHERE account_id = ? AND role = 'voter' LIMIT 1 FOR UPDATE");
				$voterQuery->bind_param('i', $voterId);
				$voterQuery->execute();
				$voter = $voterQuery->get_result()->fetch_assoc();
				$voterQuery->close();

				if (!$voter) {
					$conn->rollback();
					$error = 'That voter account could not be found.';
				} else {
					$passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
					if (!is_string($passwordHash)) {
						throw new RuntimeException('The temporary voter password could not be hashed.');
					}

					$update = $conn->prepare("UPDATE accounts SET password = ? WHERE account_id = ? AND role = 'voter'");
					$update->bind_param('si', $passwordHash, $voterId);
					$update->execute();
					$updated = $update->affected_rows;
					$update->close();

					if ($updated !== 1) {
						$conn->rollback();
						$error = 'That voter password could not be reset.';
					} else {
						$adminId = (int) $_SESSION['account_id'];
						$description = "Reset password for voter account ID {$voterId}";
						$log = $conn->prepare("INSERT INTO activity_logs (admin_id, action, description) VALUES (?, 'Reset voter password', ?)");
						$log->bind_param('is', $adminId, $description);
						$log->execute();
						$log->close();
						$conn->commit();
						$conn->close();
						header('Location: manage-voters.php?password_reset=1');
						exit;
					}
				}
			} catch (Throwable $exception) {
				$conn->rollback();
				error_log('Admin voter password reset error: ' . $exception->getMessage());
				$error = 'The voter password could not be reset. Please try again.';
			}
		}
	} elseif ($voterId < 1 || !is_string($targetStatus) || !in_array($targetStatus, ['active', 'inactive'], true)) {
		$error = 'Choose a valid voter account status.';
	} else {
		$voterQuery = $conn->prepare("SELECT status, (SELECT COUNT(*) FROM votes WHERE voter_id = accounts.account_id) AS vote_total FROM accounts WHERE account_id = ? AND role = 'voter' LIMIT 1");
		$voterQuery->bind_param('i', $voterId);
		$voterQuery->execute();
		$voter = $voterQuery->get_result()->fetch_assoc();
		$voterQuery->close();

		if (!$voter) {
			$error = 'That voter account could not be found.';
		} elseif ($voter['status'] === $targetStatus) {
			$error = 'That voter already has the selected status.';
		} else {
			try {
				$conn->begin_transaction();
				$adminId = (int) $_SESSION['account_id'];
				$description = "Changed voter account ID {$voterId} to {$targetStatus}; retained {$voter['vote_total']} associated ballots";
				$log = $conn->prepare("INSERT INTO activity_logs (admin_id, action, description) VALUES (?, 'Updated voter status', ?)");
				$log->bind_param('is', $adminId, $description);
				$log->execute();
				$log->close();

				$update = $conn->prepare("UPDATE accounts SET status = ? WHERE account_id = ? AND role = 'voter'");
				$update->bind_param('si', $targetStatus, $voterId);
				$update->execute();
				$updated = $update->affected_rows;
				$update->close();

				if ($updated !== 1) {
					$conn->rollback();
					$error = 'That voter account status could not be updated.';
				} else {
					$conn->commit();
					$conn->close();
					header('Location: manage-voters.php?status_changed=' . $targetStatus);
					exit;
				}
			} catch (mysqli_sql_exception $exception) {
				$conn->rollback();
				error_log($exception->getMessage());
				$error = 'The voter account status could not be updated.';
			}
		}
	}
}

$voterResult = $conn->query("
	SELECT a.account_id, a.student_id, a.fullname, a.email, a.course, a.year_level, a.status, a.created_at,
		(SELECT COUNT(*) FROM votes v WHERE v.voter_id = a.account_id) AS vote_total
	FROM accounts a
	WHERE a.role = 'voter'
	ORDER BY a.created_at DESC, a.account_id DESC
");
$voters = $voterResult->fetch_all(MYSQLI_ASSOC);
$resetVoterName = '';
if ($resetVoterId > 0) {
	foreach ($voters as $voter) {
		if ((int) $voter['account_id'] === $resetVoterId) {
			$resetVoterName = $voter['fullname'];
			break;
		}
	}
}
$ongoingElectionResult = $conn->query("SELECT election_id, election_name FROM elections WHERE status = 'ongoing' AND start_date <= NOW() AND end_date > NOW() ORDER BY start_date DESC LIMIT 1");
$ongoingElection = $ongoingElectionResult->fetch_assoc() ?: null;
$conn->close();

$adminName = $_SESSION['account_name'] ?? 'Administrator';
$adminInitial = strtoupper(substr($adminName, 0, 1));
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="theme-color" content="#f4fbfa">
	<title>Manage Voters | CCS E-Voting System</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/dist/tabler-icons.min.css">
	<link rel="stylesheet" href="../front_end/style.css?v=9">
	<script src="../front_end/script.js?v=8" defer></script>
</head>
<body class="admin-page">
	<div class="admin-layout">
		<aside class="admin-sidebar">
			<a class="admin-brand" href="admin-landing-page.php"><img src="../image/logo-css.jpg" alt=""><span><strong>CCS E-Voting</strong><small>ADMINISTRATION</small></span></a>
			<p class="admin-nav-label">WORKSPACE</p>
			<nav class="admin-nav" aria-label="Admin navigation">
				<a class="admin-nav-link" href="admin-landing-page.php"><i class="ti ti-layout-dashboard" aria-hidden="true"></i> Dashboard</a>
				<a class="admin-nav-link" href="election-status.php"><i class="ti ti-calendar-event" aria-hidden="true"></i> Election overview</a>
				<a class="admin-nav-link" href="add-candidates.php"><i class="ti ti-user-plus" aria-hidden="true"></i> Add candidates</a>
				<a class="admin-nav-link admin-nav-current" href="manage-voters.php"><i class="ti ti-users" aria-hidden="true"></i> Manage voters</a>
			</nav>
			<?php if ($ongoingElection): ?>
				<div class="admin-sidebar-election">
					<span>ONGOING ELECTION</span>
					<a href="add-candidates.php?election_id=<?= (int) $ongoingElection['election_id'] ?>"><?= escape($ongoingElection['election_name']) ?></a>
				</div>
			<?php endif; ?>
		</aside>
		<div class="admin-main">
			<header class="admin-topbar">
				<div><span class="admin-topbar-kicker">COLLEGE OF COMPUTER STUDIES</span><strong>Voter management</strong></div>
				<div class="admin-user"><span class="admin-avatar"><?= escape($adminInitial) ?></span><span class="admin-user-name"><?= escape($adminName) ?><small>Administrator</small></span><a class="admin-logout" href="../landing-page/index.php?logout=1" aria-label="Log out" title="Log out"><i class="ti ti-logout-2" aria-hidden="true"></i></a></div>
			</header>
			<main class="admin-content">
				<section class="admin-welcome">
					<div><p class="admin-eyebrow">REGISTERED ACCOUNTS</p><h1>Manage voters</h1><p>Review voter registrations and control account access without changing recorded ballots.</p></div>
				</section>
				<?php if ($error !== ''): ?><p class="admin-feedback admin-feedback-error" role="alert"><?= escape($error) ?></p><?php endif; ?>
				<?php if (isset($_GET['status_changed']) && in_array($_GET['status_changed'], ['active', 'inactive'], true)): ?><p class="admin-feedback admin-feedback-success" role="status">Voter account status updated to <?= escape($_GET['status_changed']) ?>. Existing ballots were retained.</p><?php endif; ?>
				<?php if (isset($_GET['password_reset'])): ?><p class="admin-feedback admin-feedback-success" role="status">Voter password reset successfully. Share the temporary password with the voter securely.</p><?php endif; ?>

				<section class="admin-work-panel admin-list-panel">
					<div class="admin-work-heading"><div><p class="admin-eyebrow">VOTER ACCOUNTS</p><h2>Registered voters</h2></div><span class="admin-count"><?= count($voters) ?> total</span></div>
					<?php if ($voters): ?>
						<div class="admin-table-wrap">
							<table class="admin-table admin-voter-table">
								<thead><tr><th>Name</th><th>Student ID</th><th>Email</th><th>Course</th><th>Year</th><th>Status</th><th>Votes</th><th>Registered</th><th>Action</th></tr></thead>
								<tbody>
									<?php foreach ($voters as $voter): ?>
										<tr>
											<td><strong><?= escape($voter['fullname']) ?></strong></td>
											<td><?= escape($voter['student_id'] ?? '') ?></td>
											<td><?= escape($voter['email']) ?></td>
											<td><?= escape($voter['course'] ?? '') ?></td>
											<td><?= escape($voter['year_level'] ?? '') ?></td>
											<td><span class="admin-table-status<?= $voter['status'] === 'inactive' ? ' admin-table-status-inactive' : '' ?>"><?= escape(ucfirst($voter['status'])) ?></span></td>
											<td><?= number_format((int) $voter['vote_total']) ?></td>
											<td><?= escape(date('M j, Y', strtotime($voter['created_at']))) ?></td>
											<td>
												<div class="admin-voter-actions">
													<button class="admin-small-button admin-voter-reset-trigger" type="button" data-voter-id="<?= (int) $voter['account_id'] ?>" data-voter-name="<?= escape($voter['fullname']) ?>">Reset password</button>
													<form method="post" action="manage-voters.php" data-confirm-title="<?= $voter['status'] === 'active' ? 'Deactivate voter?' : 'Reactivate voter?' ?>" data-confirm-message="Existing ballots will be retained. <?= $voter['status'] === 'active' ? 'This account will no longer be able to sign in or cast a ballot.' : 'This account will be able to sign in again.' ?>" data-confirm-action="<?= $voter['status'] === 'active' ? 'Deactivate voter' : 'Reactivate voter' ?>">
														<input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
														<input type="hidden" name="voter_id" value="<?= (int) $voter['account_id'] ?>">
														<input type="hidden" name="status" value="<?= $voter['status'] === 'active' ? 'inactive' : 'active' ?>">
														<button class="admin-small-button<?= $voter['status'] === 'active' ? ' admin-small-button-danger' : '' ?>" type="submit"><?= $voter['status'] === 'active' ? 'Deactivate' : 'Reactivate' ?></button>
													</form>
												</div>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						</div>
					<?php else: ?>
						<p class="admin-list-empty">No voter accounts have been registered yet.</p>
					<?php endif; ?>
				</section>
				<dialog class="confirmation-dialog admin-password-reset-dialog" id="voter-password-reset-dialog" aria-labelledby="voter-password-reset-title" aria-describedby="voter-password-reset-description">
					<div class="confirmation-card">
						<span class="confirmation-icon admin-password-reset-icon" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 7.5-2"></path><path d="M16 3v4h4"></path><path d="M12 15v2"></path></svg></span>
						<h2 id="voter-password-reset-title">Reset voter password</h2>
						<p id="voter-password-reset-description">Set a temporary password for <strong id="voter-password-reset-name"></strong>. Share it with the voter securely.</p>
						<form class="admin-password-reset-form" method="post" action="manage-voters.php">
							<input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
							<input type="hidden" name="action" value="reset_password">
							<input type="hidden" name="voter_id" id="voter-password-reset-id" value="<?= $resetPasswordRequested ? $resetVoterId : '' ?>">
							<label for="voter-new-password">Temporary password</label>
							<input id="voter-new-password" name="new_password" type="password" minlength="8" maxlength="72" autocomplete="new-password" required>
							<label for="voter-confirm-password">Confirm temporary password</label>
							<input id="voter-confirm-password" name="confirm_password" type="password" minlength="8" maxlength="72" autocomplete="new-password" required>
							<div class="admin-password-reset-actions">
								<button class="confirmation-cancel" type="button" id="cancel-voter-password-reset">Cancel</button>
								<button class="confirmation-accept" type="submit">Reset password</button>
							</div>
						</form>
					</div>
				</dialog>
			</main>
		</div>
	</div>
	<script>
		const resetDialog = document.querySelector('#voter-password-reset-dialog');
		const resetVoterName = document.querySelector('#voter-password-reset-name');
		const resetVoterId = document.querySelector('#voter-password-reset-id');
		const resetPasswordInput = document.querySelector('#voter-new-password');

		document.querySelectorAll('.admin-voter-reset-trigger').forEach((button) => {
			button.addEventListener('click', () => {
				resetVoterId.value = button.dataset.voterId || '';
				resetVoterName.textContent = button.dataset.voterName || '';
				resetDialog.showModal();
				resetPasswordInput.focus();
			});
		});

		document.querySelector('#cancel-voter-password-reset').addEventListener('click', () => resetDialog.close());

		<?php if ($resetPasswordRequested): ?>
			resetVoterName.textContent = <?= json_encode($resetVoterName !== '' ? $resetVoterName : 'the selected voter', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
			resetDialog.showModal();
			resetPasswordInput.focus();
		<?php endif; ?>
	</script>
</body>
</html>
