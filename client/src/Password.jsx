import React, { useState } from 'react';
import {
	Alert,
	Box,
	Button,
	Stack,
	TextField,
	Typography,
} from '@mui/material';

function Password({ user }) {
	const [currentPassword, setCurrentPassword] = useState('');
	const [newPassword, setNewPassword] = useState('');
	const [confirmPassword, setConfirmPassword] = useState('');
	const [status, setStatus] = useState(null);
	const [loading, setLoading] = useState(false);

	const handleChangePassword = async (e) => {
		e.preventDefault();
		setStatus(null);
		if (!currentPassword || !newPassword || !confirmPassword) {
			setStatus({ error: 'All fields are required.' });
			return;
		}
		if (newPassword !== confirmPassword) {
			setStatus({ error: 'New passwords do not match.' });
			return;
		}
		setLoading(true);
		try {
			const res = await fetch('/api/auth/change-password', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ currentPassword, newPassword }),
			});
			const data = await res.json();
			if (data.success) {
				setStatus({ success: 'Password changed successfully.' });
				setCurrentPassword('');
				setNewPassword('');
				setConfirmPassword('');
			} else {
				setStatus({ error: data.message || 'Password change failed.' });
			}
		} catch (err) {
			setStatus({ error: 'Network error.' });
		} finally {
			setLoading(false);
		}
	};

	// Ensure user object exists with defaults
	const safeUser = user || {};
	
	return (
		<Box sx={{ maxWidth: 520, mx: 'auto' }}>
			<Stack spacing={2}>
				<Box>
					<Typography variant="h5" sx={{ fontWeight: 700 }}>
						LDAP password
					</Typography>
					<Typography variant="body2" color="text.secondary">
						Change the password for {(safeUser.cn || safeUser.uid || safeUser.username || 'your account')}.
					</Typography>
				</Box>

				{status?.success && <Alert severity="success">{status.success}</Alert>}
				{status?.error && <Alert severity="error">{status.error}</Alert>}
				{newPassword && confirmPassword && newPassword !== confirmPassword && (
					<Alert severity="warning">New passwords do not match.</Alert>
				)}

				<Box
					component="form"
					onSubmit={handleChangePassword}
					sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}
				>
					<TextField
						label="Current password"
						type="password"
						value={currentPassword}
						onChange={(e) => setCurrentPassword(e.target.value)}
						required
						disabled={loading}
						autoComplete="current-password"
					/>
					<TextField
						label="New password"
						type="password"
						value={newPassword}
						onChange={(e) => setNewPassword(e.target.value)}
						required
						disabled={loading}
						autoComplete="new-password"
					/>
					<TextField
						label="Confirm new password"
						type="password"
						value={confirmPassword}
						onChange={(e) => setConfirmPassword(e.target.value)}
						required
						disabled={loading}
						autoComplete="new-password"
					/>
					<Button
						type="submit"
						variant="contained"
						color="primary"
						disabled={
							loading ||
							!newPassword ||
							!confirmPassword ||
							newPassword !== confirmPassword
						}
						sx={{ alignSelf: 'flex-start' }}
					>
						{loading ? 'Changing...' : 'Change password'}
					</Button>
				</Box>
			</Stack>
		</Box>
	);
}

export default Password;
