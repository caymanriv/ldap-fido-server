import React, { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Box,
	Button,
	CircularProgress,
	Stack,
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableRow,
	Typography,
} from '@mui/material';
import { useAuth } from './contexts/AuthContext';

function Admin() {
	const { user } = useAuth();
	const [users, setUsers] = useState([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState(null);
	const [readOnly, setReadOnly] = useState(false);
	const [revokingUserId, setRevokingUserId] = useState(null);

	const fetchUsers = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch('/admin/users', { credentials: 'include' });
			const data = await res.json().catch(() => ({}));
			if (!res.ok || !data.success) {
				throw new Error(data.message || 'Failed to fetch users');
			}
			setUsers(Array.isArray(data.users) ? data.users : []);
			setReadOnly(!!data.readOnly);
		} catch (err) {
			setError(err.message || 'Error loading users');
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		fetchUsers();
	}, [fetchUsers]);

	const revokeAuthenticator = async (targetUserId) => {
		if (!window.confirm('Are you sure you want to revoke this user\'s security key?')) {
			return;
		}
		setError(null);
		setRevokingUserId(targetUserId);
		try {
			const res = await fetch(`/admin/users/${targetUserId}/authenticator`, {
				method: 'DELETE',
				credentials: 'include',
			});
			const data = await res.json().catch(() => ({}));
			if (!res.ok || !data.success) {
				throw new Error(data.message || 'Failed to revoke authenticator');
			}
			await fetchUsers();
		} catch (err) {
			setError(err.message || 'Error revoking authenticator');
		} finally {
			setRevokingUserId(null);
		}
	};

	const myUserId = user?.id || user?.user_id;

	return (
		<Box>
			<Stack spacing={2} sx={{ mb: 2 }}>
				<Box>
					<Typography variant="h5" sx={{ fontWeight: 700 }}>
						Admin
					</Typography>
					<Typography variant="body2" color="text.secondary">
						Users and linked security keys
					</Typography>
				</Box>

				{readOnly && <Alert severity="info">Read-only access</Alert>}
				{error && <Alert severity="error">{error}</Alert>}
			</Stack>

			{loading ? (
				<Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
					<CircularProgress />
				</Box>
			) : (
				<Table size="small" sx={{ minWidth: 650 }}>
					<TableHead>
						<TableRow>
							<TableCell sx={{ fontWeight: 700 }}>Username</TableCell>
							<TableCell sx={{ fontWeight: 700 }}>Email</TableCell>
							<TableCell sx={{ fontWeight: 700 }}>Security Key</TableCell>
							<TableCell sx={{ fontWeight: 700 }} align="right">
								Action
							</TableCell>
						</TableRow>
					</TableHead>
					<TableBody>
						{users.map((u) => {
							const hasAuthenticator = !!u.hasAuthenticator;
							const authenticatorName = u.authenticatorName || '';
							const isSelf = myUserId && u.id === myUserId;
							const disableRevoke = readOnly || !hasAuthenticator || isSelf || revokingUserId === u.id;

							return (
								<TableRow key={u.id} hover>
									<TableCell>{u.username}</TableCell>
									<TableCell>{u.email}</TableCell>
									<TableCell>{hasAuthenticator ? (authenticatorName || 'Linked') : '—'}</TableCell>
									<TableCell align="right">
										<Button
											variant="contained"
											color="error"
											disabled={disableRevoke}
											onClick={() => revokeAuthenticator(u.id)}
											size="small"
										>
											{revokingUserId === u.id ? 'Revoking...' : 'Revoke'}
										</Button>
									</TableCell>
								</TableRow>
							);
						})}
					</TableBody>
				</Table>
			)}
		</Box>
	);
}

export default Admin;
