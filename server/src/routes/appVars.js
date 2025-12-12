// Backend API for managing application variables (service-grouped)
import express from 'express';
import pool from '../db/index.js';
import requireRole from '../middlewares/requireRole.js';
import { deleteAuthenticator } from '../db/authenticatorOps.js';

// Create a router with a base path
const router = express.Router({ mergeParams: true });

// GET /admin/app-vars - Read all app variables grouped by service (admin, auditor)
router.get('/app-vars', requireRole(['admin', 'auditor'], { readOnly: true }), async (req, res, next) => {
	try {
		const { rows } = await pool.query('SELECT service, key, value, description FROM app_variables ORDER BY service, key');
		const grouped = {};
		for (const row of rows) {
			if (!grouped[row.service]) grouped[row.service] = {};
			grouped[row.service][row.key] = { value: row.value, description: row.description };
		}
		res.json({ services: grouped, readOnly: req.readOnly });
	} catch (err) {
		next(err);
	}
});

// PUT /admin/app-vars/:service - Update all variables for a service (admin only)
router.put('/app-vars/:service', requireRole(['admin']), async (req, res, next) => {
	const { service } = req.params;
	const updates = req.body; // { key1: value1, key2: value2, ... }
	try {
		for (const [key, value] of Object.entries(updates)) {
			await pool.query(
				`UPDATE app_variables SET value = $1, updated_at = NOW() WHERE service = $2 AND key = $3`,
				[value, service, key]
			);
		}
		res.json({ success: true });
	} catch (err) {
		next(err);
	}
});

// GET /admin/users - List users with role info and whether an authenticator is linked (admin, auditor)
router.get('/users', requireRole(['admin', 'auditor'], { readOnly: true }), async (req, res, next) => {
	try {
		const { rows } = await pool.query(
			`SELECT
				u.id,
				u.username,
				u.email,
				u.display_name as "displayName",
				COALESCE(
					json_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL),
					'[]'::json
				) as roles,
				(a.id IS NOT NULL) as "hasAuthenticator",
				a.id as "authenticatorId",
				a.name as "authenticatorName"
			FROM users u
			LEFT JOIN user_roles ur ON u.id = ur.user_id
			LEFT JOIN roles r ON ur.role_id = r.id
			LEFT JOIN authenticators a ON a.user_id = u.id
			GROUP BY u.id, a.id
			ORDER BY u.username ASC`
		);
		res.json({ success: true, users: rows, readOnly: req.readOnly });
	} catch (err) {
		next(err);
	}
});

// DELETE /admin/users/:userId/authenticator - Revoke a user's authenticator (admin only)
// Same effect as user self-service "Remove Security Key" (DB + LDAP)
router.delete('/users/:userId/authenticator', requireRole(['admin']), async (req, res, next) => {
	try {
		const { userId } = req.params;
		const requestingUserId = req.user?.id || req.user?.user_id;

		if (requestingUserId && userId === requestingUserId) {
			return res.status(403).json({
				success: false,
				message: 'Admins cannot revoke their own credential using this endpoint'
			});
		}

		const deleted = await deleteAuthenticator(userId);
		if (!deleted) {
			return res.status(404).json({ success: false, message: 'No authenticator found for user' });
		}

		res.json({ success: true, message: 'Authenticator revoked successfully' });
	} catch (err) {
		next(err);
	}
});

export default router;
