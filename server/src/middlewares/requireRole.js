// Middleware to require a specific role (or roles) for a route
export default function requireRole(roles, { readOnly = false } = {}) {
	return function (req, res, next) {
		// Check if user is authenticated
		if (!req.isAuthenticated?.() || !req.user) {
			// For API requests, return JSON response
			if (req.xhr || req.headers.accept?.includes('application/json')) {
				return res.status(401).json({ success: false, message: 'Not authenticated' });
			}
			// For browser requests, redirect to index
			return res.redirect('/');
		}

		// Check if user has required role
		const userRoles = req.user.roles || [];
		const hasRole = roles.some(role => userRoles.includes(role));
		
		if (!hasRole) {
			// For API requests, return JSON response
			if (req.xhr || req.headers.accept?.includes('application/json')) {
				return res.status(403).json({ success: false, message: 'Forbidden: insufficient privileges' });
			}
			// For browser requests, redirect to index
			return res.redirect('/');
		}

		// Attach readOnly flag for downstream handlers (for auditor role)
		req.readOnly = readOnly && userRoles.includes('auditor') && !userRoles.includes('admin');
		next();
	};
};
