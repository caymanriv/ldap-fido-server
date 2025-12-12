import request from 'supertest';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { configureLdapAuth } from '../src/utils/ldapClient.js';
import authRoutes from '../src/routes/auth.js';
import RedisStore from 'connect-redis';
import { createClient as createRedisClient } from 'redis';

// Minimal test app for auth
async function createTestApp() {
	const app = express();
	app.use(express.json());
	const redisClient = createRedisClient({ socket: { host: 'localhost', port: 6379 } });
	await redisClient.connect();
	app.use(
		session({
			store: new RedisStore({ client: redisClient }),
			secret: 'testsecret',
			resave: false,
			saveUninitialized: false,
			cookie: { secure: false },
		})
	);
	app.use(passport.initialize());
	app.use(passport.session());
	configureLdapAuth(passport);
	app.use('/api/auth', authRoutes);
	return { app, redisClient };
}

describe('Auth API', () => {
	let app;
	let redisClient;
	beforeAll(async () => {
		const ctx = await createTestApp();
		app = ctx.app;
		redisClient = ctx.redisClient;
	});

	it('should reject unauthenticated /me', async () => {
		const res = await request(app).get('/api/auth/me');
		expect(res.status).toBe(401);
		expect(res.body.authenticated).toBe(false);
	});

	// Additional tests for login/logout can be added here, with mock LDAP or integration
	afterAll(async () => {
		if (redisClient) {
			try {
				await redisClient.quit();
			} catch (_) {
				// ignore
			}
		}
	});
});
