import React from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  Navigate,
  useNavigate,
} from 'react-router-dom';
import {
  AppBar,
  Box,
  Button,
  Container,
  CssBaseline,
  GlobalStyles,
  Paper,
  Toolbar,
  Typography,
} from '@mui/material';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import LoginForm from './LoginForm';
import Password from './Password';
import Admin from './Admin';
import Security from './components/Security';
import ErrorBoundary from './components/ErrorBoundary';
import { AuthProvider, useAuth } from './contexts/AuthContext';

function MenuSessionGuard({ children }) {
  const { user, isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  
  // Only redirect on initial load if not authenticated
  React.useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isLoading, isAuthenticated, navigate]);
  
  // Show loading state while checking auth
  if (isLoading) {
    return <div>Loading application...</div>;
  }
  
  // If not authenticated after loading, don't render children
  if (!isAuthenticated) {
    return null;
  }
  
  return (
    <ErrorBoundary>
      {children}
    </ErrorBoundary>
  );
}

function App() {
  const { user, isAuthenticated, isLoading, logout } = useAuth();

	const theme = React.useMemo(
		() =>
			createTheme({
				palette: {
					mode: 'light',
					primary: { main: '#1976d2' },
				},
				typography: {
					h4: { fontWeight: 700 },
					h5: { fontWeight: 700 },
				},
				shape: { borderRadius: 10 },
			}),
		[]
	);
  
  // Show loading state while checking auth status
  if (isLoading) {
    return (
			<ThemeProvider theme={theme}>
				<CssBaseline />
				<Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center' }}>
					<Container maxWidth="sm">
						<Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
							<Typography variant="h5">Loading application...</Typography>
						</Paper>
					</Container>
				</Box>
			</ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
			<CssBaseline />
			<GlobalStyles
				styles={(t) => ({
					// LoginForm.jsx uses Bootstrap-like classes; unify them with the MUI theme
					'.login-container .card': {
						borderRadius: t.shape.borderRadius,
					},
					'.login-container .card-body': {
						padding: t.spacing(4),
					},
					// Layout: place buttons to the right of the primary field and add breathing room
					'.login-container form': {
						display: 'flex',
						flexWrap: 'wrap',
						alignItems: 'flex-end',
						gap: t.spacing(0.25),
					},
					'.login-container form > .mb-3': {
						flex: '1 1 0px',
						minWidth: 0,
						marginBottom: 0,
					},
					'.login-container .input-group': {
						minWidth: 0,
					},
					'.login-container form > button.btn': {
						flex: '0 0 auto',
						width: 'auto',
					},
					'.login-container .d-grid': {
						display: 'flex',
						justifyContent: 'flex-end',
						gap: t.spacing(0.25),
						flexWrap: 'nowrap',
						flex: '0 0 auto',
						width: 'auto',
						marginTop: 0,
					},
					'.login-container .d-grid .btn': {
						width: 'auto',
					},
					'.login-container .btn.w-100': {
						width: 'auto',
					},
					'.login-container .form-label': {
						fontWeight: 600,
						color: t.palette.text.primary,
					},
					'.login-container .form-control': {
						borderRadius: t.shape.borderRadius,
						paddingTop: 10,
						paddingBottom: 10,
						borderColor: 'rgba(0,0,0,0.23)',
					},
					'.login-container .form-control:focus': {
						borderColor: t.palette.primary.main,
						boxShadow: `0 0 0 0.2rem ${t.palette.primary.main}22`,
					},
					'.login-container .btn': {
						borderRadius: t.shape.borderRadius,
						minHeight: 44,
						paddingTop: 10,
						paddingBottom: 10,
						paddingLeft: 16,
						paddingRight: 16,
						fontWeight: 700,
						letterSpacing: 0.2,
						textTransform: 'none',
					},
					'.login-container .btn-primary': {
						backgroundColor: '#fff',
						borderColor: t.palette.primary.main,
						color: t.palette.primary.main,
						borderWidth: 2,
						boxShadow: '0 6px 16px rgba(25, 118, 210, 0.12)',
					},
					'.login-container .btn-primary:hover': {
						backgroundColor: `${t.palette.primary.main}0f`,
						borderColor: t.palette.primary.dark,
						color: t.palette.primary.dark,
						boxShadow: '0 8px 18px rgba(25, 118, 210, 0.16)',
					},
					'.login-container .btn-primary:focus, .login-container .btn-primary:focus-visible': {
						outline: 'none',
						boxShadow: `0 0 0 0.22rem ${t.palette.primary.main}33, 0 8px 18px rgba(25, 118, 210, 0.18)`,
					},
					'.login-container .btn-outline-primary': {
						color: t.palette.primary.main,
						borderColor: t.palette.primary.main,
						borderWidth: 2,
					},
					'.login-container .btn-outline-primary:hover': {
						backgroundColor: `${t.palette.primary.main}14`,
					},
					'.login-container .btn-outline-primary:focus, .login-container .btn-outline-primary:focus-visible': {
						outline: 'none',
						boxShadow: `0 0 0 0.22rem ${t.palette.primary.main}22`,
					},
					'.login-container .btn-outline-secondary': {
						borderRadius: t.shape.borderRadius,
						borderWidth: 2,
					},
					'.login-container .btn:disabled, .login-container .btn.disabled': {
						opacity: 0.55,
					},
				})}
			/>
			<Router>
				<Box sx={{ minHeight: '100vh', bgcolor: 'grey.100' }}>
					<AppBar position="static" color="primary" elevation={0}>
						<Toolbar>
							<Box sx={{ flex: 1, display: 'flex', alignItems: 'center' }}>
								<Typography variant="h6" sx={{ fontWeight: 700 }}>
									LDAP-FIDO Server
								</Typography>
							</Box>

							{isAuthenticated ? (
								<>
									<Box sx={{ flex: 1, display: 'flex', justifyContent: 'center', gap: 1 }}>
										<Button component={Link} to="/" color="inherit">
											Home
										</Button>
										<Button component={Link} to="/profile" color="inherit">
											LDAP password
										</Button>
										{user?.isAdmin && (
											<Button component={Link} to="/admin" color="inherit">
												Admin
											</Button>
										)}
									</Box>

									<Box sx={{ flex: 1, display: 'flex', justifyContent: 'flex-end' }}>
										<Button
											variant="outlined"
											color="inherit"
											onClick={logout}
											sx={{
												borderColor: 'rgba(255,255,255,0.7)',
												color: '#fff',
												'&:hover': { borderColor: '#fff', bgcolor: 'rgba(255,255,255,0.12)' },
											}}
										>
											Logout
										</Button>
									</Box>
								</>
							) : (
								<Box sx={{ flex: 2, display: 'flex', justifyContent: 'flex-end' }}>
									<Typography variant="body2" sx={{ opacity: 0.9 }}>
										Welcome
									</Typography>
								</Box>
							)}
						</Toolbar>
					</AppBar>

					<Container maxWidth="md" sx={{ py: 4 }}>
						<Paper elevation={3} sx={{ p: { xs: 2, sm: 3 } }}>
							<Routes>
								<Route
									path="/"
									element={
										isAuthenticated ? (
											<MenuSessionGuard>
												<Security />
											</MenuSessionGuard>
										) : (
											<Box sx={{ maxWidth: 520, mx: 'auto' }}>
												<LoginForm
													onLogin={(userData) => {
														// This will be handled by the AuthProvider's login function
														// which is already set up to update the authentication state
												}}
												/>
											</Box>
										)
									}
								/>

								<Route
									path="/profile"
									element={
										<MenuSessionGuard>
											<Password />
										</MenuSessionGuard>
									}
								/>

								<Route path="/security" element={<Navigate to="/" replace />} />

								<Route
									path="/admin"
									element={
										<MenuSessionGuard>
											{user?.isAdmin ? <Admin /> : <Navigate to="/" replace />}
										</MenuSessionGuard>
									}
								/>
							</Routes>
						</Paper>
					</Container>
				</Box>
			</Router>
		</ThemeProvider>
  );
}

export default App;
