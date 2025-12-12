import React, { Component } from 'react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error boundary caught an error:', error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      const status = this.state.error?.status;
      
      // Handle different types of errors
      if (status >= 500) {
        return (
          <div className="error-boundary">
            <h2>Server Error</h2>
            <p>Sorry, something went wrong on our end. Please try again later.</p>
            <button onClick={this.handleRetry}>Retry</button>
          </div>
        );
      }

      if (status === 401) {
        return (
          <div className="error-boundary">
            <h2>Session Expired</h2>
            <p>Your session has expired. Please log in again.</p>
            <button onClick={() => window.location.href = '/login'}>Go to Login</button>
          </div>
        );
      }

      return (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message || 'An unexpected error occurred'}</p>
          <button onClick={this.handleRetry}>Retry</button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
