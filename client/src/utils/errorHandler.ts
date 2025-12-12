interface ApiError extends Error {
  response?: {
    status?: number;
    data?: {
      message?: string;
      code?: string;
    };
  };
}

export const handleApiError = (error: unknown, setError?: (message: string) => void): string => {
  console.error('API Error:', error);
  
  // Default error message
  let errorMessage = 'An unexpected error occurred. Please try again.';
  
  // Handle different types of errors
  if (error instanceof Error) {
    const apiError = error as ApiError;
    
    // Handle HTTP errors
    if (apiError.response) {
      const { status, data } = apiError.response;
      
      if (status === 401) {
        errorMessage = 'Session expired. Please log in again.';
      } else if (status === 403) {
        errorMessage = 'You do not have permission to perform this action.';
      } else if (status === 404) {
        errorMessage = 'The requested resource was not found.';
      } else if (status === 429) {
        errorMessage = 'Too many requests. Please wait before trying again.';
      } else if (data?.message) {
        errorMessage = data.message;
      }
    } else if (error.message) {
      // Handle other Error objects
      errorMessage = error.message;
    }
  } else if (typeof error === 'string') {
    errorMessage = error;
  }
  
  // Update error state if setError function is provided
  if (setError) {
    setError(errorMessage);
  }
  
  return errorMessage;
};

export const isNetworkError = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  return (
    error.message === 'Network request failed' ||
    error.message === 'Failed to fetch' ||
    (error as any).code === 'ECONNABORTED' ||
    (error as any).code === 'ECONNRESET'
  );
};
