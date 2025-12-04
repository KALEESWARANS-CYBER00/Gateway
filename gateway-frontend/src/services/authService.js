import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080/api/auth';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and not already retried, try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/refresh`, {
            refreshToken,
          });

          const { accessToken, refreshToken: newRefreshToken } = response.data;
          localStorage.setItem('accessToken', accessToken);
          if (newRefreshToken) {
            localStorage.setItem('refreshToken', newRefreshToken);
          }

          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, logout user
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

const authService = {
  // Register new user
  register: async (email, password, name) => {
    const response = await axios.post(`${API_BASE_URL}/register`, {
      email,
      password,
      name,
    });
    return response.data;
  },

  // Login
  login: async (email, password) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/login`, {
        email,
        password,
      });

      // Backend returns: { message, accessToken, refreshToken }
      const { accessToken, refreshToken } = response.data;

      if (accessToken && refreshToken) {
        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('refreshToken', refreshToken);
        return response.data; // Return the whole object
      }

      throw new Error('No tokens received');
    } catch (error) {
      // Re-throw to let caller handle it
      throw error;
    }
  },

  // Logout
  logout: async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    if (refreshToken) {
      try {
        await axios.post(`${API_BASE_URL}/logout`, { refreshToken });
      } catch (error) {
        console.error('Logout error:', error);
      }
    }
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  },

  // Verify email with OTP
  verifyEmail: async (otp) => {
    const response = await axios.post(`${API_BASE_URL}/verify-email?otp=${otp}`);
    return response.data;
  },

  // Resend OTP
  resendOTP: async (email) => {
    const response = await axios.post(`${API_BASE_URL}/resend-otp?email=${email}`);
    return response.data;
  },

  // Forgot password
  forgotPassword: async (email) => {
    const response = await axios.post(`${API_BASE_URL}/forgot-password`, {
      email,
    });
    return response.data;
  },

  // Reset password with OTP
  resetPassword: async (otp, newPassword) => {
    const response = await axios.post(`${API_BASE_URL}/reset-password?otp=${otp}`, {
      newPassword,
    });
    return response.data;
  },

  // Get current user
  getCurrentUser: async () => {
    const response = await api.get('/me');
    return response.data;
  },

  // Check if user is authenticated
  isAuthenticated: () => {
    return !!localStorage.getItem('accessToken');
  },

  // Get access token
  getAccessToken: () => {
    return localStorage.getItem('accessToken');
  },
};

export default authService;
