import React, { createContext, useState, useContext, useEffect } from 'react';
import authService from './services/authService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check if user is authenticated on mount
    const checkAuth = async () => {
      if (authService.isAuthenticated()) {
        try {
          const userData = await authService.getCurrentUser();
          setUser(userData);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Failed to get user data:', error);
          authService.logout();
          setIsAuthenticated(false);
        }
      }
      setLoading(false);
    };

    checkAuth();
  }, []);

  const login = async (email, password) => {
    try {
      // This will throw on error (403, 401, etc.)
      const data = await authService.login(email, password);

      // If we get here, login was successful and tokens are saved
      console.log('Login successful, data:', data);

      // Set authenticated IMMEDIATELY - this is critical for navigation to work
      setIsAuthenticated(true);

      // Try to fetch user data in background (non-blocking)
      authService.getCurrentUser()
        .then(userData => {
          console.log('User data fetched:', userData);
          setUser(userData);
        })
        .catch(userError => {
          console.error('Could not fetch user data (non-critical):', userError);
          // Not a fatal error - user is still authenticated
        });

      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);

      // Check the error status code
      const status = error.response?.status;
      const errorData = error.response?.data;

      if (status === 403) {
        // Email not verified
        return {
          success: false,
          needsVerification: true,
          error: errorData?.error || 'Email not verified. Please check your email for the verification code.'
        };
      }

      if (status === 423) {
        // Account locked
        return {
          success: false,
          error: errorData?.message || 'Account is locked'
        };
      }

      // Invalid credentials or other error
      return {
        success: false,
        error: errorData?.error || 'Invalid email or password'
      };
    }
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
    setIsAuthenticated(false);
  };

  const register = async (email, password, name) => {
    try {
      const response = await authService.register(email, password, name);
      return { success: true, data: response };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || error.response?.data?.message || 'Registration failed'
      };
    }
  };

  const value = {
    user,
    isAuthenticated,
    loading,
    login,
    logout,
    register,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
