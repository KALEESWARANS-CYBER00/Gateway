import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import authService from '../services/authService';
import './Dashboard.css';

const Home = () => {
  const { logout } = useAuth();
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const data = await authService.getCurrentUser();
        setUserData(data);
      } catch (error) {
        console.error('Failed to fetch user data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getInitials = (name) => {
    if (!name) return 'U';
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="spinner"></div>
        <p>Loading your dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1>Welcome back, {userData?.name || 'User'}! 👋</h1>
          <p style={{ color: 'var(--text-secondary)', margin: '0.5rem 0 0 0', fontSize: '1rem' }}>
            {(() => {
              const hour = new Date().getHours();
              if (hour < 12) return '☀️ Good morning! ';
              if (hour < 18) return '🌤️ Good afternoon! ';
              return '🌙 Good evening! ';
            })()}
            Great to see you today.
          </p>
          <p style={{
            color: 'var(--success)',
            margin: '0.5rem 0 0 0',
            fontSize: '0.9rem',
            fontWeight: '500'
          }}>
            ✓ You're successfully logged in to your account
          </p>
        </div>
        <div className="user-info">
          <div className="user-avatar">
            {getInitials(userData?.name)}
          </div>
          <button onClick={handleLogout} className="btn btn-logout">
            Logout
          </button>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Account Information Card */}
        <div className="dashboard-card">
          <h2>
            <div className="card-icon">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
              </svg>
            </div>
            Account Information
          </h2>
          <div className="card-content">
            <div className="info-row">
              <span className="info-label">Name</span>
              <span className="info-value">{userData?.name || 'N/A'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Email</span>
              <span className="info-value">{userData?.email || 'N/A'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Role</span>
              <span className="info-value">{userData?.role || 'USER'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Status</span>
              <span className="info-value">
                {userData?.emailVerified ? (
                  <span className="status-badge verified">
                    <span className="dot"></span>
                    Verified
                  </span>
                ) : (
                  <span className="status-badge unverified">
                    <span className="dot"></span>
                    Unverified
                  </span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Activity Card */}
        <div className="dashboard-card">
          <h2>
            <div className="card-icon">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
              </svg>
            </div>
            Activity
          </h2>
          <div className="card-content">
            <div className="info-row">
              <span className="info-label">Account Created</span>
              <span className="info-value">{formatDate(userData?.createdAt)}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Last Login</span>
              <span className="info-value">{formatDate(userData?.lastLoginAt)}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Account ID</span>
              <span className="info-value">#{userData?.id || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Security Card */}
        <div className="dashboard-card">
          <h2>
            <div className="card-icon">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            Security
          </h2>
          <div className="card-content">
            <p style={{ marginBottom: 'var(--spacing-md)' }}>
              Your account is secured with industry-standard encryption and authentication.
            </p>
            <div className="action-buttons">
              <button
                className="btn btn-secondary"
                onClick={() => navigate('/forgot-password')}
                style={{ width: '100%' }}
              >
                Change Password
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
