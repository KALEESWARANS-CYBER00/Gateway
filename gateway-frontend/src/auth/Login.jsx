import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import ErrorMessage from '../components/ErrorMessage';
import SuccessMessage from '../components/SuccessMessage';
import './AuthHacker.css';

const Login = () => {
  const [form, setForm] = useState({ email: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    const result = await login(form.email, form.password);
    setLoading(false);

    console.log('Login result:', result);

    if (result.success) {
      setSuccess('✓ ACCESS GRANTED! Redirecting...');
      setTimeout(() => {
        navigate("/dashboard", { replace: true });
      }, 800);
    } else if (result.needsVerification) {
      setError(result.error);
      setTimeout(() => {
        navigate('/verify-email', { state: { email: form.email } });
      }, 2000);
    } else {
      setError(result.error);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-content-wrapper">
        {/* Left Sidebar - Cyber Awareness */}
        <div className="cyber-awareness-left">
          <div className="awareness-card">
            <img src="/cyber-shield.png" alt="Cyber Security" className="awareness-image" />
            <h3>🛡️ Protect Your Identity</h3>
            <p>Strong authentication is your first line of defense against cyber threats.</p>
            <ul>
              <li>Use unique passwords for each account</li>
              <li>Enable two-factor authentication</li>
              <li>Never share your credentials</li>
            </ul>
          </div>

          <div className="awareness-card">
            <h3>⚠️ Phishing Alert</h3>
            <p>Cybercriminals use fake login pages to steal credentials.</p>
            <ul>
              <li>Always verify the URL</li>
              <li>Look for HTTPS encryption</li>
              <li>Don't click suspicious links</li>
            </ul>
          </div>
        </div>

        {/* Center - Login Form */}
        <div className="auth-card fade-in">
          <div className="auth-logo">
            <img src="/authify-logo.png" alt="Authify Logo" />
            <div className="auth-logo-text">AUTHIFY</div>
          </div>

          <div className="auth-header">
            <h1>▶ System Login</h1>
            <p>Enter your credentials to access the secure system</p>
          </div>

          <form onSubmit={handleLogin} className="auth-form">
            {error && <ErrorMessage message={error} onClose={() => setError('')} />}
            {success && <SuccessMessage message={success} />}

            <div className="form-group">
              <label htmlFor="email">Email Address</label>
              <input
                id="email"
                name="email"
                type="email"
                className="form-input"
                value={form.email}
                onChange={handleChange}
                placeholder="user@domain.com"
                required
                disabled={loading}
                autoFocus
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>
              <div className="input-with-action">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  className="form-input"
                  value={form.password}
                  onChange={handleChange}
                  placeholder="••••••••"
                  required
                  disabled={loading}
                />
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? '👁️' : '🔒'}
                </button>
              </div>
            </div>

            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? (
                <>
                  <span className="spinner"></span>
                  AUTHENTICATING...
                </>
              ) : (
                '▶ LOGIN'
              )}
            </button>

            <div style={{ textAlign: 'center' }}>
              <button
                type="button"
                className="btn-text"
                onClick={() => navigate('/forgot-password')}
                disabled={loading}
              >
                Forgot Password?
              </button>
            </div>
          </form>

          <div className="auth-footer">
            Don't have an account?{' '}
            <a href="/register" onClick={(e) => { e.preventDefault(); navigate('/register'); }}>
              Create Account
            </a>
          </div>
        </div>

        {/* Right Sidebar - Security Tips */}
        <div className="cyber-awareness-right">
          <div className="awareness-card">
            <img src="/cyber-lock.png" alt="Password Security" className="awareness-image" />
            <h3>🔐 Password Best Practices</h3>
            <p>Create strong, unique passwords to keep your account secure.</p>
            <ul>
              <li>Minimum 12 characters</li>
              <li>Mix of letters, numbers, symbols</li>
              <li>Avoid personal information</li>
              <li>Use a password manager</li>
            </ul>
          </div>

          <div className="awareness-card">
            <h3>📊 Cyber Crime Stats</h3>
            <p>Stay informed about digital threats:</p>
            <ul>
              <li>95% of breaches involve weak passwords</li>
              <li>$6 trillion in annual cybercrime costs</li>
              <li>1 attack every 39 seconds</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
