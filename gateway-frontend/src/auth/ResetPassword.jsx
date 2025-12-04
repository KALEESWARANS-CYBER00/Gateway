import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import authService from '../services/authService';
import ErrorMessage from '../components/ErrorMessage';
import SuccessMessage from '../components/SuccessMessage';
import PasswordStrengthIndicator from '../components/PasswordStrengthIndicator';
import './Auth.css';

const ResetPassword = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [form, setForm] = useState({
        email: location.state?.email || '',
        otp: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const handleChange = (e) => {
        setForm({ ...form, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (form.newPassword !== form.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (form.newPassword.length < 8) {
            setError('Password must be at least 8 characters long');
            return;
        }

        if (!form.otp || form.otp.length !== 6) {
            setError('Please enter the 6-digit code');
            return;
        }

        setLoading(true);

        try {
            await authService.resetPassword(form.otp, form.newPassword);
            setSuccess('✓ Password reset successful! Redirecting to login...');
            setTimeout(() => {
                navigate('/login');
            }, 2000);
        } catch (err) {
            setError(err.response?.data?.error || 'Invalid or expired code. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleResendCode = async () => {
        if (!form.email) {
            setError('Please enter your email address');
            return;
        }

        try {
            await authService.forgotPassword(form.email);
            setSuccess('New code sent to your email!');
        } catch (err) {
            setSuccess('If the email exists, a new code has been sent.');
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card fade-in">
                <div className="auth-header">
                    <h1>🔑 Reset Password</h1>
                    <p>Enter the code sent to your email and choose a new password</p>
                </div>

                <form onSubmit={handleSubmit} className="auth-form">
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
                            placeholder="Enter your email"
                            required
                            disabled={loading}
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="otp">Reset Code</label>
                        <input
                            id="otp"
                            name="otp"
                            type="text"
                            className="form-input"
                            value={form.otp}
                            onChange={handleChange}
                            placeholder="Enter 6-digit code"
                            maxLength="6"
                            pattern="[0-9]{6}"
                            required
                            disabled={loading}
                            autoFocus
                        />
                        <button
                            type="button"
                            className="btn-text"
                            onClick={handleResendCode}
                            disabled={loading}
                            style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}
                        >
                            Didn't receive code? Resend
                        </button>
                    </div>

                    <div className="form-group">
                        <label htmlFor="newPassword">New Password</label>
                        <div className="input-with-action">
                            <input
                                id="newPassword"
                                name="newPassword"
                                type={showPassword ? 'text' : 'password'}
                                className="form-input"
                                value={form.newPassword}
                                onChange={handleChange}
                                placeholder="Enter new password"
                                required
                                disabled={loading}
                            />
                            <button
                                type="button"
                                className="btn-icon"
                                onClick={() => setShowPassword(!showPassword)}
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? '🙈' : '👁️'}
                            </button>
                        </div>
                        <PasswordStrengthIndicator
                            password={form.newPassword}
                            email={form.email}
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="confirmPassword">Confirm New Password</label>
                        <input
                            id="confirmPassword"
                            name="confirmPassword"
                            type={showPassword ? 'text' : 'password'}
                            className="form-input"
                            value={form.confirmPassword}
                            onChange={handleChange}
                            placeholder="Confirm new password"
                            required
                            disabled={loading}
                        />
                    </div>

                    <button type="submit" className="btn btn-primary" disabled={loading}>
                        {loading ? (
                            <>
                                <span className="spinner"></span>
                                Resetting Password...
                            </>
                        ) : (
                            '✓ Reset Password'
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    Remember your password?{' '}
                    <a href="/login" onClick={(e) => { e.preventDefault(); navigate('/login'); }}>
                        Sign in here
                    </a>
                </div>
            </div>
        </div>
    );
};

export default ResetPassword;
