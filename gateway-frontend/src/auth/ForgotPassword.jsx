import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../services/authService';
import ErrorMessage from '../components/ErrorMessage';
import SuccessMessage from '../components/SuccessMessage';
import './Auth.css';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        try {
            await authService.forgotPassword(email);
            setSuccess('✓ Password reset code sent to your email! Redirecting...');
            setTimeout(() => {
                navigate('/reset-password', { state: { email } });
            }, 2000);
        } catch (err) {
            // For security, we show a generic message even if email doesn't exist
            setSuccess('If the email exists, a password reset code has been sent.');
            setTimeout(() => {
                navigate('/reset-password', { state: { email } });
            }, 2000);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card fade-in">
                <div className="auth-header">
                    <h1>🔐 Forgot Password?</h1>
                    <p>No worries! Enter your email and we'll send you a reset code</p>
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
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="Enter your email"
                            required
                            disabled={loading}
                            autoFocus
                        />
                    </div>

                    <button type="submit" className="btn btn-primary" disabled={loading}>
                        {loading ? (
                            <>
                                <span className="spinner"></span>
                                Sending Code...
                            </>
                        ) : (
                            '📧 Send Reset Code'
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

export default ForgotPassword;
