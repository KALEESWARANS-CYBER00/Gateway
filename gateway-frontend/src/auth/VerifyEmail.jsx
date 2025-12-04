import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import authService from '../services/authService';
import ErrorMessage from '../components/ErrorMessage';
import SuccessMessage from '../components/SuccessMessage';
import './Auth.css';

const VerifyEmail = () => {
    const navigate = useNavigate();
    const location = useLocation();

    // Initialize email from location state or empty
    const [email, setEmail] = useState(location.state?.email || '');
    const [otp, setOtp] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [resendLoading, setResendLoading] = useState(false);
    const [countdown, setCountdown] = useState(0);
    const [isEditingEmail, setIsEditingEmail] = useState(!location.state?.email);

    useEffect(() => {
        if (countdown > 0) {
            const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
            return () => clearTimeout(timer);
        }
    }, [countdown]);

    const handleVerify = async (e) => {
        e.preventDefault();
        if (!email) {
            setError('Please enter your email address.');
            return;
        }

        setLoading(true);
        setError('');
        setSuccess('');

        try {
            const response = await authService.verifyEmail(otp);
            console.log('Verify response:', response);

            setSuccess('✓ Email verified successfully! Redirecting to login...');
            setTimeout(() => navigate('/login'), 2000);
        } catch (err) {
            console.error('Verification error:', err);
            setError(err.response?.data?.error || 'Invalid or expired OTP. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleResend = async () => {
        if (!email) {
            setError('Please enter your email address to resend the code.');
            setIsEditingEmail(true);
            return;
        }

        setResendLoading(true);
        setError('');
        setSuccess('');

        try {
            await authService.resendOTP(email);
            setSuccess(`Verification code sent to ${email}`);
            setCountdown(60);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to resend code. Please try again.');
        } finally {
            setResendLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card fade-in">
                <div className="auth-header">
                    <h1>Verify Your Email</h1>
                    <p>
                        Please enter the verification code sent to your email.
                    </p>
                </div>

                <form onSubmit={handleVerify} className="auth-form">
                    {error && <ErrorMessage message={error} onClose={() => setError('')} />}
                    {success && <SuccessMessage message={success} />}

                    <div className="form-group">
                        <label htmlFor="email">Email Address</label>
                        <div className="input-with-action">
                            <input
                                id="email"
                                type="email"
                                className="form-input"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="Enter your email"
                                disabled={!isEditingEmail && !!location.state?.email}
                                required
                            />
                            {location.state?.email && !isEditingEmail && (
                                <button
                                    type="button"
                                    className="btn-text"
                                    onClick={() => setIsEditingEmail(true)}
                                >
                                    Change
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="form-group">
                        <label htmlFor="otp">Verification Code</label>
                        <input
                            id="otp"
                            name="otp"
                            type="text"
                            className="form-input otp-input-field"
                            value={otp}
                            onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                            placeholder="• • • • • •"
                            required
                            disabled={loading}
                            maxLength={6}
                            autoComplete="one-time-code"
                        />
                    </div>

                    <button type="submit" className="btn btn-primary" disabled={loading || otp.length !== 6}>
                        {loading ? (
                            <>
                                <span className="spinner"></span>
                                Verifying...
                            </>
                        ) : (
                            'Verify Email'
                        )}
                    </button>

                    <div className="divider">Didn't receive the code?</div>

                    <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={handleResend}
                        disabled={resendLoading || countdown > 0 || !email}
                    >
                        {resendLoading ? (
                            <>
                                <span className="spinner"></span>
                                Sending...
                            </>
                        ) : countdown > 0 ? (
                            `Resend in ${countdown}s`
                        ) : (
                            'Resend Code'
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    <a href="/login" onClick={(e) => { e.preventDefault(); navigate('/login'); }}>
                        Back to Login
                    </a>
                </div>
            </div>
        </div>
    );
};

export default VerifyEmail;
