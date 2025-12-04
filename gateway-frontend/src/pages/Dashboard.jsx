import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';

const Dashboard = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    return (
        <div style={{
            minHeight: '100vh',
            background: 'linear-gradient(135deg, var(--bg-primary) 0%, #0f172a 100%)',
            padding: '2rem',
            color: 'var(--text-primary)'
        }}>
            <div style={{
                maxWidth: '1200px',
                margin: '0 auto',
                background: 'rgba(30, 41, 59, 0.7)',
                borderRadius: '1rem',
                padding: '2rem',
                backdropFilter: 'blur(20px)',
                border: '1px solid rgba(255, 255, 255, 0.05)'
            }}>
                <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '2rem',
                    paddingBottom: '1rem',
                    borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                }}>
                    <div>
                        <h1 style={{
                            fontSize: '2rem',
                            marginBottom: '0.5rem',
                            background: 'linear-gradient(135deg, #fff, #94a3b8)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent'
                        }}>
                            🎉 Welcome to Your Dashboard!
                        </h1>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>
                            {(() => {
                                const hour = new Date().getHours();
                                if (hour < 12) return '☀️ Good morning! ';
                                if (hour < 18) return '🌤️ Good afternoon! ';
                                return '🌙 Good evening! ';
                            })()}
                            {user?.name || 'User'}
                        </p>
                        <p style={{
                            color: 'var(--success)',
                            marginTop: '0.5rem',
                            fontSize: '0.95rem',
                            fontWeight: '500'
                        }}>
                            ✓ You're successfully logged in to your account
                        </p>
                    </div>
                    <button
                        onClick={handleLogout}
                        style={{
                            padding: '0.75rem 1.5rem',
                            background: 'transparent',
                            color: 'var(--error)',
                            border: '1px solid var(--error)',
                            borderRadius: '0.5rem',
                            fontSize: '0.95rem',
                            fontWeight: '600',
                            cursor: 'pointer',
                            transition: 'all 0.2s'
                        }}
                    >
                        Logout
                    </button>
                </div>

                <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                    gap: '1.5rem'
                }}>
                    {/* Account Info Card */}
                    <div style={{
                        background: 'rgba(15, 23, 42, 0.6)',
                        padding: '1.5rem',
                        borderRadius: '0.75rem',
                        border: '1px solid rgba(255, 255, 255, 0.05)'
                    }}>
                        <h2 style={{
                            fontSize: '1.25rem',
                            marginBottom: '1rem',
                            color: 'var(--primary-light)'
                        }}>
                            👤 Account Information
                        </h2>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            <div>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Name</span>
                                <p style={{ fontSize: '1rem', marginTop: '0.25rem' }}>{user?.name || 'N/A'}</p>
                            </div>
                            <div>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Email</span>
                                <p style={{ fontSize: '1rem', marginTop: '0.25rem' }}>{user?.email || 'N/A'}</p>
                            </div>
                            <div>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Status</span>
                                <p style={{ fontSize: '1rem', marginTop: '0.25rem' }}>
                                    <span style={{
                                        background: user?.emailVerified ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                                        color: user?.emailVerified ? 'var(--success)' : 'var(--error)',
                                        padding: '0.25rem 0.75rem',
                                        borderRadius: '0.25rem',
                                        fontSize: '0.875rem',
                                        fontWeight: '500'
                                    }}>
                                        {user?.emailVerified ? '✓ Verified' : '✗ Unverified'}
                                    </span>
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Success Message Card */}
                    <div style={{
                        background: 'rgba(16, 185, 129, 0.1)',
                        padding: '1.5rem',
                        borderRadius: '0.75rem',
                        border: '1px solid rgba(16, 185, 129, 0.2)'
                    }}>
                        <h2 style={{
                            fontSize: '1.25rem',
                            marginBottom: '1rem',
                            color: 'var(--success)'
                        }}>
                            ✨ Getting Started
                        </h2>
                        <p style={{ lineHeight: '1.6', color: 'var(--text-secondary)' }}>
                            Welcome to Gateway! You've successfully completed the authentication process.
                            Your account is now active and ready to use.
                        </p>
                        <ul style={{
                            marginTop: '1rem',
                            paddingLeft: '1.5rem',
                            color: 'var(--text-secondary)',
                            lineHeight: '1.8'
                        }}>
                            <li>✓ Account created and verified</li>
                            <li>✓ Secure login established</li>
                            <li>✓ Dashboard access granted</li>
                        </ul>
                    </div>
                </div>

                <div style={{
                    marginTop: '2rem',
                    padding: '1.5rem',
                    background: 'rgba(99, 102, 241, 0.1)',
                    borderRadius: '0.75rem',
                    border: '1px solid rgba(99, 102, 241, 0.2)',
                    textAlign: 'center'
                }}>
                    <h3 style={{
                        fontSize: '1.1rem',
                        marginBottom: '0.5rem',
                        color: 'var(--primary-light)'
                    }}>
                        🚀 What's Next?
                    </h3>
                    <p style={{ color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                        Explore more features, customize your profile, and make the most of your Gateway experience.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
