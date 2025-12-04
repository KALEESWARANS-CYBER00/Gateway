import React from 'react';
import '../auth/Auth.css';

const ErrorMessage = ({ message, onClose }) => {
    if (!message) return null;

    return (
        <div className="message message-error">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            <span>{message}</span>
            {onClose && (
                <button
                    onClick={onClose}
                    style={{
                        marginLeft: 'auto',
                        background: 'transparent',
                        border: 'none',
                        color: 'inherit',
                        cursor: 'pointer',
                        padding: '0.25rem'
                    }}
                >
                    ×
                </button>
            )}
        </div>
    );
};

export default ErrorMessage;
