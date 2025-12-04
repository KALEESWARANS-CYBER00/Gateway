import React from 'react';
import './PasswordStrengthIndicator.css';

const PasswordStrengthIndicator = ({ password, email }) => {
    const calculateStrength = () => {
        let strength = 0;
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            digit: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password),
        };

        // Calculate strength score
        if (checks.length) strength += 20;
        if (checks.uppercase) strength += 20;
        if (checks.lowercase) strength += 20;
        if (checks.digit) strength += 20;
        if (checks.special) strength += 20;

        // Penalties
        if (password.length < 8) strength = Math.min(strength, 40);
        if (email && password.toLowerCase().includes(email.split('@')[0].toLowerCase())) {
            strength = Math.min(strength, 30);
        }

        return { strength, checks };
    };

    const { strength, checks } = calculateStrength();

    const getStrengthLabel = () => {
        if (strength === 0) return '';
        if (strength < 40) return 'Weak';
        if (strength < 70) return 'Fair';
        if (strength < 90) return 'Good';
        return 'Strong';
    };

    const getStrengthColor = () => {
        if (strength < 40) return '#e74c3c';
        if (strength < 70) return '#f39c12';
        if (strength < 90) return '#3498db';
        return '#27ae60';
    };

    if (!password) return null;

    return (
        <div className="password-strength-indicator">
            <div className="strength-bar-container">
                <div
                    className="strength-bar"
                    style={{
                        width: `${strength}%`,
                        backgroundColor: getStrengthColor()
                    }}
                />
            </div>
            <div className="strength-label" style={{ color: getStrengthColor() }}>
                {getStrengthLabel()}
            </div>

            <div className="password-requirements">
                <div className={checks.length ? 'requirement met' : 'requirement'}>
                    {checks.length ? '✓' : '○'} At least 8 characters
                </div>
                <div className={checks.uppercase ? 'requirement met' : 'requirement'}>
                    {checks.uppercase ? '✓' : '○'} One uppercase letter
                </div>
                <div className={checks.lowercase ? 'requirement met' : 'requirement'}>
                    {checks.lowercase ? '✓' : '○'} One lowercase letter
                </div>
                <div className={checks.digit ? 'requirement met' : 'requirement'}>
                    {checks.digit ? '✓' : '○'} One number
                </div>
                <div className={checks.special ? 'requirement met' : 'requirement'}>
                    {checks.special ? '✓' : '○'} One special character
                </div>
            </div>
        </div>
    );
};

export default PasswordStrengthIndicator;
