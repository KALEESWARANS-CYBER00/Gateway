# 🔐 Authify - Secure Authentication Platform

A modern, cybersecurity-focused authentication system with advanced security features and a hacker/Matrix-inspired UI.

![Authify Logo](gateway-frontend/public/authify-logo.png)

## ✨ Features

- 🔒 **Secure Authentication** - JWT-based with refresh tokens
- 📧 **OTP Verification** - Email verification with time-limited codes
- 🔑 **Password Reset** - OTP-based password recovery
- 🛡️ **Rate Limiting** - Protection against brute force attacks
- 🔐 **Account Lockout** - Automatic lockout after failed attempts
- 📊 **Audit Logging** - Complete audit trail of auth events
- 🎨 **Hacker Theme** - Matrix-inspired UI with cyber awareness
- ♿ **Accessible** - WCAG compliant with keyboard navigation

## 🚀 Quick Start

### Prerequisites
- Java 17+
- Node.js 16+
- MySQL 8.0+
- MailHog (for local email testing)

### Backend Setup

```bash
cd gateway-backend
mvn clean install
mvn spring-boot:run
```

Backend runs on `http://localhost:8080`

### Frontend Setup

```bash
cd gateway-frontend
npm install
npm start
```

Frontend runs on `http://localhost:3000`

## 🔧 Configuration

### Backend (`application.properties`)
- Database connection
- JWT secret
- Email configuration (Gmail/MailHog)
- Rate limiting settings

### Frontend (`src/services/authService.js`)
- API base URL
- Request/response interceptors

## 🌐 Routes

### Public Routes
- `/login` - User login
- `/register` - New user registration
- `/verify-email` - Email verification
- `/forgot-password` - Request password reset
- `/reset-password` - Reset password with OTP

### Protected Routes
- `/dashboard` - User dashboard (requires authentication)

## 🔒 Security Features

### Password Requirements
- Minimum 8 characters
- Must contain uppercase and lowercase letters
- Must contain numbers
- Must contain special characters
- Cannot contain email address

### Rate Limiting
- Max 5 failed login attempts
- Account locked for 30 minutes after limit exceeded
- OTP codes expire after 15 minutes

### Token Management
- Access tokens expire after 15 minutes
- Refresh tokens expire after 7 days
- All tokens revoked on password reset

## 🎨 Cybersecurity Awareness

The platform includes educational content about:
- **Password Security** - Best practices for strong passwords
- **Phishing Prevention** - How to identify fake login pages
- **Cyber Crime Stats** - Stay informed about digital threats
- **Identity Protection** - Safeguard your digital identity

## 📸 Screenshots

*Login page with Matrix theme and cyber awareness sidebars*

## 🛠️ Tech Stack

### Backend
- Spring Boot 3.2.0
- Spring Security
- JWT Authentication
- MySQL Database
- JavaMail (Email sending)
- Hibernate/JPA

### Frontend
- React 18
- React Router v6
- Axios (HTTP client)
- CSS3 (Custom animations)

## 📝 API Documentation

### Authentication Endpoints

#### POST `/api/auth/register`
Register a new user

#### POST `/api/auth/login`
Login with email and password

#### POST `/api/auth/verify-email?otp={code}`
Verify email with OTP

#### POST `/api/auth/forgot-password`
Request password reset OTP

#### POST `/api/auth/reset-password?otp={code}`
Reset password with OTP

#### POST `/api/auth/refresh`
Refresh access token

#### POST `/api/auth/logout`
Logout and revoke refresh token

#### GET `/api/auth/me`
Get current user info

## 🧹 Before Deployment

Run the cleanup script:
```bash
chmod +x cleanup.sh
./cleanup.sh
```

This removes:
- Build artifacts
- IDE files
- Sensitive data
- Temporary files

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please follow security best practices when contributing.

## ⚠️ Security Notice

- Never commit sensitive data (passwords, API keys, etc.)
- Use environment variables for configuration
- Keep dependencies updated
- Follow OWASP security guidelines

## 📧 Support

For issues or questions, please open a GitHub issue.

---

**Built with ❤️ for a more secure digital world**
