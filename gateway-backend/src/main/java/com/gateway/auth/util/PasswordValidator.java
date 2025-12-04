package com.gateway.auth.util;

import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");

    // Common weak passwords to reject
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
        "password", "12345678", "qwerty", "abc123", "password123",
        "admin", "letmein", "welcome", "monkey", "dragon",
        "master", "sunshine", "princess", "football", "shadow"
    );

    public ValidationResult validate(String password, String email) {
        ValidationResult result = new ValidationResult();

        if (password == null || password.isEmpty()) {
            result.addError("Password is required");
            return result;
        }

        // Length check
        if (password.length() < MIN_LENGTH) {
            result.addError("Password must be at least " + MIN_LENGTH + " characters long");
        }

        if (password.length() > MAX_LENGTH) {
            result.addError("Password must not exceed " + MAX_LENGTH + " characters");
        }

        // Character requirements
        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            result.addError("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            result.addError("Password must contain at least one lowercase letter");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            result.addError("Password must contain at least one digit");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            result.addError("Password must contain at least one special character (!@#$%^&*()_+-=[]{}etc.)");
        }

        // Common password check
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            result.addError("This password is too common. Please choose a stronger password");
        }

        // Email similarity check
        if (email != null && !email.isEmpty()) {
            String emailPrefix = email.split("@")[0].toLowerCase();
            if (password.toLowerCase().contains(emailPrefix)) {
                result.addError("Password should not contain your email address");
            }
        }

        return result;
    }

    public static class ValidationResult {
        private final List<String> errors = new java.util.ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return errors.isEmpty();
        }

        public List<String> getErrors() {
            return errors;
        }

        public String getErrorMessage() {
            return String.join("; ", errors);
        }
    }
}
