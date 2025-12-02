package com.gateway.auth.service;

import com.gateway.auth.model.*;
import com.gateway.auth.repository.OTPRepository;
import com.gateway.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OTPVerificationService {

    private final OTPRepository otpRepository;
    private final UserRepository userRepository;

    public boolean verifyOTP(String otpCode, OTPPurpose purpose) {

        Optional<OTP> otpOptional =
                otpRepository.findByOtpCodeAndPurposeAndIsUsedFalse(otpCode, purpose);

        if (otpOptional.isEmpty()) {
            return false; // invalid or already used
        }

        OTP otp = otpOptional.get();

        if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
            return false; // expired
        }

        // Mark OTP as used
        otp.setUsed(true);
        otpRepository.save(otp);

        // If this is email verification → update user
        if (purpose == OTPPurpose.EMAIL_VERIFICATION) {
            User user = otp.getUser();
            user.setEmailVerified(true);
            userRepository.save(user);
        }

        return true;
    }
}
