package com.gateway.auth.service;

import com.gateway.auth.model.*;
import com.gateway.auth.repository.OTPRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OTPService {

    private final OTPRepository otpRepository;
    private final Random random = new Random();

    public OTP generateOTP(User user, OTPPurpose purpose, int expiryMinutes) {
        // Invalidate previous unused OTPs for same user/purpose
        List<OTP> existing = otpRepository.findByUserIdAndPurposeAndIsUsedFalse(user.getId(), purpose);
        existing.forEach(e -> {
            e.setUsed(true);
            otpRepository.save(e);
        });

        String otpCode = String.format("%06d", random.nextInt(1_000_000));

        OTP otp = OTP.builder()
                .user(user)
                .otpCode(otpCode)
                .purpose(purpose)
                .expiresAt(LocalDateTime.now().plusMinutes(expiryMinutes))
                .isUsed(false)
                .build();

        return otpRepository.save(otp);
    }

    public void markUsed(OTP otp) {
        otp.setUsed(true);
        otpRepository.save(otp);
    }
}
