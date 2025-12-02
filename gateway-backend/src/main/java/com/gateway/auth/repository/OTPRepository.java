package com.gateway.auth.repository;

import com.gateway.auth.model.OTP;
import com.gateway.auth.model.OTPPurpose;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OTPRepository extends JpaRepository<OTP, Long> {
    Optional<OTP> findByOtpCodeAndPurposeAndIsUsedFalse(String otpCode, OTPPurpose purpose);
    List<OTP> findByUserIdAndPurposeAndIsUsedFalse(Long userId, OTPPurpose purpose);
}
