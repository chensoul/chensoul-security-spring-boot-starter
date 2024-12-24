package com.chensoul.security.mfa;

import com.chensoul.security.jwt.token.JwtPair;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.List;

public interface MfaSettingService {
    void prepareVerificationCode() throws JsonProcessingException;

    JwtPair checkVerificationCode(String verificationCode);

    List<MfaAuthController.TwoFaProviderInfo> getAvailableTwoFaProviders();
}
