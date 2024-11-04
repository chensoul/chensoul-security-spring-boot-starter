package com.chensoul.security.mfa;

import com.chensoul.security.jwt.token.JwtPair;
import com.chensoul.security.mfa.config.TwoFaConfig;
import com.chensoul.security.mfa.config.UserTwoFaSetting;
import com.chensoul.security.mfa.provider.TwoFaProviderType;
import com.chensoul.security.util.SecurityUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.List;
import java.util.Optional;
import org.springframework.security.core.userdetails.User;

public interface TwoFaSettingService {

    void prepareVerificationCode() throws JsonProcessingException;

    JwtPair checkVerificationCode(String verificationCode);

    List<TwoFaAuthController.TwoFaProviderInfo> getAvailableTwoFaProviders();

}
