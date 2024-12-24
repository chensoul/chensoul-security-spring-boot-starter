package com.chensoul.security.mfa.provider.impl;

import com.chensoul.security.mfa.config.SmsMfaConfig;
import com.chensoul.security.mfa.provider.SmsMfaProviderConfig;
import com.chensoul.security.mfa.provider.MfaProviderType;
import com.chensoul.security.util.SecurityUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class SmsMfaProvider extends OtpBasedMfaProvider<SmsMfaProviderConfig, SmsMfaConfig> {
//    private final SmsService smsService;

    public SmsMfaProvider(CacheManager cacheManager, ObjectMapper objectMapper) {
        super(cacheManager, objectMapper);
//        this.smsService = smsService;
    }

    @Override
    public SmsMfaConfig generateTwoFaConfig(User user, SmsMfaProviderConfig providerConfig) {
        return new SmsMfaConfig();
    }

    @Override
    protected void sendVerificationCode(SecurityUser user, String verificationCode, SmsMfaProviderConfig providerConfig, SmsMfaConfig twoFaConfig) {
        log.info("send verification code {} to phoneNumber ", verificationCode, twoFaConfig.getPhoneNumber());

//        Map<String, String> messageData = Map.of(
//                "code", verificationCode,
//                "userEmail", user.getEmail()
//        );
//        String message = FormatUtils.formatVariables(providerConfig.getSmsVerificationMessageTemplate(), "${", "}", messageData);
//        String phoneNumber = twoFaConfig.getPhoneNumber();
//        try {
//            smsService.sendSms(user.getTenantId(), user.getMerchantId(), new String[]{phoneNumber}, message);
//        } catch (RuntimeException e) {
//            throw e;
//        }
    }

    @Override
    public void check(String tenantId) {
//        if (!smsService.isConfigured(tenantId)) {
//            throw new RuntimeException("SMS service is not configured");
//        }
    }

    @Override
    public MfaProviderType getType() {
        return MfaProviderType.SMS;
    }

}
