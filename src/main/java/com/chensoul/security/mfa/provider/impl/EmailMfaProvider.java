package com.chensoul.security.mfa.provider.impl;

import com.chensoul.security.mfa.config.EmailMfaConfig;
import com.chensoul.security.mfa.provider.EmailMfaProviderConfig;
import com.chensoul.security.mfa.provider.MfaProviderType;
import com.chensoul.security.util.SecurityUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class EmailMfaProvider extends OtpBasedMfaProvider<EmailMfaProviderConfig, EmailMfaConfig> {
//    private final MailService mailService;

    protected EmailMfaProvider(CacheManager cacheManager, ObjectMapper objectMapper) {
        super(cacheManager, objectMapper);
//        this.mailService = mailService;
    }

    @Override
    public EmailMfaConfig generateTwoFaConfig(User user, EmailMfaProviderConfig providerConfig) {
        EmailMfaConfig config = new EmailMfaConfig();
//        config.setEmail(user.getEmail());
        return config;
    }

    @Override
    public void check(String tenantId) {
//        try {
//            mailService.testConnection(tenantId);
//        } catch (Exception e) {
//            throw new RuntimeException("Mail service is not set up");
//        }
    }

    @Override
    protected void sendVerificationCode(SecurityUser user, String verificationCode, EmailMfaProviderConfig providerConfig, EmailMfaConfig twoFaConfig) {
        log.info("send verification code {} to email {}", verificationCode, twoFaConfig.getEmail());
//        mailService.sendTwoFaVerificationEmail(twoFaConfig.getEmail(), verificationCode, providerConfig.getVerificationCodeLifetime());
    }

    @Override
    public MfaProviderType getType() {
        return MfaProviderType.EMAIL;
    }

}
