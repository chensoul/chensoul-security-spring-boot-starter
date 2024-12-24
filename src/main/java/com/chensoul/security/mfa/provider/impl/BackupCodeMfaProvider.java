package com.chensoul.security.mfa.provider.impl;

import com.chensoul.security.mfa.config.BackupCodeMfaConfig;
import com.chensoul.security.mfa.provider.BackupCodeMfaProviderConfig;
import com.chensoul.security.mfa.provider.MfaProvider;
import com.chensoul.security.mfa.provider.MfaProviderType;
import com.chensoul.security.util.SecurityUser;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

@Component
public class BackupCodeMfaProvider implements MfaProvider<BackupCodeMfaProviderConfig, BackupCodeMfaConfig> {
    @Override
    public BackupCodeMfaConfig generateTwoFaConfig(User user, BackupCodeMfaProviderConfig providerConfig) {
        BackupCodeMfaConfig config = new BackupCodeMfaConfig();
        config.setCodes(generateCodes(providerConfig.getCodesQuantity(), 8));
        config.setSerializeHiddenFields(true);
        return config;
    }

    private static String generateCodes(int count, int length) {
        return Stream.generate(() -> RandomStringUtils.random(length, "0123456789abcdef"))
                .distinct().limit(count)
                .collect(Collectors.joining(","));
    }

    @Override
    public boolean checkVerificationCode(SecurityUser user, String code, BackupCodeMfaProviderConfig providerConfig, BackupCodeMfaConfig accountConfig) {
        if (CollectionUtils.contains(accountConfig.getCodesForJson().iterator(), code)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public MfaProviderType getType() {
        return MfaProviderType.BACKUP_CODE;
    }

}
