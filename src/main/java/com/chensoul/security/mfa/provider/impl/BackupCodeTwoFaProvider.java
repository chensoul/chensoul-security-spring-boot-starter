package com.chensoul.security.mfa.provider.impl;

import com.chensoul.security.mfa.config.BackupCodeTwoFaConfig;
import com.chensoul.security.mfa.provider.BackupCodeTwoFaProviderConfig;
import com.chensoul.security.mfa.provider.TwoFaProvider;
import com.chensoul.security.mfa.provider.TwoFaProviderType;
import com.chensoul.security.util.SecurityUser;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

@Component
public class BackupCodeTwoFaProvider implements TwoFaProvider<BackupCodeTwoFaProviderConfig, BackupCodeTwoFaConfig> {
    @Override
    public BackupCodeTwoFaConfig generateTwoFaConfig(User user, BackupCodeTwoFaProviderConfig providerConfig) {
        BackupCodeTwoFaConfig config = new BackupCodeTwoFaConfig();
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
    public boolean checkVerificationCode(SecurityUser user, String code, BackupCodeTwoFaProviderConfig providerConfig, BackupCodeTwoFaConfig accountConfig) {
        if (CollectionUtils.contains(accountConfig.getCodesForJson().iterator(), code)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public TwoFaProviderType getType() {
        return TwoFaProviderType.BACKUP_CODE;
    }

}
