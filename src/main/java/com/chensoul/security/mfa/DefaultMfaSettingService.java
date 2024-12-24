package com.chensoul.security.mfa;

import com.chensoul.security.config.JwtProperties;
import com.chensoul.security.jwt.token.JwtPair;
import com.chensoul.security.jwt.token.JwtTokenFactory;
import com.chensoul.security.mfa.config.EmailMfaConfig;
import com.chensoul.security.mfa.config.SmsMfaConfig;
import com.chensoul.security.mfa.config.MfaConfig;
import com.chensoul.security.mfa.provider.MfaProvider;
import com.chensoul.security.mfa.provider.MfaProviderConfig;
import com.chensoul.security.mfa.provider.MfaProviderType;
import com.chensoul.security.util.SecurityUser;
import com.chensoul.security.util.SecurityUtils;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import static org.apache.commons.lang3.StringUtils.repeat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DefaultMfaSettingService implements MfaSettingService {
    private final Map<MfaProviderType, MfaProvider<MfaProviderConfig, MfaConfig>> providers = new EnumMap<>(MfaProviderType.class);
    private static final RuntimeException PROVIDER_NOT_CONFIGURED_ERROR = new RuntimeException("mfa provider is not configured");
    private static final RuntimeException PROVIDER_NOT_AVAILABLE_ERROR = new RuntimeException("mfa provider is not available");

    private final JwtTokenFactory tokenFactory;
    private final JwtProperties jwtProperties;

    @Autowired
    private void setProviders(Collection<MfaProvider> providers) {
        providers.forEach(provider -> {
            this.providers.put(provider.getType(), provider);
        });
    }

    @Override
    public void prepareVerificationCode() {
        MfaConfig mfaConfig = jwtProperties.getMfa().getDefaultConfig();
        MfaProviderConfig providerConfig = jwtProperties.getMfa().getProviderConfig(mfaConfig.getProviderType())
                .orElseThrow(() -> PROVIDER_NOT_CONFIGURED_ERROR);
        getTwoFaProvider(mfaConfig.getProviderType()).prepareVerificationCode(SecurityUtils.getCurrentUser(), providerConfig, mfaConfig);
    }


    @Override
    public JwtPair checkVerificationCode(String verificationCode) {
        SecurityUser user = SecurityUtils.getCurrentUser();
        MfaConfig mfaConfig = jwtProperties.getMfa().getDefaultConfig();
        MfaProviderConfig providerConfig = jwtProperties.getMfa().getProviderConfig(mfaConfig.getProviderType())
                .orElseThrow(() -> PROVIDER_NOT_CONFIGURED_ERROR);

        boolean verificationSuccess = false;
        if (StringUtils.isNotBlank(verificationCode)) {
            if (StringUtils.isNumeric(verificationCode) || mfaConfig.getProviderType()==MfaProviderType.BACKUP_CODE) {
                verificationSuccess = getTwoFaProvider(mfaConfig.getProviderType()).checkVerificationCode(user, verificationCode, providerConfig, mfaConfig);
            }
        }

        if (verificationSuccess) {
            return tokenFactory.createTokenPair(user);
        } else {
            RuntimeException error = new RuntimeException("Verification code is incorrect");
            throw error;
        }
    }

    private MfaProvider<MfaProviderConfig, MfaConfig> getTwoFaProvider(MfaProviderType providerType) {
        return Optional.ofNullable(providers.get(providerType)).orElseThrow(() -> PROVIDER_NOT_AVAILABLE_ERROR);
    }

    @Override
    public List<MfaAuthController.TwoFaProviderInfo> getAvailableTwoFaProviders() {
        return jwtProperties.getMfa().getAllConfigs().stream().map(config -> {
                    String contact = null;
                    switch (config.getProviderType()) {
                        case SMS:
                            String phoneNumber = ((SmsMfaConfig) config).getPhoneNumber();
                            contact = obfuscate(phoneNumber, 2, '*', phoneNumber.indexOf('+') + 1, phoneNumber.length());
                            break;
                        case EMAIL:
                            String email = ((EmailMfaConfig) config).getEmail();
                            contact = obfuscate(email, 2, '*', 0, email.indexOf('@'));
                            break;
                    }
                    return MfaAuthController.TwoFaProviderInfo.builder()
                            .type(config.getProviderType())
                            .useByDefault(config.isUseByDefault())
                            .contact(contact)
                            .minVerificationCodeSendPeriod(jwtProperties.getMfa().getMinVerificationCodeSendPeriod())
                            .build();
                })
                .collect(Collectors.toList());
    }

    private static String obfuscate(String input, int seenMargin, char obfuscationChar,
                                    int startIndexInclusive, int endIndexExclusive) {
        String part = input.substring(startIndexInclusive, endIndexExclusive);
        String obfuscatedPart;
        if (part.length() <= seenMargin * 2) {
            obfuscatedPart = repeat(obfuscationChar, part.length());
        } else {
            obfuscatedPart = part.substring(0, seenMargin)
                    + repeat(obfuscationChar, part.length() - seenMargin * 2)
                    + part.substring(part.length() - seenMargin);
        }
        return input.substring(0, startIndexInclusive) + obfuscatedPart + input.substring(endIndexExclusive);
    }
}
