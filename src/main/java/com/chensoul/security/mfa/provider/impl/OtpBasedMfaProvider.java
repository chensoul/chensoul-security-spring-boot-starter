package com.chensoul.security.mfa.provider.impl;

import com.chensoul.security.mfa.config.OtpBasedMfaConfig;
import com.chensoul.security.mfa.provider.OtpBasedMfaProviderConfig;
import com.chensoul.security.mfa.provider.MfaProvider;
import static com.chensoul.security.util.CacheConstants.TWO_FA_VERIFICATION_CODE_CACHE;
import com.chensoul.security.util.SecurityUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public abstract class OtpBasedMfaProvider<C extends OtpBasedMfaProviderConfig, A extends OtpBasedMfaConfig> implements MfaProvider<C, A> {
    private final CacheManager cacheManager;
    private final ObjectMapper objectMapper;

    @Override
    @SneakyThrows
    public final void prepareVerificationCode(SecurityUser user, C providerConfig, A twoFaConfig) {
        String verificationCode = RandomStringUtils.randomNumeric(6);
        sendVerificationCode(user, verificationCode, providerConfig, twoFaConfig);
        cacheManager.getCache(TWO_FA_VERIFICATION_CODE_CACHE)
                .put(TWO_FA_VERIFICATION_CODE_CACHE + ":" + user.getUsername(), objectMapper.writeValueAsBytes(new Otp(System.currentTimeMillis(), verificationCode, twoFaConfig)));
    }

    protected abstract void sendVerificationCode(SecurityUser user, String verificationCode, C providerConfig, A accountConfig);

    @Override
    @SneakyThrows
    public final boolean checkVerificationCode(SecurityUser user, String code, C providerConfig, A twoFaConfig) {
        String correctVerificationCode = cacheManager.getCache(TWO_FA_VERIFICATION_CODE_CACHE).get(TWO_FA_VERIFICATION_CODE_CACHE + ":" + user.getUsername()).toString();
        Otp otp = objectMapper.readValue(correctVerificationCode, Otp.class);
        if (correctVerificationCode!=null) {
            if (System.currentTimeMillis() - otp.getTimestamp()
                    > TimeUnit.SECONDS.toMillis(providerConfig.getVerificationCodeExpireTime())) {
                cacheManager.getCache(TWO_FA_VERIFICATION_CODE_CACHE).evict(TWO_FA_VERIFICATION_CODE_CACHE + ":" + user.getUsername());
                return false;
            }
            if (code.equals(otp.getValue()) && twoFaConfig.equals(otp.getTwoFaConfig())) {
                cacheManager.getCache(TWO_FA_VERIFICATION_CODE_CACHE).evict(TWO_FA_VERIFICATION_CODE_CACHE + ":" + user.getUsername());
                return true;
            }
        }
        return false;
    }


    @Data
    public static class Otp implements Serializable {
        private final long timestamp;
        private final String value;
        private final OtpBasedMfaConfig twoFaConfig;
    }

}
