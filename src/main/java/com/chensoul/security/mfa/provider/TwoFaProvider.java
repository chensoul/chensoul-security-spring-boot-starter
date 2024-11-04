package com.chensoul.security.mfa.provider;


import com.chensoul.security.mfa.config.TwoFaConfig;
import com.chensoul.security.util.SecurityUser;
import org.springframework.security.core.userdetails.User;

public interface TwoFaProvider<C extends TwoFaProviderConfig, A extends TwoFaConfig> {

    A generateTwoFaConfig(User user, C providerConfig);

    default void prepareVerificationCode(SecurityUser user, C providerConfig, A accountConfig)  {
    }

    boolean checkVerificationCode(SecurityUser user, String code, C providerConfig, A accountConfig) ;

    default void check(String tenantId) {
    }

    TwoFaProviderType getType();

}
