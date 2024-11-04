package com.chensoul.security;

import com.chensoul.security.mfa.config.TwoFaConfig;
import com.chensoul.security.mfa.provider.TwoFaProviderConfig;
import com.chensoul.security.mfa.provider.TwoFaProviderType;
import com.chensoul.security.util.JacksonUtil;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@AllArgsConstructor
@NoArgsConstructor
@Data
@ConfigurationProperties(prefix = "security.jwt", ignoreUnknownFields = false)
public class JwtProperties {
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";

    private boolean enabled = true;
    private String baseUrl = TOKEN_BASED_AUTH_ENTRY_POINT;
    private String loginUrl = FORM_BASED_LOGIN_ENTRY_POINT;
    private String tokenRefreshUrl = TOKEN_REFRESH_ENTRY_POINT;

    private List<String> pathsToSkip = Arrays.asList("/api/auth/token", "/api/auth/login", "/api/noauth/**", "/error", "/actuator/**", "/api/system/mail/oauth2/code");
    private Integer accessTokenExpireTime = 9000;
    private Integer refreshTokenExpireTime = 604800;
    private String tokenIssuer = "chensoul.com";
    private String tokenSigningKey = "secret12345678901234567890123456789012345678901234567890123456789012345678901234567890";

    @NestedConfigurationProperty
    private MfaProperties mfa = new MfaProperties();

    @Data
    public class MfaProperties {
        private boolean enabled = false;

        @Valid
        @NotEmpty
        private List<Map<String, Object>> providers;

        @NotNull
        @Min(value = 5)
        private Integer minVerificationCodeSendPeriod;

        @Min(value = 0, message = "must be positive")
        private Integer maxVerificationFailuresBeforeUserLockout;

        @NotNull
        @Min(value = 60)
        private Integer totalAllowedTimeForVerification = 3600; //sec

        @Valid
        @NotNull
        private List<Map<String, Object>> configs;

        public List<TwoFaConfig> getAllConfigs() {
            return configs.stream().map(twoFaConfig -> JacksonUtil.fromString(JacksonUtil.toString(twoFaConfig), TwoFaConfig.class)).collect(Collectors.toList());
        }

        public TwoFaConfig getDefaultConfig() {
            return getAllConfigs().stream().filter(TwoFaConfig::isUseByDefault).findAny().orElse(null);
        }

        public Optional<TwoFaProviderConfig> getProviderConfig(TwoFaProviderType providerType) {
            return Optional.ofNullable(providers)
                    .flatMap(providersConfigs -> providersConfigs.stream()
                            .map(providerConfig -> JacksonUtil.fromString(JacksonUtil.toString(providerConfig), TwoFaProviderConfig.class))
                            .filter(providerConfig -> providerConfig.getProviderType().equals(providerType))
                            .findFirst());
        }

    }
}
